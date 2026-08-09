import AuthenticationServices
import CryptoKit
import Foundation

/// The three ways a device can be bound, and why they are not equivalent.
///
/// The relay decides which of these an account may use — a principal holding a
/// privileged role (ADMIN, by default) is refused anything but `.apple` or
/// `.google`. The app asks the relay for that rule at launch
/// (`GET /api/v1/providers`) and greys out the rest, so a user is told before
/// they tap rather than after a 403.
public enum SignInMethod: String, Sendable, CaseIterable {
    case apple
    case google
    case github
    /// An admin-issued single-use code, typed in. Never available to a
    /// privileged account.
    case enrollmentCode

    public var displayName: String {
        switch self {
        case .apple: return "Sign in with Apple"
        case .google: return "Sign in with Google"
        case .github: return "Sign in with GitHub"
        case .enrollmentCode: return "Use an enrollment code"
        }
    }
}

// MARK: - Apple

/// Sign in with Apple.
///
/// The strongest of the three, and the reason it is the default for privileged
/// accounts: the identity token is signed by Apple, verified by the relay
/// against Apple's JWKS, and bound to a relay-issued nonce. No browser, no
/// client secret anywhere, and no bearer credential left on the device.
///
/// The nonce handling is the part that is easy to get wrong. Apple hashes
/// nothing for you: the app must put SHA-256 of the raw nonce into the request,
/// and the token comes back carrying that hash. The relay returns both forms
/// (`nonce`, `nonceHash`) precisely so this code does not have to re-derive it.
@MainActor
public final class AppleSignInController: NSObject {

    private var continuation: CheckedContinuation<ASAuthorizationAppleIDCredential, Error>?
    private weak var presentationAnchor: ASPresentationAnchor?

    public init(presentationAnchor: ASPresentationAnchor?) {
        self.presentationAnchor = presentationAnchor
    }

    /// Runs the Apple flow and returns the identity token.
    ///
    /// - Parameter nonceHash: `RelayLoginNonce.nonceHash`, i.e. SHA-256 hex of
    ///   the raw nonce the relay issued for this device key.
    public func identityToken(nonceHash: String) async throws -> String {
        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        // No scopes are requested. The relay identifies a user by the stable
        // `sub` claim and matches it against a mapping an admin created; asking
        // for a name or an email would collect personal data the product does
        // not use.
        request.requestedScopes = []
        request.nonce = nonceHash

        let credential: ASAuthorizationAppleIDCredential = try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }

        guard let tokenData = credential.identityToken,
              let token = String(data: tokenData, encoding: .utf8) else {
            throw RelayError.signIn("Apple returned no identity token.")
        }
        return token
    }
}

extension AppleSignInController: ASAuthorizationControllerDelegate {
    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            continuation?.resume(throwing: RelayError.signIn("Unexpected Apple credential type."))
            continuation = nil
            return
        }
        continuation?.resume(returning: credential)
        continuation = nil
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if let authError = error as? ASAuthorizationError, authError.code == .canceled {
            continuation?.resume(throwing: RelayError.userCancelled)
        } else {
            continuation?.resume(throwing: RelayError.signIn(error.localizedDescription))
        }
        continuation = nil
    }
}

extension AppleSignInController: ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        presentationAnchor ?? ASPresentationAnchor()
    }
}

// MARK: - Google

/// Sign in with Google, without the Google SDK.
///
/// Google's iOS OAuth clients are *public* clients: authorization code plus
/// PKCE, no client secret. That means the whole flow is an
/// `ASWebAuthenticationSession` and one token exchange, which is worth doing by
/// hand — a security product should not carry a vendor runtime with its own
/// networking, logging and update cadence for 120 lines of protocol.
///
/// What the app keeps afterwards: nothing. The ID token is handed to the relay
/// and dropped; the access token is never requested beyond the minimum scopes
/// and never stored.
@MainActor
public final class GoogleSignInController: NSObject {

    public struct Configuration: Sendable {
        /// The iOS OAuth client id from the Google Cloud console.
        public let clientID: String
        /// Google requires the reversed client id as the redirect scheme.
        public let redirectScheme: String

        public init(clientID: String) {
            self.clientID = clientID
            // "123-abc.apps.googleusercontent.com" -> "com.googleusercontent.apps.123-abc"
            let reversed = clientID
                .replacingOccurrences(of: ".apps.googleusercontent.com", with: "")
            self.redirectScheme = "com.googleusercontent.apps.\(reversed)"
        }
    }

    private let configuration: Configuration
    private weak var presentationAnchor: ASPresentationAnchor?
    private var session: ASWebAuthenticationSession?

    public init(configuration: Configuration, presentationAnchor: ASPresentationAnchor?) {
        self.configuration = configuration
        self.presentationAnchor = presentationAnchor
    }

    /// Runs the Google flow and returns the OIDC ID token.
    ///
    /// - Parameter nonce: the *raw* nonce from the relay. Google echoes it
    ///   verbatim into the ID token, and the relay accepts either the raw or
    ///   the hashed form for exactly this reason.
    public func identityToken(nonce: String) async throws -> String {
        let verifier = Self.randomURLSafeString(bytes: 32)
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        let state = Self.randomURLSafeString(bytes: 16)
        let redirectURI = "\(configuration.redirectScheme):/oauth2redirect"

        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        components.queryItems = [
            .init(name: "client_id", value: configuration.clientID),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "response_type", value: "code"),
            // openid is all that is needed to get an ID token with a stable
            // `sub`. No profile, no email, no Drive.
            .init(name: "scope", value: "openid"),
            .init(name: "code_challenge", value: challenge),
            .init(name: "code_challenge_method", value: "S256"),
            .init(name: "nonce", value: nonce),
            .init(name: "state", value: state)
        ]

        let callbackURL = try await presentWebAuthSession(
            url: components.url!,
            callbackScheme: configuration.redirectScheme
        )

        let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        // The state check is what stops a callback that did not originate here
        // from being turned into a token exchange.
        guard items.first(where: { $0.name == "state" })?.value == state else {
            throw RelayError.signIn("The Google response did not match this request.")
        }
        guard let code = items.first(where: { $0.name == "code" })?.value else {
            let error = items.first(where: { $0.name == "error" })?.value ?? "no authorization code"
            throw RelayError.signIn("Google returned \(error).")
        }

        return try await exchange(code: code, verifier: verifier, redirectURI: redirectURI)
    }

    private func exchange(code: String, verifier: String, redirectURI: String) async throws -> String {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        var form = URLComponents()
        form.queryItems = [
            .init(name: "client_id", value: configuration.clientID),
            .init(name: "code", value: code),
            .init(name: "code_verifier", value: verifier),
            .init(name: "grant_type", value: "authorization_code"),
            .init(name: "redirect_uri", value: redirectURI)
        ]
        request.httpBody = form.percentEncodedQuery.map { Data($0.utf8) }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw RelayError.signIn("Google refused the token exchange.")
        }
        struct TokenResponse: Decodable { let id_token: String? }
        guard let token = try? JSONDecoder().decode(TokenResponse.self, from: data), let idToken = token.id_token else {
            throw RelayError.signIn("Google returned no ID token.")
        }
        return idToken
    }

    private func presentWebAuthSession(url: URL, callbackScheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error {
                    if (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin {
                        continuation.resume(throwing: RelayError.userCancelled)
                    } else {
                        continuation.resume(throwing: RelayError.signIn(error.localizedDescription))
                    }
                    return
                }
                guard let callbackURL else {
                    continuation.resume(throwing: RelayError.signIn("No callback was received."))
                    return
                }
                continuation.resume(returning: callbackURL)
            }
            // An ephemeral session means no cookie from the user's normal
            // browsing is reused, and nothing is left behind afterwards. It
            // also forces an explicit account choice, which is what you want
            // when the account being chosen governs a security dashboard.
            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self
            self.session = session
            if !session.start() {
                continuation.resume(throwing: RelayError.signIn("The sign-in browser could not be opened."))
            }
        }
    }

    static func randomURLSafeString(bytes count: Int) -> String {
        var buffer = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        return Data(buffer).base64URLEncodedString()
    }
}

extension GoogleSignInController: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        presentationAnchor ?? ASPresentationAnchor()
    }
}

// MARK: - GitHub

/// Sign in with GitHub, through the relay.
///
/// GitHub has no ID token, so the relay is the OAuth client and holds the
/// secret. The app opens the relay's `/auth/github/start` URL, the browser ends
/// on the relay's callback, and the relay hands back a single-use *binding
/// ticket* on a custom scheme. The app never sees a GitHub token.
///
/// Not available to privileged accounts: the relay refuses to bind an ADMIN
/// through GitHub, and the UI hides the button when
/// `GET /api/v1/providers` says so.
@MainActor
public final class GitHubSignInController: NSObject {

    private let callbackScheme: String
    private weak var presentationAnchor: ASPresentationAnchor?
    private var session: ASWebAuthenticationSession?

    public init(callbackScheme: String = "secman-relay", presentationAnchor: ASPresentationAnchor?) {
        self.callbackScheme = callbackScheme
        self.presentationAnchor = presentationAnchor
    }

    /// Opens the relay-hosted flow and returns the binding ticket.
    public func bindingTicket(authorizationURL: URL) async throws -> String {
        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authorizationURL,
                callbackURLScheme: callbackScheme
            ) { callbackURL, error in
                if let error {
                    if (error as? ASWebAuthenticationSessionError)?.code == .canceledLogin {
                        continuation.resume(throwing: RelayError.userCancelled)
                    } else {
                        continuation.resume(throwing: RelayError.signIn(error.localizedDescription))
                    }
                    return
                }
                guard let callbackURL else {
                    continuation.resume(throwing: RelayError.signIn("No callback was received."))
                    return
                }
                continuation.resume(returning: callbackURL)
            }
            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self
            self.session = session
            if !session.start() {
                continuation.resume(throwing: RelayError.signIn("The sign-in browser could not be opened."))
            }
        }

        let items = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
        if let error = items.first(where: { $0.name == "error" })?.value {
            throw RelayError.signIn("The relay reported: \(error).")
        }
        guard let ticket = items.first(where: { $0.name == "ticket" })?.value, !ticket.isEmpty else {
            throw RelayError.signIn("The relay returned no binding ticket.")
        }
        return ticket
    }
}

extension GitHubSignInController: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        presentationAnchor ?? ASPresentationAnchor()
    }
}

// MARK: - Helpers

extension Data {
    /// Unpadded base64url, the encoding OAuth and JOSE use throughout.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
