import Foundation

/// HTTP client for the relay's mobile API.
///
/// Everything the app sends or receives goes through here, which is what makes
/// the security properties checkable in one place:
///
///  - TLS is mandatory. A plaintext relay URL is refused at configuration time,
///    not at request time, so it cannot slip through in a debug build.
///  - Optional SPKI pinning. Off by default because a Let's Encrypt certificate
///    rotates every ~60 days and a pinned leaf would brick the app; on when the
///    operator supplies a pin set and accepts the rotation procedure.
///  - No cookies, no credential store, no redirects. The relay never redirects
///    an API call, so following one could only ever help an attacker.
///  - The access token lives in memory only, and never in a URL.
public actor RelayClient {

    public struct Configuration: Sendable {
        /// Base URL of the relay, e.g. `https://relay.example.com`.
        public let baseURL: URL
        /// Optional base64 SHA-256 SPKI pins. Empty disables pinning.
        public let publicKeyPins: Set<String>
        public let requestTimeout: TimeInterval

        public init(baseURL: URL, publicKeyPins: Set<String> = [], requestTimeout: TimeInterval = 20) throws {
            guard let scheme = baseURL.scheme?.lowercased(), scheme == "https" else {
                throw RelayError.notConfigured
            }
            guard baseURL.host != nil else { throw RelayError.notConfigured }
            self.baseURL = baseURL
            self.publicKeyPins = publicKeyPins
            self.requestTimeout = requestTimeout
        }
    }

    /// How a 503 should be read.
    ///
    /// The relay answers 503 for three unrelated situations — no snapshot has
    /// been pushed yet, the device registry is full, and "cannot start a login
    /// right now" — and only the first is the app's cheerful "waiting for
    /// secman" state. Telling an admin whose registry is full that secman has
    /// not pushed yet sends them to debug the wrong system.
    private enum Unavailable {
        case meansNoSnapshot
        case meansServerBusy
    }

    /// The `body` argument for a GET. A named empty type rather than
    /// `Optional<Never>.none`, which reads as a puzzle at every call site.
    private struct EmptyBody: Encodable {}
    private static let noBody: EmptyBody? = nil

    private let configuration: Configuration
    // nonisolated because `deinit` has to reach it, and deinit is not
    // actor-isolated. URLSession is documented thread-safe and this is a `let`.
    nonisolated(unsafe) private let session: URLSession
    private let decoder = RelayJSON.decoder
    private let encoder = RelayJSON.encoder

    /// The current access token. In memory only: it lives fifteen minutes and
    /// re-minting it costs one biometric-gated round trip, so persisting it
    /// would add attack surface for no real benefit.
    private var accessToken: String?
    private var accessTokenExpiry: Date?

    public init(configuration: Configuration) {
        self.configuration = configuration

        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = configuration.requestTimeout
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        config.httpAdditionalHeaders = ["Accept": "application/json"]

        self.session = URLSession(
            configuration: config,
            delegate: RelayURLSessionDelegate(pins: configuration.publicKeyPins),
            delegateQueue: nil
        )
    }

    deinit {
        // A URLSession with a delegate retains it until invalidated. Without
        // this the delegate — and the session's operation queue — outlive the
        // client for the life of the process.
        session.finishTasksAndInvalidate()
    }

    // MARK: - Session state

    public var hasValidToken: Bool {
        guard accessToken != nil, let expiry = accessTokenExpiry else { return false }
        // Treat a token as spent 30s early so a request does not expire in
        // flight and surface as a spurious "session expired".
        return expiry.timeIntervalSinceNow > 30
    }

    public func clearToken() {
        accessToken = nil
        accessTokenExpiry = nil
    }

    private func store(token: RelayToken) {
        accessToken = token.accessToken
        accessTokenExpiry = Date().addingTimeInterval(TimeInterval(token.expiresIn))
    }

    // MARK: - Discovery

    public func providers() async throws -> RelayProviders {
        try await send(path: "/api/v1/providers", method: "GET", body: RelayClient.noBody, authenticated: false)
    }

    // MARK: - Sign-in

    public func loginNonce(publicKeyBase64: String) async throws -> RelayLoginNonce {
        struct Body: Encodable { let publicKey: String }
        return try await send(
            path: "/api/v1/auth/nonce",
            method: "POST",
            body: Body(publicKey: publicKeyBase64),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    /// Completes an Apple or Google sign-in by binding this device.
    public func bindWithIDToken(
        provider: String,
        idToken: String,
        nonce: String,
        publicKeyBase64: String,
        signatureBase64: String,
        deviceName: String
    ) async throws -> RelayBinding {
        struct Body: Encodable {
            let provider: String
            let idToken: String
            let nonce: String
            let publicKey: String
            let signature: String
            let deviceName: String
        }
        return try await send(
            path: "/api/v1/auth/oidc",
            method: "POST",
            body: Body(
                provider: provider, idToken: idToken, nonce: nonce,
                publicKey: publicKeyBase64, signature: signatureBase64, deviceName: deviceName
            ),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    public func startGitHubSignIn(publicKeyBase64: String, deviceName: String) async throws -> RelayGitHubStart {
        struct Body: Encodable {
            let publicKey: String
            let deviceName: String
        }
        return try await send(
            path: "/api/v1/auth/github/start",
            method: "POST",
            body: Body(publicKey: publicKeyBase64, deviceName: deviceName),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    public func completeGitHubSignIn(
        ticket: String,
        publicKeyBase64: String,
        signatureBase64: String,
        deviceName: String
    ) async throws -> RelayBinding {
        struct Body: Encodable {
            let ticket: String
            let publicKey: String
            let signature: String
            let deviceName: String
        }
        return try await send(
            path: "/api/v1/auth/github/complete",
            method: "POST",
            body: Body(ticket: ticket, publicKey: publicKeyBase64, signature: signatureBase64, deviceName: deviceName),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    /// Binds a device with an admin-issued enrollment code.
    ///
    /// Available only to non-privileged accounts; the relay refuses it for
    /// anyone holding a privileged role.
    public func enrol(code: String, publicKeyBase64: String, deviceName: String) async throws -> RelayBinding {
        struct Body: Encodable {
            let enrollmentCode: String
            let publicKey: String
            let deviceName: String
        }
        return try await send(
            path: "/api/v1/enroll",
            method: "POST",
            body: Body(enrollmentCode: code, publicKey: publicKeyBase64, deviceName: deviceName),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    // MARK: - Per-session authentication

    public func challenge(deviceId: String) async throws -> RelayChallenge {
        struct Body: Encodable { let deviceId: String }
        return try await send(
            path: "/api/v1/auth/challenge",
            method: "POST",
            body: Body(deviceId: deviceId),
            authenticated: false,
            unavailable: .meansServerBusy
        )
    }

    @discardableResult
    public func exchange(deviceId: String, nonce: String, signatureBase64: String) async throws -> RelayToken {
        struct Body: Encodable {
            let deviceId: String
            let nonce: String
            let signature: String
        }
        let token: RelayToken = try await send(
            path: "/api/v1/auth/token",
            method: "POST",
            body: Body(deviceId: deviceId, nonce: nonce, signature: signatureBase64),
            authenticated: false,
            unavailable: .meansServerBusy
        )
        store(token: token)
        return token
    }

    // MARK: - Reads

    public func session() async throws -> RelaySession {
        try await send(path: "/api/v1/session", method: "GET", body: RelayClient.noBody, authenticated: true)
    }

    /// Freshness and entitlements without the payload — the cheap poll.
    public func meta() async throws -> RelayMeta {
        try await send(
            path: "/api/v1/meta", method: "GET", body: RelayClient.noBody,
            authenticated: true, unavailable: .meansNoSnapshot
        )
    }

    public func status() async throws -> RelaySnapshot {
        let snapshot: RelaySnapshot = try await send(
            path: "/api/v1/status", method: "GET", body: RelayClient.noBody,
            authenticated: true, unavailable: .meansNoSnapshot
        )
        guard snapshot.schemaVersion == relaySupportedSnapshotSchemaVersion else {
            // Refuse rather than render half of it: a status screen that
            // silently drops the field it did not understand is worse than one
            // that says "update the app".
            throw RelayError.unsupportedSchema(
                found: snapshot.schemaVersion,
                supported: relaySupportedSnapshotSchemaVersion
            )
        }
        return snapshot
    }

    /// The snapshot, or nil when the relay is healthy but secman has not pushed.
    ///
    /// "Waiting for secman" is a normal state on a freshly deployed relay, not
    /// a failure, and modelling it as one forces every caller to catch.
    public func statusIfAvailable() async throws -> RelaySnapshot? {
        do {
            return try await status()
        } catch RelayError.noSnapshotYet {
            return nil
        }
    }

    // MARK: - Transport

    private func send<Body: Encodable, Response: Decodable>(
        path: String,
        method: String,
        body: Body?,
        authenticated: Bool,
        unavailable: Unavailable = .meansServerBusy
    ) async throws -> Response {
        var request = URLRequest(url: configuration.baseURL.appending(path: path))
        request.httpMethod = method
        request.timeoutInterval = configuration.requestTimeout

        if let body {
            request.httpBody = try encoder.encode(body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if authenticated {
            guard let accessToken else { throw RelayError.unauthenticated }
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch let error as URLError where error.code == .cancelled {
            throw RelayError.userCancelled
        } catch {
            throw RelayError.transport(error)
        }

        guard let http = response as? HTTPURLResponse else {
            throw RelayError.malformedResponse("not an HTTP response")
        }

        switch http.statusCode {
        case 200...299:
            do {
                return try decoder.decode(Response.self, from: data)
            } catch {
                throw RelayError.malformedResponse("could not read the \(Response.self) the relay sent")
            }
        case 401:
            clearToken()
            throw RelayError.unauthenticated
        case 403:
            throw RelayError.forbidden(message(from: data) ?? "This account is not permitted to use the app.")
        case 429:
            let retryAfter = http.value(forHTTPHeaderField: "Retry-After").flatMap { Double($0) }
            throw RelayError.rateLimited(retryAfter: retryAfter)
        case 503:
            switch unavailable {
            case .meansNoSnapshot:
                throw RelayError.noSnapshotYet
            case .meansServerBusy:
                throw RelayError.http(status: 503, message: message(from: data))
            }
        default:
            throw RelayError.http(status: http.statusCode, message: message(from: data))
        }
    }

    private func message(from data: Data) -> String? {
        guard let body = try? decoder.decode(RelayErrorBody.self, from: data) else { return nil }
        return body.error
    }
}

/// TLS and redirect policy for the relay session.
///
/// Pinning is opt-in. When no pins are configured the delegate leaves trust
/// evaluation to the system (plus App Transport Security) — the right default
/// for a relay using Let's Encrypt, where a pinned certificate would stop
/// working at the next renewal.
///
/// When pins *are* configured they are SPKI hashes, not certificate hashes, so
/// a renewal that reuses the key keeps working. Supply at least two — the
/// current key and a spare — or a forced key rotation locks every installed app
/// out until an App Store release ships.
/// `@unchecked` only because the superclass is `NSObject`: the single stored
/// property is an immutable `Set<String>`, so there is nothing to race on.
final class RelayURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let pins: Set<String>

    init(pins: Set<String>) {
        self.pins = pins
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            return (.performDefaultHandling, nil)
        }
        if pins.isEmpty {
            return (.performDefaultHandling, nil)
        }

        // Chain validity first. Pinning is an *addition* to the platform's
        // checks, never a replacement — a pinned but expired or hostname-
        // mismatched certificate must still be refused.
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            return (.cancelAuthenticationChallenge, nil)
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
            return (.cancelAuthenticationChallenge, nil)
        }
        for certificate in chain {
            guard let key = SecCertificateCopyKey(certificate),
                  let digest = try? SPKI.pin(from: key) else {
                continue
            }
            if pins.contains(digest) {
                return (.useCredential, URLCredential(trust: trust))
            }
        }
        return (.cancelAuthenticationChallenge, nil)
    }

    /// Refuses every redirect.
    ///
    /// No relay API route redirects — the one route that does,
    /// `/auth/github/callback`, is reached by the browser and never by this
    /// session. So a redirect here is either a misconfigured proxy or an
    /// attempt to walk the app to another host, possibly carrying the
    /// `Authorization` header with it. Returning nil delivers the 3xx to the
    /// caller, which then fails as an unexpected status.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
