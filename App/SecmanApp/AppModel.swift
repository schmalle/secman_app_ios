import Foundation
import SecmanRelayKit
import SwiftUI
import UIKit

/// The app's single source of truth.
///
/// Everything the UI shows about *what the user may see* comes from the relay's
/// `/api/v1/session` — never from a local role check. If the server says a
/// section is not readable, the tab does not exist; if the server changes its
/// mind, the next refresh changes the UI. That keeps the client from developing
/// its own, inevitably divergent, opinion about authorization.
@Observable
@MainActor
final class AppModel {

    enum Phase {
        case loading
        /// No relay URL is baked in or stored yet.
        case needsConfiguration
        case signedOut
        case signedIn
    }

    private(set) var phase: Phase = .loading
    private(set) var session: RelaySession?
    private(set) var snapshot: RelaySnapshot?
    private(set) var providers: RelayProviders?
    private(set) var availableMethods: [SignInMethod] = []
    private(set) var isRefreshing = false

    var alert: String?

    private var client: RelayClient?
    private var authenticator: RelayAuthenticator?
    private let settings = AppSettings()

    // MARK: - Lifecycle

    func start() async {
        guard case .loading = phase else { return }
        guard let url = settings.relayURL else {
            phase = .needsConfiguration
            return
        }
        await connect(to: url)
    }

    func connect(to url: URL) async {
        do {
            let configuration = try RelayClient.Configuration(
                baseURL: url,
                publicKeyPins: settings.publicKeyPins
            )
            let client = RelayClient(configuration: configuration)
            let authenticator = RelayAuthenticator(client: client, deviceName: Self.deviceName)

            self.client = client
            self.authenticator = authenticator
            settings.relayURL = url

            let discovery = try await authenticator.availableMethods()
            providers = discovery.providers
            availableMethods = discovery.methods

            if authenticator.enrolledDevice != nil {
                await refresh()
            } else {
                phase = .signedOut
            }
        } catch {
            present(error)
            phase = .needsConfiguration
        }
    }

    // MARK: - Sign-in

    func signIn(using method: SignInMethod, enrollmentCode: String = "") async {
        guard let authenticator else { return }
        do {
            switch method {
            case .apple:
                let controller = AppleSignInController(presentationAnchor: Self.presentationAnchor())
                try await authenticator.bind(provider: "apple") { nonce in
                    try await controller.identityToken(nonceHash: nonce.nonceHash)
                }

            case .google:
                guard let clientID = settings.googleClientID else {
                    throw RelayError.signIn("This build has no Google client id configured.")
                }
                let controller = GoogleSignInController(
                    configuration: .init(clientID: clientID),
                    presentationAnchor: Self.presentationAnchor()
                )
                try await authenticator.bind(provider: "google") { nonce in
                    try await controller.identityToken(nonce: nonce.nonce)
                }

            case .github:
                let controller = GitHubSignInController(presentationAnchor: Self.presentationAnchor())
                try await authenticator.bindWithGitHub { url in
                    try await controller.bindingTicket(authorizationURL: url)
                }

            case .enrollmentCode:
                try await authenticator.bind(enrollmentCode: enrollmentCode)
            }
            await refresh()
        } catch RelayError.userCancelled {
            // Not an error worth an alert.
        } catch {
            present(error)
        }
    }

    func signOut() {
        do {
            try authenticator?.signOutLocally()
            Task { await client?.clearToken() }
            session = nil
            snapshot = nil
            phase = .signedOut
        } catch {
            present(error)
        }
    }

    // MARK: - Data

    func refreshIfNeeded() async {
        guard case .signedIn = phase else { return }
        await refresh()
    }

    func refresh() async {
        guard let client, let authenticator else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        do {
            try await authenticator.ensureSession()
            // Session first: it tells us which sections are readable, and the
            // answer may have changed since the last launch because somebody's
            // roles changed in secman.
            session = try await client.session()
            snapshot = try await client.status()
            phase = .signedIn
        } catch RelayError.noSnapshotYet {
            // The relay is healthy but secman has not pushed yet. Show the
            // shell with an explanatory empty state rather than an error.
            session = try? await client.session()
            snapshot = nil
            phase = .signedIn
        } catch RelayError.unauthenticated {
            phase = .signedOut
        } catch RelayError.forbidden(let message) {
            // Re-signing in cannot fix this: an admin has to change something
            // in secman. Say so plainly instead of looping the sign-in sheet.
            alert = message
            phase = .signedOut
        } catch RelayError.userCancelled {
            phase = .signedOut
        } catch {
            present(error)
            if session == nil { phase = .signedOut }
        }
    }

    /// The sections this device may read, in a stable display order.
    var visibleSections: [RelaySection] {
        guard let session else { return [] }
        return RelaySection.allCases.filter { session.sections.contains($0.rawValue) }
    }

    // MARK: - Helpers

    private func present(_ error: Error) {
        alert = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }

    private static var deviceName: String {
        UIDevice.current.name
    }

    private static func presentationAnchor() -> UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow }
    }
}

/// Non-secret app configuration.
///
/// The relay URL and the Google client id are not credentials, so `UserDefaults`
/// is the right home. Nothing sensitive is stored here — the enclave key is in
/// the Secure Enclave, the device record is in the Keychain, and the access
/// token is only ever in memory.
struct AppSettings {
    private let defaults = UserDefaults.standard

    var relayURL: URL? {
        get {
            if let configured = Bundle.main.object(forInfoDictionaryKey: "SecmanRelayURL") as? String,
               let url = URL(string: configured), url.scheme == "https" {
                // A URL baked into the build wins: a managed deployment should
                // not depend on the user typing the right host.
                return url
            }
            guard let stored = defaults.string(forKey: "relayURL") else { return nil }
            return URL(string: stored)
        }
        nonmutating set {
            defaults.set(newValue?.absoluteString, forKey: "relayURL")
        }
    }

    var googleClientID: String? {
        Bundle.main.object(forInfoDictionaryKey: "SecmanGoogleClientID") as? String
    }

    /// Optional SPKI pins, base64 SHA-256, from the app bundle.
    var publicKeyPins: Set<String> {
        let pins = Bundle.main.object(forInfoDictionaryKey: "SecmanRelayPublicKeyPins") as? [String] ?? []
        return Set(pins)
    }
}
