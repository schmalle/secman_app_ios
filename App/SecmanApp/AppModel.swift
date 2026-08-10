import Foundation
import SecmanRelayKit
import SwiftUI
import UIKit

/// The app's single source of truth.
///
/// Everything the UI shows about *what the user may see* comes from the relay's
/// `/api/v1/session` — never from a local role check. If the server says a
/// section is not readable, it does not appear; if the server changes its mind,
/// the next refresh changes the UI. That keeps the client from developing its
/// own, inevitably divergent, opinion about authorization.
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
    /// Who this device is. Fetched once per launch: a display name and a
    /// binding method do not change between two pulls of the same list.
    private(set) var session: RelaySession?
    /// Freshness and entitlements. Fetched on every refresh, because both can
    /// change under the app — a role edit in secman, or a snapshot going stale.
    private(set) var meta: RelayMeta?
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
            Task { [client] in await client?.clearToken() }
            session = nil
            meta = nil
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

    /// Brings the screen up to date for the smallest number of bytes.
    ///
    /// `/meta` is a few hundred bytes and carries everything the shell needs:
    /// how old the snapshot is, and which sections this device may read.
    /// `/status` — the actual payload, and the only large response the app ever
    /// downloads — is fetched only when `generatedAt` has moved since the copy
    /// already in memory. On a phone that wakes up several times an hour behind
    /// a relay secman pushes to every fifteen minutes, most refreshes are the
    /// small request alone.
    func refresh() async {
        guard let client, let authenticator else { return }
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        do {
            try await authenticator.ensureSession()

            if session == nil {
                session = try await client.session()
            }

            do {
                let latest = try await client.meta()
                let unchanged = latest.instanceId == snapshot?.instanceId
                    && latest.generatedAt == snapshot?.generatedAt
                meta = latest
                if !unchanged {
                    snapshot = try await client.statusIfAvailable()
                }
            } catch RelayError.noSnapshotYet {
                // The relay is healthy but secman has not pushed. Show the
                // shell with an explanatory empty state rather than an error.
                meta = nil
                snapshot = nil
            }

            phase = .signedIn
        } catch RelayError.unauthenticated {
            phase = .signedOut
        } catch RelayError.forbidden(let message) {
            // Re-signing in cannot fix this: an admin has to change something
            // in secman. Say so plainly instead of looping the sign-in sheet.
            alert = message
            phase = .signedOut
        } catch RelayError.userCancelled {
            // The user dismissed Face ID. Keep whatever is on screen; nagging
            // with an alert they just declined helps nobody.
            if session == nil { phase = .signedOut }
        } catch {
            present(error)
            if session == nil { phase = .signedOut }
        }
    }

    /// The sections this device may read, in a stable display order.
    ///
    /// Taken from the relay's answer and only *ordered* locally. A section this
    /// build has never heard of still appears — see `RelaySectionID`.
    var visibleSections: [RelaySectionID] {
        // /meta is the fresher of the two and reflects a role change a refresh
        // earlier than the once-per-launch /session would.
        let names = meta?.sections ?? session?.sections ?? []
        return names.map(RelaySectionID.init).sorted()
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
