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

    enum Phase: Equatable {
        case loading
        /// No relay URL is baked in or stored yet.
        case needsConfiguration
        case signedOut
        case signedIn
    }

    /// Why the snapshot cannot be shown even though the relay answered.
    ///
    /// Distinct from an error: the relay is healthy, the device is authorized,
    /// and refreshing will not change anything. The screen has to say so
    /// persistently rather than flash an alert and fall back to "waiting for
    /// secman", which would be a lie.
    enum SnapshotProblem: Equatable {
        /// The relay serves an envelope version this build does not understand.
        case unsupportedSchema(found: Int, supported: Int)
    }

    /// How often the foreground refresh loop asks `/meta` for news.
    ///
    /// Matches secman's default publish interval (`secman.relay.publish-interval`,
    /// 60s), so a phone left on the desk during an incident tracks the relay
    /// about as closely as it can without polling for nothing. The request is a
    /// few hundred bytes; the loop never triggers a biometric prompt.
    static let foregroundRefreshInterval: Duration = .seconds(60)

    private(set) var phase: Phase = .loading
    /// Who this device is. Fetched once per launch: a display name and a
    /// binding method do not change between two pulls of the same list.
    private(set) var session: RelaySession?
    /// Freshness and entitlements. Fetched on every refresh, because both can
    /// change under the app — a role edit in secman, or a snapshot going stale.
    private(set) var meta: RelayMeta?
    private(set) var snapshot: RelaySnapshot?
    private(set) var snapshotProblem: SnapshotProblem?
    private(set) var providers: RelayProviders?
    private(set) var availableMethods: [SignInMethod] = []
    private(set) var isRefreshing = false

    /// When the relay last answered a refresh in full. Drives the "last checked"
    /// line; the snapshot's own age is a separate number the relay reports.
    private(set) var lastRefreshedAt: Date?
    /// Set when the most recent refresh could not reach the relay, and cleared
    /// by the next one that does. While set, whatever is on screen is the last
    /// data received — the UI labels it rather than dropping it.
    private(set) var lastRefreshFailure: RefreshFailure?

    struct RefreshFailure: Equatable {
        let at: Date
        let message: String
    }

    var alert: String?

    private var client: RelayClient?
    private var authenticator: RelayAuthenticator?
    private let settings = AppSettings()

    /// The `generatedAt` / `instanceId` pair of the last `/status` fetched, so
    /// an unchanged snapshot — or one this build refused for its schema — is
    /// not downloaded again on every poll.
    private var fetchedSnapshotKey: SnapshotKey?

    private struct SnapshotKey: Equatable {
        let instanceId: String
        let generatedAt: Date
    }

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

    /// The local enrollment record: when this device was bound, and how.
    var enrolledDevice: DeviceRecordStore.Record? {
        authenticator?.enrolledDevice
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
            snapshotProblem = nil
            fetchedSnapshotKey = nil
            lastRefreshedAt = nil
            lastRefreshFailure = nil
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

    /// The periodic foreground poll.
    ///
    /// Differs from a user-initiated refresh in one way: it never prompts.
    /// Minting a token costs a Face ID check, and a sheet that appears on its
    /// own every fifteen minutes while the phone sits on a desk is exactly the
    /// prompt people learn to approve without looking. When the token has
    /// lapsed the loop simply waits for the user's next interaction.
    func refreshQuietly() async {
        guard case .signedIn = phase, let client else { return }
        guard await client.hasValidToken else { return }
        await refresh()
    }

    /// Brings the screen up to date for the smallest number of bytes.
    ///
    /// `/meta` is a few hundred bytes and carries everything the shell needs:
    /// how old the snapshot is, and which sections this device may read.
    /// `/status` — the actual payload, and the only large response the app ever
    /// downloads — is fetched only when `generatedAt` has moved since the copy
    /// already in memory. secman pushes about once a minute, so a foreground
    /// poll usually does download it; the saving is on the phone that wakes up
    /// several times between two pushes.
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
                meta = latest
                let key = SnapshotKey(instanceId: latest.instanceId, generatedAt: latest.generatedAt)
                if key != fetchedSnapshotKey {
                    try await fetchSnapshot(using: client)
                    fetchedSnapshotKey = key
                }
            } catch RelayError.noSnapshotYet {
                // The relay is healthy but secman has not pushed. Show the
                // shell with an explanatory empty state rather than an error.
                meta = nil
                snapshot = nil
                snapshotProblem = nil
                fetchedSnapshotKey = nil
            }

            lastRefreshedAt = Date()
            lastRefreshFailure = nil
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
        } catch RelayError.transport(let underlying) {
            // Unreachable is a state, not an event. The list header says so
            // for as long as it lasts, and the last data received stays on
            // screen with its age — an alert on every tunnel would be noise.
            lastRefreshFailure = RefreshFailure(at: Date(), message: Self.unreachableMessage)
            if session == nil {
                // Nothing is on screen yet, so there is nothing to label.
                present(RelayError.transport(underlying))
                phase = .signedOut
            }
        } catch {
            present(error)
            if session == nil { phase = .signedOut }
        }
    }

    /// Downloads `/status`, keeping "no snapshot" and "wrong schema" apart.
    ///
    /// Both leave `snapshot` nil, but they are opposite situations: one clears
    /// itself on secman's next push, the other only clears with an app update.
    /// Every other failure propagates to `refresh()` and is handled exactly as
    /// it would be for `/meta`.
    private func fetchSnapshot(using client: RelayClient) async throws {
        do {
            snapshot = try await client.statusIfAvailable()
            snapshotProblem = nil
        } catch RelayError.unsupportedSchema(let found, let supported) {
            snapshot = nil
            snapshotProblem = .unsupportedSchema(found: found, supported: supported)
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

    static let unreachableMessage = "The relay could not be reached. Showing the last data received."

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

    /// "1.0 (1)" for the settings screen.
    var appVersion: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(short) (\(build))"
    }
}
