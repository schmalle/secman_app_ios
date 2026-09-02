import SecmanRelayKit
import SwiftUI

/// secman status — a read-only view of the security posture secman publishes,
/// for iPhone and iPad.
///
/// The app has no write path of any kind. It cannot change an asset, approve an
/// exception, or reach secman at all: it talks only to the relay, which holds a
/// snapshot secman pushed out to it. See ../../docs/ARCHITECTURE.md.
@main
struct SecmanApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                // The status is security state. Blur it in the app switcher so
                // a screenshot of a locked phone does not show the fleet's
                // vulnerability counts.
                .privacySensitive()
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    /// What the foreground poll keys on: it runs only while signed in and on
    /// screen, and restarts from zero whenever either changes.
    private struct PollKey: Equatable {
        let signedIn: Bool
        let active: Bool
    }

    private var pollKey: PollKey {
        PollKey(signedIn: model.phase == .signedIn, active: scenePhase == .active)
    }

    var body: some View {
        Group {
            switch model.phase {
            case .loading:
                ProgressView("Connecting…")
            case .needsConfiguration:
                ConfigurationView()
            case .signedOut:
                SignInView()
            case .signedIn:
                StatusView()
            }
        }
        .task { await model.start() }
        .onChange(of: scenePhase) { _, phase in
            // Returning from the background re-authenticates rather than
            // resuming a stale token. It costs one Face ID prompt and removes
            // "the app was left open on a desk" as a threat.
            if phase == .active { Task { await model.refreshIfNeeded() } }
        }
        .task(id: pollKey) {
            // While the app is on screen, ask /meta for news about once a
            // minute — secman's own push cadence. The poll never prompts: once
            // the fifteen-minute token lapses it waits for the user instead of
            // raising Face ID on its own.
            guard pollKey.signedIn, pollKey.active else { return }
            while !Task.isCancelled {
                try? await Task.sleep(for: AppModel.foregroundRefreshInterval)
                guard !Task.isCancelled else { return }
                await model.refreshQuietly()
            }
        }
        .alert(
            "Something went wrong",
            isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } }),
            presenting: model.alert
        ) { _ in
            Button("OK", role: .cancel) { model.alert = nil }
        } message: { message in
            Text(message)
        }
    }
}
