import SecmanRelayKit
import SwiftUI

/// Who this device is, what it may read, how fresh what it shows is — and how
/// to stop being it.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmingSignOut = false

    var body: some View {
        List {
            if let session = model.session {
                Section("Account") {
                    LabeledContent("secman user", value: session.subject)
                    if let name = session.displayName, !name.isEmpty, name != session.subject {
                        LabeledContent("Name", value: name)
                    }
                    LabeledContent("Roles", value: session.roles.isEmpty ? "none" : session.roles.joined(separator: ", "))
                    LabeledContent("Signed in with", value: signInDescription(session))
                }

                Section {
                    LabeledContent("Device", value: session.deviceId)
                    if let record = model.enrolledDevice {
                        LabeledContent("Registered", value: record.boundAt.formatted(date: .abbreviated, time: .shortened))
                    }
                    LabeledContent("Scope", value: RelayFormat.scopes(session.scopes))
                    LabeledContent("Readable sections", value: sectionsDescription)
                } header: {
                    Text("This device")
                } footer: {
                    Text("Quote the device identifier when asking an administrator to revoke the device. The scope is a per-device narrowing an administrator can apply on top of your roles; it can never widen them.")
                }
            }

            Section {
                if let refreshed = model.lastRefreshedAt {
                    LabeledContent("Last checked") {
                        Text(refreshed, style: .relative) + Text(" ago")
                    }
                } else {
                    LabeledContent("Last checked", value: "not yet")
                }
                if let failure = model.lastRefreshFailure {
                    LabeledContent("Relay unreachable since") {
                        Text(failure.at, style: .relative) + Text(" ago")
                    }
                    .foregroundStyle(.orange)
                }
                if let meta = model.meta {
                    LabeledContent("Snapshot from") {
                        Text(meta.generatedAt, style: .relative) + Text(" ago")
                    }
                    LabeledContent("Considered stale after", value: RelayFormat.duration(seconds: meta.maxAgeSeconds))
                    LabeledContent("secman instance", value: meta.instanceId)
                    LabeledContent("Status format", value: formatDescription(meta.schemaVersion))
                } else {
                    LabeledContent("Snapshot", value: "none received yet")
                }
                LabeledContent("Checks for news", value: "every \(RelayFormat.duration(seconds: Int(AppModel.foregroundRefreshInterval.components.seconds))) while open")
            } header: {
                Text("Freshness")
            } footer: {
                Text("The relay reports how old its copy of secman's status is. The app asks for news about once a minute while it is on screen, and again whenever it returns to the foreground. Checking never prompts for Face ID on its own.")
            }

            if let providers = model.providers {
                Section {
                    LabeledContent("Sign-in methods", value: providers.providers.map(\.capitalized).joined(separator: ", "))
                    LabeledContent("Enrollment codes", value: providers.enrollmentCodes ? "on" : "off")
                    if !providers.privilegedRoles.isEmpty {
                        LabeledContent("Privileged roles", value: providers.privilegedRoles.joined(separator: ", "))
                        LabeledContent("Strong providers", value: providers.strongProviders.map(\.capitalized).joined(separator: ", "))
                    }
                } header: {
                    Text("Relay policy")
                } footer: {
                    Text("Published by the relay and enforced by it on every session. Accounts holding a privileged role can only be registered through a strong provider.")
                }
            }

            Section {
                LabeledContent("Relay", value: AppSettings().relayURL?.host() ?? "not configured")
                LabeledContent("Certificate pinning", value: AppSettings().publicKeyPins.isEmpty ? "off" : "on")
                LabeledContent("App version", value: AppSettings().appVersion)
            } header: {
                Text("Connection")
            } footer: {
                Text("This app connects only to the relay. It holds no secman credential and cannot reach secman directly. Nothing it shows is stored on this device.")
            }

            Section {
                Button("Sign out on this device", role: .destructive) {
                    confirmingSignOut = true
                }
            } footer: {
                // Being honest about what sign-out is and is not matters more
                // than sounding reassuring: on a lost phone this button is not
                // the control that helps.
                Text("Removes this device's key and registration from this phone. It does not revoke the device on the relay — ask an administrator to do that in secman if the device is lost.")
            }
        }
        .navigationTitle("Settings")
        .confirmationDialog(
            "Sign out on this device?",
            isPresented: $confirmingSignOut,
            titleVisibility: .visible
        ) {
            Button("Sign out", role: .destructive) { model.signOut() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You will need to sign in again to see status. Registering again requires a new sign-in or a new enrollment code.")
        }
    }

    private func signInDescription(_ session: RelaySession) -> String {
        if let provider = session.provider, !provider.isEmpty {
            return provider.capitalized
        }
        return session.boundVia == "code" ? "Enrollment code" : session.boundVia
    }

    private var sectionsDescription: String {
        let sections = model.visibleSections
        if sections.isEmpty { return "none" }
        return "\(sections.count) — " + sections.map(\.displayName).joined(separator: ", ")
    }

    private func formatDescription(_ version: Int) -> String {
        version == relaySupportedSnapshotSchemaVersion
            ? "v\(version)"
            : "v\(version) (this app understands v\(relaySupportedSnapshotSchemaVersion))"
    }
}

/// First-run screen for a build with no relay URL baked in.
struct ConfigurationView: View {
    @Environment(AppModel.self) private var model
    @State private var host = ""
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("relay.example.com", text: $host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("Relay address")
                } footer: {
                    Text("Ask your secman administrator. The connection is always HTTPS; a plain http address is refused.")
                }

                Button("Connect") {
                    Task {
                        isWorking = true
                        if let url = normalizedURL {
                            await model.connect(to: url)
                        }
                        isWorking = false
                    }
                }
                .disabled(normalizedURL == nil || isWorking)
            }
            .navigationTitle("Set up")
        }
    }

    /// Accepts a bare hostname and makes it https, but never downgrades an
    /// explicit scheme the user typed — a pasted `http://` address is left
    /// invalid so it is rejected rather than silently "fixed".
    private var normalizedURL: URL? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let url = URL(string: candidate), url.scheme == "https", url.host() != nil else { return nil }
        return url
    }
}
