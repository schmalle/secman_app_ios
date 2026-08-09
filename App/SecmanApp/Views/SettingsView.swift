import SecmanRelayKit
import SwiftUI

/// Who this device is, and how to stop being it.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmingSignOut = false

    var body: some View {
        List {
            if let session = model.session {
                Section("Account") {
                    LabeledContent("secman user", value: session.subject)
                    LabeledContent("Roles", value: session.roles.isEmpty ? "none" : session.roles.joined(separator: ", "))
                    LabeledContent("Signed in with", value: signInDescription(session))
                }

                Section {
                    LabeledContent("Device", value: session.deviceId)
                } header: {
                    Text("This device")
                } footer: {
                    Text("Quote this identifier when asking an administrator to revoke the device.")
                }
            }

            Section {
                LabeledContent("Relay", value: AppSettings().relayURL?.host() ?? "not configured")
                LabeledContent("Certificate pinning", value: AppSettings().publicKeyPins.isEmpty ? "off" : "on")
            } header: {
                Text("Connection")
            } footer: {
                Text("This app connects only to the relay. It holds no secman credential and cannot reach secman directly.")
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
