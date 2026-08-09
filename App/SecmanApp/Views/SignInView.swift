import SecmanRelayKit
import SwiftUI

/// The sign-in screen.
///
/// It offers only the methods the relay says it supports, and it explains the
/// privileged-account rule *before* the user picks — an admin who taps GitHub
/// and gets a 403 learns nothing useful, whereas a greyed-out button with a
/// one-line reason is actionable.
struct SignInView: View {
    @Environment(AppModel.self) private var model
    @State private var enrollmentCode = ""
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    ForEach(model.availableMethods.filter { $0 != .enrollmentCode }, id: \.self) { method in
                        Button {
                            Task { await run { await model.signIn(using: method) } }
                        } label: {
                            Label(method.displayName, systemImage: icon(for: method))
                        }
                        .disabled(isWorking)
                    }
                } header: {
                    Text("Sign in")
                } footer: {
                    Text(policyExplanation)
                }

                if model.availableMethods.contains(.enrollmentCode) {
                    Section {
                        TextField("XXXXX-XXXXX-XXXXX-XXXXX", text: $enrollmentCode)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                            .font(.system(.body, design: .monospaced))

                        Button("Register with code") {
                            Task { await run { await model.signIn(using: .enrollmentCode, enrollmentCode: enrollmentCode) } }
                        }
                        .disabled(isWorking || enrollmentCode.count < 8)
                    } header: {
                        Text("Enrollment code")
                    } footer: {
                        Text("A single-use code from a secman administrator. Not available for administrator accounts — those must sign in with Apple or Google.")
                    }
                }

                Section {
                    LabeledContent("Relay", value: relayHost)
                } footer: {
                    Text("This app talks only to the relay. It has no connection to secman itself and cannot change anything.")
                }
            }
            .navigationTitle("secman")
            .overlay {
                if isWorking { ProgressView().controlSize(.large) }
            }
        }
    }

    private var relayHost: String {
        AppSettings().relayURL?.host() ?? "not configured"
    }

    /// Spells out the rule the relay publishes rather than hard-coding it, so a
    /// deployment that widens or narrows it does not need an app release.
    private var policyExplanation: String {
        guard let providers = model.providers, !providers.privilegedRoles.isEmpty else {
            return "Your secman roles decide what you can see. This app never grants access on its own."
        }
        let roles = providers.privilegedRoles.joined(separator: ", ")
        let strong = providers.strongProviders.map(\.capitalized).joined(separator: " or ")
        return "Accounts holding \(roles) must sign in with \(strong). Your secman roles decide what you can see."
    }

    private func icon(for method: SignInMethod) -> String {
        switch method {
        case .apple: return "apple.logo"
        case .google: return "g.circle"
        case .github: return "chevron.left.forwardslash.chevron.right"
        case .enrollmentCode: return "number"
        }
    }

    private func run(_ work: () async -> Void) async {
        isWorking = true
        await work()
        isWorking = false
    }
}
