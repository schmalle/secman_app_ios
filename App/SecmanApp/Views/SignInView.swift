import SecmanRelayKit
import SwiftUI

/// The sign-in screen.
///
/// It offers only the methods the relay says it supports, and it explains the
/// privileged-account rule *before* the user picks — an admin who taps GitHub
/// and gets a 403 learns nothing useful, whereas a button captioned "not for
/// administrator accounts" is actionable.
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
                            Label {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(method.displayName)
                                    if let caption = caption(for: method) {
                                        Text(caption).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            } icon: {
                                Image(systemName: icon(for: method))
                            }
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
                        Text(enrollmentExplanation)
                    }
                }

                Section {
                    LabeledContent("Relay", value: relayHost)
                    if let providers = model.providers {
                        LabeledContent("Sign-in methods", value: providers.providers.map(\.capitalized).joined(separator: ", "))
                    }
                } header: {
                    Text("Connection")
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

    private var privilegedRoles: String? {
        guard let providers = model.providers, !providers.privilegedRoles.isEmpty else { return nil }
        return providers.privilegedRoles.joined(separator: ", ")
    }

    /// Spells out the rule the relay publishes rather than hard-coding it, so a
    /// deployment that widens or narrows it does not need an app release.
    private var policyExplanation: String {
        guard let providers = model.providers, let roles = privilegedRoles else {
            return "Your secman roles decide what you can see. This app never grants access on its own."
        }
        let strong = providers.strongProviders.map(\.capitalized).joined(separator: " or ")
        return "Accounts holding \(roles) must sign in with \(strong). Your secman roles decide what you can see; signing in proves who you are and grants nothing by itself."
    }

    private var enrollmentExplanation: String {
        let base = "A single-use code from a secman administrator."
        guard let roles = privilegedRoles else { return base }
        return "\(base) Not available for \(roles) accounts — those must sign in with a strong provider."
    }

    /// One line under each button saying whether it is open to administrators.
    ///
    /// Derived from `/api/v1/providers`, never from a constant: the relay
    /// decides which providers are strong.
    private func caption(for method: SignInMethod) -> String? {
        guard let providers = model.providers, let roles = privilegedRoles else { return nil }
        let provider: String
        switch method {
        case .apple: provider = "apple"
        case .google: provider = "google"
        case .github: provider = "github"
        case .enrollmentCode: return nil
        }
        return providers.isStrong(provider)
            ? "For every account, including \(roles)"
            : "Not for \(roles) accounts"
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
