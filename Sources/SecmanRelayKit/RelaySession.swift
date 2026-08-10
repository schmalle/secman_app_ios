import Foundation
import Security

/// Where the device's non-secret enrollment state lives.
///
/// Only the device id and a display hint are persisted. The access token is
/// not: it lives fifteen minutes, re-minting it costs one biometric-gated round
/// trip, and a token on disk is a token in a backup.
///
/// The device id is not a credential either — without the enclave key it
/// authenticates nothing — but it is stored `ThisDeviceOnly` so it does not
/// travel in an iCloud backup and confuse a restored device into thinking it is
/// already enrolled.
public struct DeviceRecordStore: Sendable {

    public struct Record: Codable, Sendable, Equatable {
        public let deviceId: String
        public let subject: String
        public let boundVia: String
        public let provider: String?
        public let boundAt: Date

        public init(deviceId: String, subject: String, boundVia: String, provider: String?, boundAt: Date = Date()) {
            self.deviceId = deviceId
            self.subject = subject
            self.boundVia = boundVia
            self.provider = provider
            self.boundAt = boundAt
        }
    }

    private let service: String
    private let account = "device-record"

    public init(service: String = "io.secman.relay") {
        self.service = service
    }

    public func load() throws -> Record? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            // A record written by an older build that cannot be decoded is
            // treated as absent rather than fatal: the worst case is one
            // re-enrollment, and refusing to launch would be much worse.
            return try? RelayJSON.decoder.decode(Record.self, from: data)
        case errSecItemNotFound:
            return nil
        default:
            throw RelayError.keychain(status: status, operation: "reading the device record")
        }
    }

    public func save(_ record: Record) throws {
        let data = try RelayJSON.encoder.encode(record)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw RelayError.keychain(status: updateStatus, operation: "updating the device record")
        }

        var insert = query
        insert.merge(attributes) { _, new in new }
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw RelayError.keychain(status: addStatus, operation: "storing the device record")
        }
    }

    public func clear() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw RelayError.keychain(status: status, operation: "clearing the device record")
        }
    }
}

/// Drives enrollment and session renewal.
///
/// The whole client-side protocol lives here, in one readable sequence, so a
/// reviewer can check it against `docs/SECURITY.md` without chasing callbacks:
///
/// **Binding (once per device)**
/// 1. create or load the Secure Enclave key
/// 2. ask the relay for a nonce bound to that key's fingerprint
/// 3. prove who the user is (Apple / Google / GitHub) or present a code
/// 4. sign the relay's binding input with the enclave key — proof of possession
/// 5. send identity + public key + signature; receive a device id
///
/// **Every session afterwards**
/// 1. ask for a challenge for this device id
/// 2. sign it with the enclave key, behind Face ID / Touch ID
/// 3. exchange the signature for a 15-minute access token
///
/// The identity provider is not consulted again after step 5. That is
/// deliberate: it keeps a phone usable when Apple is having a bad morning, and
/// it means the long-lived credential is a key in hardware rather than a token
/// on disk.
///
/// The type is `@MainActor` because it is driven from the UI, but every
/// Keychain and Secure Enclave call is pushed off it. `SecKeyCreateSignature`
/// on a biometry-gated key blocks its thread for as long as the Face ID sheet
/// is up; on the main actor that is a frozen app for the entire prompt.
@MainActor
public final class RelayAuthenticator {

    private let client: RelayClient
    private let keys: DeviceKeyStore
    private let records: DeviceRecordStore
    private let deviceName: String

    public init(
        client: RelayClient,
        keys: DeviceKeyStore = DeviceKeyStore(),
        records: DeviceRecordStore = DeviceRecordStore(),
        deviceName: String
    ) {
        self.client = client
        self.keys = keys
        self.records = records
        self.deviceName = String(deviceName.prefix(64))
    }

    public var enrolledDevice: DeviceRecordStore.Record? {
        try? records.load()
    }

    // MARK: - Off-main key work

    /// Runs a blocking Keychain / Secure Enclave call away from the main actor.
    ///
    /// `DeviceKeyStore` is a `Sendable` value holding only a tag, so handing it
    /// to a detached task copies nothing that matters.
    private func withKeys<T: Sendable>(_ work: @Sendable @escaping (DeviceKeyStore) throws -> T) async throws -> T {
        let keys = self.keys
        return try await Task.detached(priority: .userInitiated) { try work(keys) }.value
    }

    private func publicKeyBase64() async throws -> String {
        try await withKeys { try $0.publicKeyBase64() }
    }

    private func sign(_ message: String, reason: String) async throws -> String {
        try await withKeys { try $0.signBase64(message: message, reason: reason) }
    }

    /// What this relay allows, so the UI can offer only what will work.
    public func availableMethods() async throws -> (providers: RelayProviders, methods: [SignInMethod]) {
        let providers = try await client.providers()
        var methods: [SignInMethod] = []
        if providers.providers.contains("apple") { methods.append(.apple) }
        if providers.providers.contains("google") { methods.append(.google) }
        if providers.providers.contains("github") { methods.append(.github) }
        if providers.enrollmentCodes { methods.append(.enrollmentCode) }
        return (providers, methods)
    }

    // MARK: - Binding

    /// Binds this device using an Apple or Google identity token.
    @discardableResult
    public func bind(provider: String, identityTokenProvider: (RelayLoginNonce) async throws -> String) async throws -> RelayBinding {
        let publicKey = try await publicKeyBase64()
        let nonce = try await client.loginNonce(publicKeyBase64: publicKey)
        let idToken = try await identityTokenProvider(nonce)

        // Proof of possession. The relay already bound the nonce to this key's
        // fingerprint; the signature proves we hold the private half, so a
        // captured identity token cannot register somebody else's key.
        let input = try await bindingInput(for: nonce.nonce, proposedBy: nonce.bindingInput)
        let signature = try await sign(input, reason: "Register this device for secman")

        let binding = try await client.bindWithIDToken(
            provider: provider,
            idToken: idToken,
            nonce: nonce.nonce,
            publicKeyBase64: publicKey,
            signatureBase64: signature,
            deviceName: deviceName
        )
        try persist(binding)
        return binding
    }

    /// Binds this device through the relay-hosted GitHub flow.
    @discardableResult
    public func bindWithGitHub(ticketProvider: (URL) async throws -> String) async throws -> RelayBinding {
        let publicKey = try await publicKeyBase64()
        let start = try await client.startGitHubSignIn(publicKeyBase64: publicKey, deviceName: deviceName)
        guard let url = URL(string: start.authorizationUrl), url.scheme?.lowercased() == "https" else {
            throw RelayError.signIn("The relay returned an unusable authorization URL.")
        }

        let ticket = try await ticketProvider(url)
        // The GitHub binding signs the ticket, not the state: the state travels
        // through the browser and must not double as the challenge. The relay
        // has nothing to propose here — at /start the ticket does not exist yet
        // — so this is derived with nothing to check it against.
        let input = try await bindingInput(for: ticket, proposedBy: nil)
        let signature = try await sign(input, reason: "Register this device for secman")

        let binding = try await client.completeGitHubSignIn(
            ticket: ticket,
            publicKeyBase64: publicKey,
            signatureBase64: signature,
            deviceName: deviceName
        )
        try persist(binding)
        return binding
    }

    /// Binds this device with an admin-issued enrollment code.
    @discardableResult
    public func bind(enrollmentCode: String) async throws -> RelayBinding {
        let publicKey = try await publicKeyBase64()
        let binding = try await client.enrol(
            code: enrollmentCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
            publicKeyBase64: publicKey,
            deviceName: deviceName
        )
        try persist(binding)
        return binding
    }

    /// The binding input to sign, derived locally and checked against the
    /// relay's own copy when it sent one.
    ///
    /// See `RelayProtocol` for why the server's value is a cross-check rather
    /// than the thing that gets signed.
    func bindingInput(for nonce: String, proposedBy proposed: String?) async throws -> String {
        let derived = RelayProtocol.bindingInput(
            nonce: nonce,
            keyFingerprint: try await withKeys { try $0.publicKeyFingerprint() }
        )
        guard RelayProtocol.agrees(derived: derived, proposed: proposed) else {
            throw RelayError.signIn("The relay asked this device to sign something unexpected.")
        }
        return derived
    }

    // MARK: - Sessions

    /// Ensures there is a usable access token, minting one if needed.
    ///
    /// Signing the challenge triggers the biometric prompt, so this is called
    /// lazily — on the first read after launch or after a token expires — not
    /// on every request.
    public func ensureSession() async throws {
        if await client.hasValidToken { return }
        guard let record = try records.load() else { throw RelayError.unauthenticated }

        let challenge = try await client.challenge(deviceId: record.deviceId)
        let derived = RelayProtocol.signingInput(deviceId: record.deviceId, nonce: challenge.nonce)
        guard RelayProtocol.agrees(derived: derived, proposed: challenge.signingInput) else {
            throw RelayError.signIn("The relay asked this device to sign something unexpected.")
        }
        let signature = try await sign(derived, reason: "Unlock secman status")
        try await client.exchange(
            deviceId: record.deviceId,
            nonce: challenge.nonce,
            signatureBase64: signature
        )
    }

    /// Forgets this device locally: the enclave key and the stored record.
    ///
    /// This does **not** revoke the device on the relay — only an admin can do
    /// that, from secman. Signing out on a lost phone is not a security
    /// control, and the UI says so rather than implying otherwise.
    public func signOutLocally() throws {
        try records.clear()
        try keys.delete()
    }

    private func persist(_ binding: RelayBinding) throws {
        try records.save(
            DeviceRecordStore.Record(
                deviceId: binding.deviceId,
                subject: binding.subject,
                boundVia: binding.boundVia,
                provider: binding.provider
            )
        )
    }
}
