import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The device's identity: a P-256 key pair generated inside the Secure Enclave.
///
/// This is the credential that matters. The relay's access tokens live fifteen
/// minutes; this key lives for the life of the enrollment and never leaves the
/// enclave, so:
///
///  - a backup, a filesystem dump or a jailbroken copy of the app's container
///    yields nothing that can authenticate;
///  - every session begins with a fresh server challenge signed by the key, so
///    a captured token is worth at most its remaining minutes;
///  - the key is gated by biometry, so a phone unlocked by someone else still
///    cannot talk to the relay.
///
/// `SecKeyCopyExternalRepresentation` hands back an ANSI X9.63 point, not the
/// SPKI structure the relay expects, so `publicKeyDER()` wraps it. That
/// conversion is the single most commonly botched step in this flow, which is
/// why it is isolated and unit-tested.
public struct DeviceKeyStore: Sendable {

    /// Keychain tag for the enclave key. Changing it orphans the old key and
    /// forces a re-enrollment, which is the intended effect of a key reset.
    public static let defaultTag = "io.secman.relay.device-key"

    private let tag: Data
    private let requiresBiometry: Bool

    /// - Parameters:
    ///   - tag: keychain application tag.
    ///   - requiresBiometry: when true the private key can only be used after a
    ///     successful biometric check, and any change to the enrolled
    ///     biometrics invalidates it (`.biometryCurrentSet`). That last part is
    ///     deliberate: adding a face or fingerprint to a stolen device must not
    ///     silently inherit access to a security dashboard.
    public init(tag: String = DeviceKeyStore.defaultTag, requiresBiometry: Bool = true) {
        self.tag = Data(tag.utf8)
        self.requiresBiometry = requiresBiometry
    }

    // MARK: - Lifecycle

    /// Returns the existing key, creating one if this device has none.
    ///
    /// Only enrollment may create a key. Everything else uses `load()` and
    /// fails loudly when the key is gone — see `sign(message:reason:)`.
    public func loadOrCreate() throws -> SecKey {
        if let existing = try load() {
            return existing
        }
        return try create()
    }

    /// Returns the existing key, or nil.
    ///
    /// - Parameter context: when supplied, the keychain evaluates the key's
    ///   access control against *this* context, which is the only way the
    ///   biometric prompt shows our own wording rather than the system default.
    ///   Passing it here rather than at signing time is not a style choice:
    ///   `SecKeyCreateSignature` has no parameter for it, so a context that is
    ///   not attached to the `SecKey` reference is simply ignored.
    public func load(context: LAContext? = nil) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let key = item else { return nil }
            // The force cast is safe: kSecClassKey with kSecReturnRef yields a
            // SecKey or nothing at all.
            return (key as! SecKey)
        case errSecItemNotFound:
            return nil
        case errSecUserCanceled, errSecAuthFailed:
            throw RelayError.userCancelled
        default:
            throw RelayError.keychain(status: status, operation: "loading the device key")
        }
    }

    /// Generates a new enclave key, replacing any existing one.
    @discardableResult
    public func create() throws -> SecKey {
        try delete()

        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requiresBiometry {
            flags.insert(.biometryCurrentSet)
        }

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            // ThisDeviceOnly: the key must never travel in an iCloud Keychain
            // or a device-to-device transfer. An enclave key cannot anyway, but
            // stating it keeps the intent explicit if the enclave requirement
            // is ever relaxed for the simulator.
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            throw RelayError.deviceKey("could not build the key access policy: \(cfErrorDescription(accessError))")
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]
        if Self.secureEnclaveAvailable {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        var createError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &createError) else {
            throw RelayError.deviceKey("could not create the device key: \(cfErrorDescription(createError))")
        }
        return key
    }

    /// Removes the key. The device must re-enrol afterwards.
    public func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw RelayError.keychain(status: status, operation: "deleting the device key")
        }
    }

    /// Whether this build can use the Secure Enclave.
    ///
    /// The simulator has none. Falling back to a software key there keeps the
    /// flow testable; a release build should never take that path, which is why
    /// `#if targetEnvironment(simulator)` gates it rather than a runtime probe.
    public static var secureEnclaveAvailable: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }

    // MARK: - Public key

    /// The public key in the SPKI DER encoding the relay parses.
    ///
    /// Creates the key if this device has none, because the first caller is
    /// always enrollment.
    public func publicKeyDER() throws -> Data {
        try Self.publicKeyDER(of: try loadOrCreate())
    }

    /// Base64 SPKI, the form the relay's JSON expects.
    public func publicKeyBase64() throws -> String {
        try publicKeyDER().base64EncodedString()
    }

    /// Lowercase hex SHA-256 of the SPKI DER.
    ///
    /// Mirrors `idp.Fingerprint` in the relay. It appears inside the binding
    /// input the device signs, so the two implementations have to agree byte
    /// for byte — see `RelayProtocol.bindingInput`.
    public func publicKeyFingerprint() throws -> String {
        SPKI.sha256Hex(try publicKeyDER())
    }

    private static func publicKeyDER(of key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw RelayError.deviceKey("the device key has no public half")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw RelayError.deviceKey("could not export the public key: \(cfErrorDescription(error))")
        }
        return try spkiFromX963(raw)
    }

    /// Wraps an ANSI X9.63 uncompressed P-256 point in a SubjectPublicKeyInfo.
    ///
    /// Any input that is not a 65-byte uncompressed point is rejected rather
    /// than wrapped into a structure that would fail confusingly on the server:
    /// a compressed point produces a structurally valid but wrong SPKI.
    public static func spkiFromX963(_ x963: Data) throws -> Data {
        guard x963.count == 65, x963.first == 0x04 else {
            throw RelayError.deviceKey("expected a 65-byte uncompressed P-256 point, got \(x963.count) bytes")
        }
        return try SPKI.ecSPKI(point: x963, bits: 256)
    }

    // MARK: - Signing

    /// Signs `message` with the enclave key, behind a biometric prompt.
    ///
    /// The algorithm hashes the message with SHA-256 and produces an ASN.1 DER
    /// ECDSA signature, which is exactly what the relay verifies with
    /// `ecdsa.VerifyASN1` over `sha256(message)`.
    ///
    /// A missing key is an error rather than a reason to make one. Signing with
    /// a freshly minted key would produce a signature no relay has ever seen,
    /// and the user would get an unexplained 403 instead of "this device is no
    /// longer registered".
    ///
    /// - Parameter reason: shown in the biometric prompt. Say what is being
    ///   authorised, not "authenticate" — the user is approving access to a
    ///   security dashboard and deserves to be told so.
    public func sign(message: Data, reason: String) throws -> Data {
        let context = LAContext()
        context.localizedReason = reason
        // Force a fresh biometric check per signature rather than reusing a
        // recent one: each signature authorises a new session.
        context.touchIDAuthenticationAllowableReuseDuration = 0

        guard let key = try load(context: context) else {
            throw RelayError.deviceKey("this device's registration key is gone; register the device again")
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            guard let failure = error?.takeRetainedValue() else {
                throw RelayError.deviceKey("signing failed: unknown error")
            }
            if Self.isCancellation(failure) {
                throw RelayError.userCancelled
            }
            throw RelayError.deviceKey("signing failed: \((failure as Error).localizedDescription)")
        }
        return signature
    }

    /// Signs and base64-encodes, the form every relay request uses.
    public func signBase64(message: String, reason: String) throws -> String {
        try sign(message: Data(message.utf8), reason: reason).base64EncodedString()
    }

    /// Whether a signing failure was the user dismissing the prompt.
    ///
    /// Matched on the error domain and code rather than on the localized
    /// description, which is translated: a German device reports "Abbrechen",
    /// and a substring search for "cancel" would turn every cancellation into
    /// an alarming "signing failed" alert.
    private static func isCancellation(_ error: CFError) -> Bool {
        let nsError = error as Error as NSError
        if nsError.domain == LAError.errorDomain {
            return nsError.code == LAError.userCancel.rawValue
                || nsError.code == LAError.appCancel.rawValue
                || nsError.code == LAError.systemCancel.rawValue
        }
        return nsError.code == Int(errSecUserCanceled)
    }
}

func cfErrorDescription(_ error: Unmanaged<CFError>?) -> String {
    guard let error else { return "unknown error" }
    return (error.takeRetainedValue() as Error).localizedDescription
}
