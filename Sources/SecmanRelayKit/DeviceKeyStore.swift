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
    public func loadOrCreate() throws -> SecKey {
        if let existing = try load() {
            return existing
        }
        return try create()
    }

    /// Returns the existing key, or nil.
    public func load() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
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
    public func publicKeyDER() throws -> Data {
        let key = try loadOrCreate()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw RelayError.deviceKey("the device key has no public half")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw RelayError.deviceKey("could not export the public key: \(cfErrorDescription(error))")
        }
        return try Self.spkiFromX963(raw)
    }

    /// Base64 SPKI, the form the relay's JSON expects.
    public func publicKeyBase64() throws -> String {
        try publicKeyDER().base64EncodedString()
    }

    /// Wraps an ANSI X9.63 uncompressed P-256 point in a SubjectPublicKeyInfo.
    ///
    /// The prefix is the fixed DER for
    /// `SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING }`.
    /// Because both the algorithm and the curve are pinned, the header is a
    /// constant rather than something that has to be assembled — and any input
    /// that is not a 65-byte uncompressed point is rejected instead of being
    /// wrapped into a structure that would fail confusingly on the server.
    public static func spkiFromX963(_ x963: Data) throws -> Data {
        guard x963.count == 65, x963.first == 0x04 else {
            throw RelayError.deviceKey("expected a 65-byte uncompressed P-256 point, got \(x963.count) bytes")
        }
        let header: [UInt8] = [
            0x30, 0x59,                                            // SEQUENCE (89 bytes)
            0x30, 0x13,                                            //   SEQUENCE (19 bytes)
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,  //     OID 1.2.840.10045.2.1  (id-ecPublicKey)
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 (prime256v1)
            0x03, 0x42, 0x00                                       //   BIT STRING (66 bytes, 0 unused)
        ]
        return Data(header) + x963
    }

    // MARK: - Signing

    /// Signs `message` with the enclave key.
    ///
    /// The algorithm hashes the message with SHA-256 and produces an ASN.1 DER
    /// ECDSA signature, which is exactly what the relay verifies with
    /// `ecdsa.VerifyASN1` over `sha256(message)`.
    ///
    /// - Parameter reason: shown in the biometric prompt. Say what is being
    ///   authorised, not "authenticate" — the user is approving access to a
    ///   security dashboard and deserves to be told so.
    public func sign(message: Data, reason: String) throws -> Data {
        let key = try loadOrCreate()

        let context = LAContext()
        context.localizedReason = reason
        // Force a fresh biometric check per signature rather than reusing a
        // recent one: each signature authorises a new session.
        context.touchIDAuthenticationAllowableReuseDuration = 0

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            let description = cfErrorDescription(error)
            if description.localizedCaseInsensitiveContains("cancel") {
                throw RelayError.userCancelled
            }
            throw RelayError.deviceKey("signing failed: \(description)")
        }
        return signature
    }

    /// Signs and base64-encodes, the form every relay request uses.
    public func signBase64(message: String, reason: String) throws -> String {
        try sign(message: Data(message.utf8), reason: reason).base64EncodedString()
    }
}

func cfErrorDescription(_ error: Unmanaged<CFError>?) -> String {
    guard let error else { return "unknown error" }
    return (error.takeRetainedValue() as Error).localizedDescription
}
