import CryptoKit
import Foundation
import Security

/// Builds a SubjectPublicKeyInfo (SPKI) DER blob from a `SecKey`, and the two
/// digests derived from one.
///
/// This exists because both certificate pinning and device registration are
/// only useful if both sides compute the same bytes, and the obvious call does
/// not give you them. `SecKeyCopyExternalRepresentation` returns the *bare* key
/// material — an ANSI X9.63 point for EC, a PKCS#1 `RSAPublicKey` for RSA —
/// while the relay parses SPKI (`x509.ParsePKIXPublicKey`) and every `openssl`
/// pinning recipe an operator will find hashes the SPKI wrapper:
///
/// ```
/// openssl s_client -connect relay.example.com:443 </dev/null 2>/dev/null \
///   | openssl x509 -pubkey -noout \
///   | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | base64
/// ```
///
/// Hashing the bare representation instead would produce a pin that no tool
/// reproduces, which is exactly how pinning ends up either disabled or wrong.
enum SPKI {

    /// The SPKI DER for a public key.
    static func der(from key: SecKey) throws -> Data {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            throw RelayError.deviceKey("could not read key attributes")
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw RelayError.deviceKey("could not export the key: \(cfErrorDescription(error))")
        }

        let type = attributes[kSecAttrKeyType] as? String
        let bits = (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0

        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            return try ecSPKI(point: raw, bits: bits)
        }
        if type == (kSecAttrKeyTypeRSA as String) {
            return rsaSPKI(pkcs1: raw)
        }
        throw RelayError.deviceKey("unsupported key type for pinning")
    }

    /// SHA-256 of the SPKI, base64 — the pin format `RelayClient` compares.
    static func pin(from key: SecKey) throws -> String {
        Data(SHA256.hash(data: try der(from: key))).base64EncodedString()
    }

    /// Lowercase hex SHA-256, the encoding the relay's `idp.Fingerprint` and its
    /// enrollment-code digest both use.
    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - EC

    private static let ecPublicKeyOID: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    private static let prime256v1OID: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    private static let secp384r1OID: [UInt8] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
    private static let secp521r1OID: [UInt8] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]

    static func ecSPKI(point: Data, bits: Int) throws -> Data {
        let curveOID: [UInt8]
        switch bits {
        case 256: curveOID = prime256v1OID
        case 384: curveOID = secp384r1OID
        case 521: curveOID = secp521r1OID
        default: throw RelayError.deviceKey("unsupported EC curve size \(bits)")
        }
        let algorithm = sequence(ecPublicKeyOID + curveOID)
        let subjectPublicKey = bitString(Array(point))
        return Data(sequence(algorithm + subjectPublicKey))
    }

    // MARK: - RSA

    private static let rsaEncryptionOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]

    static func rsaSPKI(pkcs1: Data) -> Data {
        // AlgorithmIdentifier for rsaEncryption carries an explicit NULL.
        let algorithm = sequence(rsaEncryptionOID + [0x05, 0x00])
        let subjectPublicKey = bitString(Array(pkcs1))
        return Data(sequence(algorithm + subjectPublicKey))
    }

    // MARK: - Minimal DER

    static func sequence(_ contents: [UInt8]) -> [UInt8] {
        [0x30] + length(contents.count) + contents
    }

    /// A BIT STRING with zero unused bits, which is what a key blob always is.
    static func bitString(_ contents: [UInt8]) -> [UInt8] {
        let payload: [UInt8] = [0x00] + contents
        return [0x03] + length(payload.count) + payload
    }

    /// DER definite-length encoding.
    static func length(_ value: Int) -> [UInt8] {
        if value < 0x80 {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }
}
