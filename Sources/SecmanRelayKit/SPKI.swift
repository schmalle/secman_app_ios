import Foundation
import Security

/// Builds a SubjectPublicKeyInfo (SPKI) DER blob from a `SecKey`.
///
/// This exists because certificate pinning is only useful if both sides compute
/// the same number, and the obvious call does not give you one.
/// `SecKeyCopyExternalRepresentation` returns the *bare* key material — an ANSI
/// X9.63 point for EC, a PKCS#1 `RSAPublicKey` for RSA — while the industry
/// convention, and every `openssl` recipe an operator will find, hashes the
/// SPKI wrapper around it:
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
        let spki = try der(from: key)
        return Data(SHA256Digest.hash(spki)).base64EncodedString()
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
        default: throw RelayError.deviceKey("unsupported EC curve size \(bits) for pinning")
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

/// A thin shim so `SPKI` does not import CryptoKit just for one hash, keeping
/// this file usable in a plain-Foundation test target.
enum SHA256Digest {
    static func hash(_ data: Data) -> [UInt8] {
        var context = SHA256Context()
        context.update(data)
        return context.finalize()
    }
}

/// FIPS 180-4 SHA-256.
///
/// Hand-written rather than CryptoKit only so the DER/pin logic above can be
/// exercised on a platform without Apple's frameworks. Application code must
/// use CryptoKit; this is not a general-purpose implementation.
struct SHA256Context {
    private var state: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    private var buffer: [UInt8] = []
    private var totalBytes: UInt64 = 0

    private static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    mutating func update(_ data: Data) {
        totalBytes += UInt64(data.count)
        buffer.append(contentsOf: data)
        while buffer.count >= 64 {
            compress(Array(buffer.prefix(64)))
            buffer.removeFirst(64)
        }
    }

    mutating func finalize() -> [UInt8] {
        let bitLength = totalBytes &* 8
        buffer.append(0x80)
        while buffer.count % 64 != 56 {
            buffer.append(0x00)
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            buffer.append(UInt8((bitLength >> UInt64(shift)) & 0xFF))
        }
        while buffer.count >= 64 {
            compress(Array(buffer.prefix(64)))
            buffer.removeFirst(64)
        }

        var out: [UInt8] = []
        for word in state {
            out.append(UInt8((word >> 24) & 0xFF))
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
            out.append(UInt8(word & 0xFF))
        }
        return out
    }

    private mutating func compress(_ block: [UInt8]) {
        var w = [UInt32](repeating: 0, count: 64)
        for i in 0..<16 {
            w[i] = (UInt32(block[i * 4]) << 24) | (UInt32(block[i * 4 + 1]) << 16)
                | (UInt32(block[i * 4 + 2]) << 8) | UInt32(block[i * 4 + 3])
        }
        for i in 16..<64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
        }

        var (a, b, c, d) = (state[0], state[1], state[2], state[3])
        var (e, f, g, h) = (state[4], state[5], state[6], state[7])

        for i in 0..<64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            let ch = (e & f) ^ (~e & g)
            let temp1 = h &+ s1 &+ ch &+ Self.k[i] &+ w[i]
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj

            h = g; g = f; f = e
            e = d &+ temp1
            d = c; c = b; b = a
            a = temp1 &+ temp2
        }

        state[0] = state[0] &+ a; state[1] = state[1] &+ b
        state[2] = state[2] &+ c; state[3] = state[3] &+ d
        state[4] = state[4] &+ e; state[5] = state[5] &+ f
        state[6] = state[6] &+ g; state[7] = state[7] &+ h
    }

    private func rotr(_ value: UInt32, _ amount: UInt32) -> UInt32 {
        (value >> amount) | (value << (32 - amount))
    }
}
