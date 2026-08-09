import Foundation
import Testing
@testable import SecmanRelayKit

// The security-relevant logic that can be checked without a device: the DER
// encoding that pinning and device registration both depend on, the hash the
// Apple nonce convention depends on, and the decoding of everything the relay
// sends. Flows that need the Secure Enclave, a biometric prompt or a browser
// are covered by the manual matrix in docs/SECURITY.md instead.

// MARK: - SPKI / DER

@Suite("SPKI encoding")
struct SPKITests {

    /// The relay parses the device key with `x509.ParsePKIXPublicKey` and
    /// rejects anything that is not P-256 SPKI, so this wrapper has to be
    /// byte-exact.
    @Test("P-256 SPKI has the expected fixed header and length")
    func p256Header() throws {
        var point = Data([0x04])
        point.append(Data(repeating: 0xAB, count: 64))

        let spki = try DeviceKeyStore.spkiFromX963(point)

        #expect(spki.count == 91)
        let expectedHeader: [UInt8] = [
            0x30, 0x59, 0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00
        ]
        #expect(Array(spki.prefix(26)) == expectedHeader)
        #expect(Array(spki.suffix(65)) == Array(point))
    }

    @Test("a non-P-256 point is refused rather than wrapped")
    func rejectsWrongLength() {
        #expect(throws: RelayError.self) {
            _ = try DeviceKeyStore.spkiFromX963(Data([0x04] + Array(repeating: 0xAB, count: 10)))
        }
        // A compressed point would produce a structurally valid but wrong SPKI.
        #expect(throws: RelayError.self) {
            _ = try DeviceKeyStore.spkiFromX963(Data([0x02] + Array(repeating: 0xAB, count: 64)))
        }
    }

    @Test("DER length encoding follows the definite-length rules")
    func derLength() {
        #expect(SPKI.length(0) == [0x00])
        #expect(SPKI.length(127) == [0x7F])
        // 128 no longer fits in the short form.
        #expect(SPKI.length(128) == [0x81, 0x80])
        #expect(SPKI.length(255) == [0x81, 0xFF])
        #expect(SPKI.length(256) == [0x82, 0x01, 0x00])
        #expect(SPKI.length(65_535) == [0x82, 0xFF, 0xFF])
    }

    @Test("a BIT STRING carries the zero-unused-bits prefix")
    func bitString() {
        #expect(SPKI.bitString([0xAA, 0xBB]) == [0x03, 0x03, 0x00, 0xAA, 0xBB])
    }

    /// An RSA relay certificate must pin to the same value `openssl pkey
    /// -pubin -outform der` produces, which means the AlgorithmIdentifier needs
    /// its explicit NULL.
    @Test("RSA SPKI includes the NULL parameters")
    func rsaAlgorithmIdentifier() {
        let spki = SPKI.rsaSPKI(pkcs1: Data([0x30, 0x03, 0x02, 0x01, 0x01]))
        let bytes = Array(spki)
        #expect(bytes[0] == 0x30)
        // OID rsaEncryption followed by NULL.
        let oidAndNull: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
        #expect(bytes.contains(oidAndNull))
    }
}

// MARK: - SHA-256

@Suite("SHA-256")
struct SHA256Tests {

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// FIPS 180-4 published vectors. The nonce convention and the pin format
    /// both depend on this producing the standard digest.
    @Test("matches the published vectors")
    func knownAnswers() {
        #expect(hex(SHA256Digest.hash(Data())) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        #expect(hex(SHA256Digest.hash(Data("abc".utf8))) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(hex(SHA256Digest.hash(Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8))) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    /// Multi-block input exercises the padding path that a single short string
    /// never reaches.
    @Test("handles input spanning several blocks")
    func multiBlock() {
        let million = Data(repeating: UInt8(ascii: "a"), count: 1_000_000)
        #expect(hex(SHA256Digest.hash(million)) ==
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }
}

// MARK: - Decoding

@Suite("Relay response decoding")
struct DecodingTests {

    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try RelayJSON.decoder.decode(T.self, from: Data(json.utf8))
    }

    @Test("a snapshot keeps its sections as opaque JSON")
    func snapshotSections() throws {
        let snapshot = try decode(RelaySnapshot.self, """
        {
          "instanceId": "secman-prod",
          "schemaVersion": 2,
          "generatedAt": "2026-08-09T12:00:00Z",
          "ageSeconds": 12,
          "stale": false,
          "roles": ["ADMIN"],
          "sections": {
            "totals": {"assets": 3, "vulnerabilities": 4, "users": 5},
            "unknown-future-section": {"whatever": [1, 2, 3]}
          }
        }
        """)

        #expect(snapshot.instanceId == "secman-prod")
        #expect(snapshot.roles == ["ADMIN"])
        #expect(snapshot.stale == false)

        let totals = try snapshot.decode(RelayTotalsSection.self, section: "totals")
        #expect(totals?.assets == 3)
        #expect(totals?.users == 5)

        // A section this build has never heard of must not break the decode of
        // the ones it has.
        #expect(snapshot.sections["unknown-future-section"] != nil)
        #expect(try snapshot.decode(RelayTotalsSection.self, section: "absent") == nil)
    }

    /// The relay mixes fractional and whole-second timestamps depending on the
    /// field, so both must parse.
    @Test("both RFC 3339 forms parse")
    func timestamps() throws {
        let withFraction = try decode(RelaySnapshot.self, """
        {"instanceId":"a","schemaVersion":2,"generatedAt":"2026-08-09T12:00:00.123456Z",
         "ageSeconds":0,"stale":false,"sections":{}}
        """)
        let withoutFraction = try decode(RelaySnapshot.self, """
        {"instanceId":"a","schemaVersion":2,"generatedAt":"2026-08-09T12:00:00Z",
         "ageSeconds":0,"stale":false,"sections":{}}
        """)
        #expect(abs(withFraction.generatedAt.timeIntervalSince(withoutFraction.generatedAt)) < 1)
    }

    @Test("the provider policy decodes and answers the strength question")
    func providers() throws {
        let providers = try decode(RelayProviders.self, """
        {"providers":["apple","google"],"enrollmentCodes":true,
         "privilegedRoles":["ADMIN"],"strongProviders":["apple","google"]}
        """)

        #expect(providers.isStrong("apple"))
        #expect(providers.isStrong("google"))
        // The whole point of the rule: GitHub is not strong enough for an admin.
        #expect(!providers.isStrong("github"))
    }

    @Test("a session carries the roles and the readable sections")
    func session() throws {
        let session = try decode(RelaySession.self, """
        {"deviceId":"dev_1","subject":"markus","displayName":"markus",
         "roles":["ADMIN","VULN"],"scopes":["status:*"],"boundVia":"identity",
         "provider":"apple","sections":["kpis","imports"]}
        """)
        #expect(session.roles == ["ADMIN", "VULN"])
        #expect(session.sections == ["kpis", "imports"])
        #expect(session.provider == "apple")
    }

    @Test("a binding response decodes")
    func binding() throws {
        let binding = try decode(RelayBinding.self, """
        {"deviceId":"dev_abc","subject":"markus","displayName":"markus",
         "roles":["ADMIN"],"scopes":["status:*"],"boundVia":"identity","provider":"apple"}
        """)
        #expect(binding.deviceId == "dev_abc")
        #expect(binding.boundVia == "identity")
    }

    @Test("KPI payloads keep unavailable distinct from zero")
    func kpisAvailability() throws {
        let kpis = try decode(RelayKpisSection.self, """
        {"awsCleanServers":{"available":false},
         "edrCoverage":{"available":true,"percentage":97.5,"totalInstances":100,
                        "eligibleInstances":98,"coveredInstances":95,
                        "excludedByException":2,"agentSeenWithinDays":7}}
        """)
        // "not measured yet" and "0%" mean opposite things on a security
        // dashboard, so the optionality has to survive decoding.
        #expect(kpis.awsCleanServers.available == false)
        #expect(kpis.awsCleanServers.percentage == nil)
        #expect(kpis.edrCoverage.percentage == 97.5)
    }
}

// MARK: - Configuration

@Suite("Client configuration")
struct ConfigurationTests {

    @Test("a plaintext relay URL is refused at configuration time")
    func rejectsPlaintext() {
        #expect(throws: RelayError.self) {
            _ = try RelayClient.Configuration(baseURL: URL(string: "http://relay.example.com")!)
        }
    }

    @Test("an https URL is accepted")
    func acceptsHTTPS() throws {
        let configuration = try RelayClient.Configuration(baseURL: URL(string: "https://relay.example.com")!)
        #expect(configuration.publicKeyPins.isEmpty)
    }
}

// MARK: - Section metadata

@Suite("Sections")
struct SectionTests {

    /// The relay validates section names against `[a-z0-9-]`; a name added here
    /// that it would reject produces a tab that can never load.
    @Test("every section name is one the relay accepts")
    func sectionNamesAreValid() {
        for section in RelaySection.allCases {
            let name = section.rawValue
            #expect(!name.isEmpty)
            #expect(!name.hasPrefix("-") && !name.hasSuffix("-"))
            #expect(name.allSatisfy { $0.isLowercase && $0.isLetter || $0.isNumber || $0 == "-" })
        }
    }

    @Test("the explanatory role table matches secman's controllers")
    func roleTable() {
        #expect(RelaySection.kpis.explanatoryRoles == ["ADMIN", "SECCHAMPION"])
        #expect(RelaySection.exceptions.explanatoryRoles == ["ADMIN", "SECCHAMPION"])
        #expect(RelaySection.imports.explanatoryRoles == ["ADMIN", "VULN"])
        #expect(RelaySection.totals.explanatoryRoles == ["ADMIN"])
    }
}
