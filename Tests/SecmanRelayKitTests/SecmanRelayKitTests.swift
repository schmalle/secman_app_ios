import CryptoKit
import Foundation
import Testing
@testable import SecmanRelayKit

// The security-relevant logic that can be checked without a device: the DER
// encoding that pinning and device registration both depend on, the byte
// strings the Secure Enclave signs, and the decoding of everything the relay
// sends. Flows that need the enclave, a biometric prompt or a browser are
// covered by the manual matrix in docs/SECURITY.md instead.
//
// Several tests pin literal values taken from the relay's own source. That is
// the point of them: this app and `src/relay` in the secman repository are two
// implementations of one contract, and the failure mode of a silent divergence
// is an unexplained 403 on somebody's phone.

// MARK: - SPKI / DER

@Suite("SPKI encoding")
struct SPKITests {

    /// A P-256 point whose SPKI wrapping and digest are both known, so the
    /// wrapper can be checked byte for byte rather than merely for plausibility.
    static let point = Data([0x04] + Array(repeating: UInt8(0xAB), count: 64))

    /// The relay parses the device key with `x509.ParsePKIXPublicKey` and
    /// rejects anything that is not P-256 SPKI, so this wrapper has to be
    /// byte-exact.
    @Test("P-256 SPKI has the expected fixed header and length")
    func p256Header() throws {
        let spki = try DeviceKeyStore.spkiFromX963(Self.point)

        #expect(spki.count == 91)
        let expectedHeader: [UInt8] = [
            0x30, 0x59, 0x30, 0x13,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00
        ]
        #expect(Array(spki.prefix(26)) == expectedHeader)
        #expect(Array(spki.suffix(65)) == Array(Self.point))
    }

    @Test("a non-P-256 point is refused rather than wrapped")
    func rejectsWrongLength() {
        #expect(throws: RelayError.self) {
            _ = try DeviceKeyStore.spkiFromX963(Data([0x04] + Array(repeating: UInt8(0xAB), count: 10)))
        }
        // A compressed point would produce a structurally valid but wrong SPKI.
        #expect(throws: RelayError.self) {
            _ = try DeviceKeyStore.spkiFromX963(Data([0x02] + Array(repeating: UInt8(0xAB), count: 64)))
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

    /// `idp.Fingerprint` is `hex(sha256(spkiDER))`, lowercase. The relay puts
    /// this string inside the binding input, so a mismatch here is a signature
    /// the relay rejects with no explanation the user can act on.
    @Test("the key fingerprint is lowercase hex SHA-256 of the SPKI")
    func fingerprintFormat() throws {
        let spki = try DeviceKeyStore.spkiFromX963(Self.point)
        let fingerprint = SPKI.sha256Hex(spki)

        #expect(fingerprint == "a8ddd2ffad4930ac6b77647b8de0d37935aaeb9fb957326da6370df67205dc77")
        #expect(fingerprint.count == 64)
        #expect(fingerprint.allSatisfy(\.isHexDigit))
        #expect(fingerprint == fingerprint.lowercased())
        // And it is the digest CryptoKit computes, not a bespoke one.
        #expect(Data(SHA256.hash(data: spki)) == Data(hexString: fingerprint))
    }
}

// MARK: - What the enclave signs

@Suite("Signing inputs")
struct RelayProtocolTests {

    /// Pinned against `auth.DeviceSigningInput` / `auth.DeviceBindingInput`.
    /// The two context prefixes are the domain separation between them; if
    /// either changes on one side only, every device stops authenticating.
    @Test("the signing inputs match the relay's construction")
    func construction() {
        #expect(RelayProtocol.signingInput(deviceId: "dev_1", nonce: "abc")
            == "secman-relay-device-auth-v1|dev_1|abc")
        #expect(RelayProtocol.bindingInput(nonce: "n1", keyFingerprint: "ff00")
            == "secman-relay-device-bind-v1|n1|ff00")
    }

    /// A binding signature must never be replayable as a session
    /// authentication, which is the whole reason there are two prefixes.
    @Test("the two purposes never produce the same bytes")
    func domainsAreSeparate() {
        #expect(RelayProtocol.signingInput(deviceId: "x", nonce: "y")
            != RelayProtocol.bindingInput(nonce: "x", keyFingerprint: "y"))
    }

    @Test("a server-proposed input that disagrees with ours is refused")
    func disagreementIsRefused() {
        let derived = RelayProtocol.signingInput(deviceId: "dev_1", nonce: "abc")

        #expect(RelayProtocol.agrees(derived: derived, proposed: derived))
        // Absent is fine — the relay is not obliged to echo it back.
        #expect(RelayProtocol.agrees(derived: derived, proposed: nil))
        #expect(RelayProtocol.agrees(derived: derived, proposed: ""))
        // Anything else is a relay asking this device to sign something else.
        #expect(!RelayProtocol.agrees(derived: derived, proposed: "sign-this-instead"))
        #expect(!RelayProtocol.agrees(
            derived: derived,
            proposed: RelayProtocol.signingInput(deviceId: "dev_1", nonce: "different")))
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
        // the ones it has, and must still be renderable.
        #expect(snapshot.sections["unknown-future-section"] != nil)
        #expect(snapshot.value(section: "unknown-future-section") != nil)
        #expect(try snapshot.decode(RelayTotalsSection.self, section: "absent") == nil)
    }

    /// Counts must survive the round trip through the opaque-section
    /// representation as integers. Routed through `Double` they come back as
    /// "3.0" on screen, and stop being exact past 2^53.
    @Test("integers in an opaque section stay integers")
    func integersSurviveRoundTrip() throws {
        let snapshot = try decode(RelaySnapshot.self, """
        {"instanceId":"a","schemaVersion":2,"generatedAt":"2026-08-09T12:00:00Z",
         "ageSeconds":0,"stale":false,
         "sections":{"totals":{"assets":9007199254740993,"vulnerabilities":4,"users":5}}}
        """)

        let totals = try snapshot.decode(RelayTotalsSection.self, section: "totals")
        #expect(totals?.assets == 9_007_199_254_740_993)

        guard case .object(let members)? = snapshot.value(section: "totals") else {
            Issue.record("expected an object")
            return
        }
        #expect(members["vulnerabilities"] == .int(4))
        #expect(members["vulnerabilities"]?.displayText == "4")
    }

    /// Go marshals `time.Time` as RFC 3339 Nano with trailing zeros trimmed, so
    /// the same field arrives with anywhere between zero and nine fractional
    /// digits depending on the instant.
    @Test(arguments: [
        "2026-08-09T12:00:00Z",
        "2026-08-09T12:00:00.1Z",
        "2026-08-09T12:00:00.123Z",
        "2026-08-09T12:00:00.123456Z",
        "2026-08-09T12:00:00.123456789Z"
    ])
    func timestampPrecision(_ text: String) throws {
        let snapshot = try decode(RelaySnapshot.self, """
        {"instanceId":"a","schemaVersion":2,"generatedAt":"\(text)",
         "ageSeconds":0,"stale":false,"sections":{}}
        """)
        let noon = try decode(RelaySnapshot.self, """
        {"instanceId":"a","schemaVersion":2,"generatedAt":"2026-08-09T12:00:00Z",
         "ageSeconds":0,"stale":false,"sections":{}}
        """)
        #expect(abs(snapshot.generatedAt.timeIntervalSince(noon.generatedAt)) < 1)
    }

    @Test("fractional seconds are normalised to three digits")
    func fractionNormalisation() {
        #expect(RelayJSON.normalizingFraction("2026-08-09T12:00:00.123456789Z")
            == "2026-08-09T12:00:00.123Z")
        #expect(RelayJSON.normalizingFraction("2026-08-09T12:00:00.1Z")
            == "2026-08-09T12:00:00.100Z")
        // Nothing to normalise.
        #expect(RelayJSON.normalizingFraction("2026-08-09T12:00:00Z") == nil)
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

    @Test("meta carries freshness without the payload")
    func meta() throws {
        let meta = try decode(RelayMeta.self, """
        {"instanceId":"secman-prod","schemaVersion":2,
         "generatedAt":"2026-08-09T12:00:00Z","receivedAt":"2026-08-09T12:00:01Z",
         "ageSeconds":1800,"stale":true,"maxAgeSeconds":900,
         "sections":["kpis"],"deviceId":"dev_1","subject":"markus",
         "roles":["SECCHAMPION"],"scopes":["status:*"]}
        """)
        #expect(meta.stale)
        #expect(meta.ageSeconds == 1800)
        #expect(meta.maxAgeSeconds == 900)
        #expect(meta.sections == ["kpis"])
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

    /// The relay's `/auth/nonce` echoes the binding input back; a build talking
    /// to a relay that does not must still work, which is why it is optional.
    @Test("a login nonce decodes with and without the advisory fields")
    func loginNonce() throws {
        let full = try decode(RelayLoginNonce.self, """
        {"nonce":"abc","nonceHash":"def","expiresAt":"2026-08-09T12:02:00Z",
         "bindingInput":"secman-relay-device-bind-v1|abc|ff","algorithm":"ECDSA-P256-SHA256-ASN1"}
        """)
        #expect(full.bindingInput == "secman-relay-device-bind-v1|abc|ff")

        let minimal = try decode(RelayLoginNonce.self, """
        {"nonce":"abc","nonceHash":"def","expiresAt":"2026-08-09T12:02:00Z"}
        """)
        #expect(minimal.bindingInput == nil)
        #expect(minimal.nonce == "abc")
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

// MARK: - Sections

@Suite("Sections")
struct SectionTests {

    /// The relay validates section names against `[a-z0-9-]`; a name added here
    /// that it would reject produces an entry that can never load.
    @Test("every built-in section name is one the relay accepts")
    func sectionNamesAreValid() {
        for section in RelaySection.allCases {
            let name = section.rawValue
            #expect(!name.isEmpty && name.count <= 64)
            #expect(!name.hasPrefix("-") && !name.hasSuffix("-"))
            #expect(name.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") })
        }
    }

    /// A section the relay grows tomorrow has to survive the trip through the
    /// app without being filtered out — that is the difference between a
    /// refresh and an App Store release.
    @Test("an unknown section is still listed and named")
    func unknownSectionIsUsable() {
        let unknown = RelaySectionID("supply-chain")
        #expect(unknown.known == nil)
        #expect(unknown.displayName == "Supply chain")
        #expect(unknown.symbolName == "doc.text")
    }

    @Test("known sections sort before unknown ones, in a stable order")
    func ordering() {
        let ids = ["supply-chain", "kpis", "top-servers", "aardvarks", "totals"]
            .map(RelaySectionID.init)
            .sorted()

        #expect(ids.map(\.name) == ["totals", "kpis", "top-servers", "aardvarks", "supply-chain"])
    }
}

// MARK: - Presentation

@Suite("Timestamps inside sections")
struct RelayTimestampTests {

    /// `importedAt` and `lastCalculatedAt` come out of MariaDB as zone-less
    /// `LocalDateTime` and secman deliberately does not stamp a zone on them.
    /// The app must keep them as written rather than "helpfully" converting.
    @Test("a zone-less server time is kept as written")
    func serverLocal() throws {
        let stamp = try #require(RelayTimestamp("2026-08-24T06:15:03"))
        #expect(stamp.isServerLocal)
        guard case .serverLocal(let components) = stamp else {
            Issue.record("expected a server-local timestamp")
            return
        }
        #expect(components.year == 2026)
        #expect(components.month == 8)
        #expect(components.day == 24)
        #expect(components.hour == 6)
        #expect(components.minute == 15)
        #expect(components.second == 3)
        #expect(components.nanosecond == 0)
    }

    /// `DateTimeFormatter.ISO_LOCAL_DATE_TIME` prints seconds and a fraction
    /// only when they are non-zero, so all of these are the same producer.
    @Test(arguments: [
        ("2026-08-24T06:15", 0, 0),
        ("2026-08-24T06:15:03", 3, 0),
        ("2026-08-24T06:15:03.5", 3, 500_000_000),
        ("2026-08-24T06:15:03.123456", 3, 123_456_000),
        ("2026-08-24T06:15:03.123456789", 3, 123_456_789)
    ])
    func localVariants(_ text: String, second: Int, nanosecond: Int) throws {
        let stamp = try #require(RelayTimestamp(text))
        guard case .serverLocal(let components) = stamp else {
            Issue.record("expected a server-local timestamp for \(text)")
            return
        }
        #expect(components.second == second)
        #expect(components.nanosecond == nanosecond)
    }

    @Test("an RFC 3339 instant is an instant, not a server time")
    func instant() throws {
        let stamp = try #require(RelayTimestamp("2026-08-24T06:15:03Z"))
        #expect(!stamp.isServerLocal)
        guard case .instant(let date) = stamp else {
            Issue.record("expected an instant")
            return
        }
        #expect(date == RelayJSON.parseRFC3339("2026-08-24T06:15:03Z"))
    }

    @Test(arguments: [
        "", "yesterday", "2026-08-24", "06:15:03",
        "2026-13-01T00:00:00", "2026-08-32T00:00:00", "2026-08-24T24:00:00", "2026-08-24T06:60:00",
        "2026-08-24T06:15:03.", "2026-08-24T06:15:03.1234567890", "2026-08-24T06:15:03.12a"
    ])
    func rejectsGarbage(_ text: String) {
        #expect(RelayTimestamp(text) == nil)
    }

    /// The rendering is locale-dependent, so the check is only that the digits
    /// the server wrote are the digits shown — no zone shift crept in.
    @Test("the display text carries the server's digits")
    func displayText() throws {
        let stamp = try #require(RelayTimestamp("2026-08-24T23:15:03"))
        let text = stamp.displayText
        #expect(text.contains("2026"))
        #expect(text.contains("15"))
        // 23:15 in 24-hour locales, 11:15 PM in 12-hour ones — never 22 or 00.
        #expect(text.contains("23") || text.contains("11"))
    }
}

@Suite("Formatting")
struct RelayFormatTests {

    /// Locale decides the separator and the spacing before "%", so the checks
    /// are about the digits and the precision, not the exact string.
    @Test("percentages keep one decimal")
    func percent() {
        let text = RelayFormat.percent(92.44)
        #expect(text.contains("92"))
        #expect(text.contains("%"))
        #expect(!text.contains("92.44") && !text.contains("92,44"))
        #expect(RelayFormat.percent(100).contains("100"))
    }

    @Test("sub-minute durations are given in seconds, not as 0m")
    func shortDurations() {
        #expect(RelayFormat.duration(seconds: 0) == "0s")
        #expect(RelayFormat.duration(seconds: 42) == "42s")
        #expect(RelayFormat.duration(seconds: -5) == "0s")
        #expect(!RelayFormat.duration(seconds: 59).contains("m"))
    }

    @Test("longer durations carry hours and minutes")
    func longDurations() {
        let text = RelayFormat.duration(seconds: 5400)
        #expect(text.contains("1"))
        #expect(text.contains("30"))
        #expect(RelayFormat.duration(seconds: 900).contains("15"))
    }

    @Test("ages read as prose")
    func ages() {
        #expect(RelayFormat.age(seconds: 12) == "just now")
        #expect(RelayFormat.age(seconds: 600).hasSuffix(" ago"))
    }

    @Test("scopes collapse the wildcard and strip the prefix")
    func scopes() {
        #expect(RelayFormat.scopes(["status:*"]) == "all sections")
        #expect(RelayFormat.scopes(["status:*", "status:kpis"]) == "all sections")
        #expect(RelayFormat.scopes(["status:kpis", "status:imports"]) == "imports, kpis")
        #expect(RelayFormat.scopes(["other"]) == "other")
        #expect(RelayFormat.scopes([]) == "none")
    }
}

@Suite("Section highlights")
struct HighlightTests {

    private func makeSnapshot(_ sections: String) throws -> RelaySnapshot {
        try RelayJSON.decoder.decode(RelaySnapshot.self, from: Data("""
        {"instanceId":"secman-prod","schemaVersion":2,"generatedAt":"2026-08-24T06:15:03Z",
         "ageSeconds":10,"stale":false,"roles":["ADMIN"],"sections":\(sections)}
        """.utf8))
    }

    @Test("each known section yields the one number worth glancing at")
    func allSections() throws {
        let snapshot = try makeSnapshot("""
        {"totals":{"assets":12043,"vulnerabilities":88211,"users":64},
         "kpis":{"awsCleanServers":{"available":true,"percentage":92.4},
                 "edrCoverage":{"available":true,"percentage":97.5}},
         "exceptions":{"pending":14},
         "imports":{"crowdstrike":{"available":true,"errorCount":3}},
         "top-products":{"items":[{"name":"nginx","vulnerabilities":1204},{"name":"curl","vulnerabilities":9}]},
         "top-servers":{"items":[]}}
        """)

        let totals = try #require(snapshot.highlight(for: RelaySectionID("totals")))
        #expect(totals.text.hasSuffix(" vulnerabilities"))
        #expect(totals.tone == .neutral)

        let kpis = try #require(snapshot.highlight(for: RelaySectionID("kpis")))
        #expect(kpis.text.hasPrefix("AWS "))
        #expect(kpis.text.contains("EDR "))
        #expect(kpis.tone == .neutral)

        let exceptions = try #require(snapshot.highlight(for: RelaySectionID("exceptions")))
        #expect(exceptions.text == "14 pending")
        #expect(exceptions.tone == .attention)

        let imports = try #require(snapshot.highlight(for: RelaySectionID("imports")))
        #expect(imports.text == "3 errors")
        #expect(imports.tone == .problem)

        let products = try #require(snapshot.highlight(for: RelaySectionID("top-products")))
        #expect(products.text.hasPrefix("nginx · "))

        let servers = try #require(snapshot.highlight(for: RelaySectionID("top-servers")))
        #expect(servers.text == "empty")
    }

    /// "Not measured yet" and "0%" mean opposite things, and the quiet state
    /// of a healthy deployment should not shout.
    @Test("quiet states are neutral; unmeasured ones ask for attention")
    func quietAndUnmeasured() throws {
        let snapshot = try makeSnapshot("""
        {"kpis":{"awsCleanServers":{"available":false},
                 "edrCoverage":{"available":true,"percentage":97.5}},
         "exceptions":{"pending":0},
         "imports":{"crowdstrike":{"available":true,"errorCount":0}}}
        """)

        #expect(snapshot.highlight(for: RelaySectionID("kpis"))?.tone == .attention)
        #expect(snapshot.highlight(for: RelaySectionID("exceptions")) == RelaySectionHighlight(text: "none pending", tone: .neutral))
        #expect(snapshot.highlight(for: RelaySectionID("imports")) == RelaySectionHighlight(text: "no errors", tone: .neutral))

        let noImport = try makeSnapshot("""
        {"imports":{"crowdstrike":{"available":false}}}
        """)
        #expect(noImport.highlight(for: RelaySectionID("imports")) == RelaySectionHighlight(text: "no import yet", tone: .attention))
    }

    /// A highlight is a convenience. Anything the app cannot summarise — an
    /// unknown section, a missing one, or a known name with an unexpected
    /// shape — simply has no trailing text; the detail view still renders it.
    @Test("nothing is invented for unknown, absent or reshaped sections")
    func nilCases() throws {
        let snapshot = try makeSnapshot("""
        {"supply-chain":{"score":7},"exceptions":{"pending":"many"}}
        """)
        #expect(snapshot.highlight(for: RelaySectionID("supply-chain")) == nil)
        #expect(snapshot.highlight(for: RelaySectionID("totals")) == nil)
        #expect(snapshot.highlight(for: RelaySectionID("exceptions")) == nil)
    }

    @Test("every built-in section has a blurb")
    func blurbs() {
        for section in RelaySection.allCases {
            #expect(!section.blurb.isEmpty)
        }
    }
}

// MARK: - Helpers

private extension Data {
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
