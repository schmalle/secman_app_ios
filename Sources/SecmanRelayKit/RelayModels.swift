import Foundation

/// Wire types for the relay's mobile API (`/api/v1/...`).
///
/// These mirror `src/relay/internal/api/api.go` in the secman repository.
/// The relay versions its snapshot envelope; `RelaySnapshot.schemaVersion` is
/// checked on arrival so a relay that has moved ahead of the app produces a
/// clear "update the app" state rather than a half-rendered screen.

/// The envelope version this build understands.
public let relaySupportedSnapshotSchemaVersion = 2

// MARK: - Discovery

/// `GET /api/v1/providers` — what this relay offers, and the rule it enforces.
public struct RelayProviders: Codable, Sendable, Equatable {
    /// `apple`, `google` and/or `github`, whichever the operator enabled.
    public let providers: [String]
    /// Whether the typed enrollment-code path is available at all.
    public let enrollmentCodes: Bool
    /// Roles that may only be bound through a strong provider (default `ADMIN`).
    public let privilegedRoles: [String]
    /// The providers that count as strong (default `apple`, `google`).
    public let strongProviders: [String]

    /// Whether `provider` is strong enough for a privileged account.
    ///
    /// Used to grey out a button *before* the user taps it. The relay enforces
    /// the same rule; this is UX, never the boundary.
    public func isStrong(_ provider: String) -> Bool {
        strongProviders.contains(provider)
    }
}

// MARK: - Sign-in

/// `POST /api/v1/auth/nonce` — a single-use nonce bound to this device's key.
public struct RelayLoginNonce: Codable, Sendable {
    /// The raw nonce. Sent back to the relay when completing the binding.
    public let nonce: String
    /// SHA-256 hex of `nonce` — the value handed to Sign in with Apple.
    ///
    /// The relay computes it too, and returns it so the client cannot get the
    /// hashing convention subtly wrong.
    public let nonceHash: String
    public let expiresAt: Date
    /// The byte string the relay expects the device key to sign.
    ///
    /// Advisory. The app derives the same string with `RelayProtocol` and
    /// refuses the binding if the two disagree — see that type for why signing
    /// the server's copy directly would be a mistake.
    public let bindingInput: String?
    public let algorithm: String?
}

/// The result of binding a device: who the relay thinks we are.
public struct RelayBinding: Codable, Sendable, Equatable {
    public let deviceId: String
    public let subject: String
    public let displayName: String?
    /// The secman roles this user holds, as the relay currently sees them.
    public let roles: [String]
    public let scopes: [String]
    public let boundVia: String
    public let provider: String?
}

/// `POST /api/v1/auth/challenge` — a per-session challenge for the device key.
public struct RelayChallenge: Codable, Sendable {
    public let nonce: String
    public let expiresAt: Date
    /// Advisory, like `RelayLoginNonce.bindingInput`.
    public let signingInput: String?
    public let algorithm: String?
}

/// `POST /api/v1/auth/token` — a short-lived access token.
public struct RelayToken: Codable, Sendable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int
    public let subject: String
    public let roles: [String]
    public let scopes: [String]
}

/// `POST /api/v1/auth/github/start`
///
/// The relay's `bindingInput` field is deliberately *not* modelled: it carries
/// the literal text "issued with the ticket", because at this point in the flow
/// the value to sign does not exist yet. The app derives it from the ticket the
/// browser round trip returns.
public struct RelayGitHubStart: Codable, Sendable {
    public let authorizationUrl: String
    public let state: String
}

// MARK: - Status

/// `GET /api/v1/session` — identity and entitlements for the current device.
public struct RelaySession: Codable, Sendable, Equatable {
    public let deviceId: String
    public let subject: String
    public let displayName: String?
    public let roles: [String]
    public let scopes: [String]
    public let boundVia: String
    public let provider: String?
    /// The sections this device may read. The app builds its section list from
    /// this rather than from a local guess, so a role change on the server
    /// changes the UI without an app update.
    public let sections: [String]
}

/// `GET /api/v1/meta` — freshness and entitlements, without the payload.
///
/// The cheap poll. Everything the shell of the UI needs (is the data stale, how
/// old is it, which sections may this device read) at a fraction of the bytes
/// of a full `/status`, which matters on a phone that wakes up on cellular.
public struct RelayMeta: Codable, Sendable, Equatable {
    public let instanceId: String
    public let schemaVersion: Int
    public let generatedAt: Date
    public let receivedAt: Date
    public let ageSeconds: Int
    public let stale: Bool
    /// The relay's staleness threshold, so the UI can say "older than 15
    /// minutes" using the deployment's own number rather than a guess.
    public let maxAgeSeconds: Int
    public let sections: [String]
    public let deviceId: String
    public let subject: String
    public let roles: [String]
    public let scopes: [String]
}

/// `GET /api/v1/status` — the snapshot, filtered to what this device may read.
public struct RelaySnapshot: Sendable {
    public let instanceId: String
    public let schemaVersion: Int
    public let generatedAt: Date
    public let ageSeconds: Int
    /// True when the relay has not had a fresh push within its configured
    /// window. The data is still returned; the UI must label it, never hide it.
    public let stale: Bool
    public let roles: [String]
    /// Section name to raw JSON. Decoded lazily by the feature that needs it,
    /// so an unknown or changed section never breaks the whole screen.
    public let sections: [String: Data]

    /// Decodes one section into a concrete type.
    public func decode<T: Decodable>(_ type: T.Type, section: String, using decoder: JSONDecoder = RelayJSON.decoder) throws -> T? {
        guard let data = sections[section] else { return nil }
        return try decoder.decode(T.self, from: data)
    }

    /// One section as generic JSON, for a section this build has no type for.
    ///
    /// This is what lets the relay grow a section without an app release: the
    /// UI renders whatever arrives as labelled rows instead of hiding it.
    public func value(section: String) -> RelayJSONValue? {
        guard let data = sections[section] else { return nil }
        return try? RelayJSON.decoder.decode(RelayJSONValue.self, from: data)
    }
}

extension RelaySnapshot: Decodable {
    private enum CodingKeys: String, CodingKey {
        case instanceId, schemaVersion, generatedAt, ageSeconds, stale, roles, sections
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        instanceId = try container.decode(String.self, forKey: .instanceId)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        generatedAt = try container.decode(Date.self, forKey: .generatedAt)
        ageSeconds = try container.decode(Int.self, forKey: .ageSeconds)
        stale = try container.decode(Bool.self, forKey: .stale)
        roles = try container.decodeIfPresent([String].self, forKey: .roles) ?? []

        // Sections stay as raw JSON. The relay deliberately treats them as
        // opaque, and so does the app: a new field, or a whole new section,
        // must never fail the decode of the screen the user is looking at.
        let raw = try container.decodeIfPresent([String: RelayRawJSON].self, forKey: .sections) ?? [:]
        sections = raw.mapValues(\.data)
    }
}

/// A JSON value captured as its encoded bytes.
struct RelayRawJSON: Decodable {
    let data: Data

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(RelayJSONValue.self)
        data = try RelayJSON.rawEncoder.encode(value)
    }
}

/// A minimal `any JSON` representation.
///
/// Used to round-trip an opaque section back into `Data`, and to render a
/// section this build has no concrete type for.
public indirect enum RelayJSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    /// Integers are kept distinct from `number` on purpose. Everything the
    /// relay carries in this position is a count — assets, vulnerabilities,
    /// servers processed — and routing those through `Double` renders 1234 as
    /// "1234.0" and loses precision past 2^53.
    case int(Int)
    case number(Double)
    case string(String)
    case array([RelayJSONValue])
    case object([String: RelayJSONValue])

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([RelayJSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: RelayJSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "unsupported JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// A short single-line rendering, for the generic section view.
    public var displayText: String? {
        switch self {
        case .null: return "—"
        case .bool(let value): return value ? "yes" : "no"
        case .int(let value): return value.formatted()
        case .number(let value): return value.formatted()
        case .string(let value): return value
        case .array, .object: return nil
        }
    }
}

// MARK: - Known section payloads

/// `kpis` — requires ADMIN or SECCHAMPION on the secman side.
public struct RelayKpisSection: Codable, Sendable {
    public struct AwsCleanServers: Codable, Sendable {
        public let available: Bool
        public let percentage: Double?
        public let totalServers: Int?
        public let cleanServers: Int?
        public let lastCalculatedAt: String?
    }

    public struct EdrCoverage: Codable, Sendable {
        public let available: Bool
        public let percentage: Double?
        public let totalInstances: Int?
        public let eligibleInstances: Int?
        public let coveredInstances: Int?
        public let excludedByException: Int?
        public let agentSeenWithinDays: Int?
        public let lastCalculatedAt: String?
    }

    public let awsCleanServers: AwsCleanServers
    public let edrCoverage: EdrCoverage
}

/// `totals` — requires ADMIN.
public struct RelayTotalsSection: Codable, Sendable {
    public let assets: Int
    public let vulnerabilities: Int
    public let users: Int
}

/// `exceptions` — requires ADMIN or SECCHAMPION.
public struct RelayExceptionsSection: Codable, Sendable {
    public let pending: Int
}

/// `imports` — requires ADMIN or VULN.
public struct RelayImportsSection: Codable, Sendable {
    public struct CrowdStrike: Codable, Sendable {
        public let available: Bool
        public let importedAt: String?
        public let serversProcessed: Int?
        public let vulnerabilitiesImported: Int?
        public let errorCount: Int?
    }
    public let crowdstrike: CrowdStrike
}

/// `top-products` / `top-servers` — require ADMIN.
public struct RelayTopListSection: Codable, Sendable {
    public struct Item: Codable, Sendable, Identifiable {
        public let name: String
        public let vulnerabilities: Int
        public var id: String { name }
    }
    public let items: [Item]
}

// MARK: - Section identifiers

/// The sections `RelaySnapshotBuilder` publishes today, and the roles secman
/// gates them behind.
///
/// This table is presentation only — an icon and a title. It decides nothing:
/// authorization happens on the relay, and a section missing from this enum
/// still appears in the UI via the generic renderer. See `RelaySectionID`. The
/// role each section requires is documented in `docs/API.md`; it is not
/// mirrored here, because a copy the app never consults is a copy that drifts.
public enum RelaySection: String, CaseIterable, Sendable {
    case totals
    case kpis
    case exceptions
    case imports
    case topProducts = "top-products"
    case topServers = "top-servers"

    public var displayName: String {
        switch self {
        case .totals: return "Overview"
        case .kpis: return "Security KPIs"
        case .exceptions: return "Exceptions"
        case .imports: return "Imports"
        case .topProducts: return "Top products"
        case .topServers: return "Top servers"
        }
    }

    public var symbolName: String {
        switch self {
        case .totals: return "square.grid.2x2"
        case .kpis: return "gauge.with.needle"
        case .exceptions: return "exclamationmark.triangle"
        case .imports: return "arrow.down.circle"
        case .topProducts: return "shippingbox"
        case .topServers: return "server.rack"
        }
    }
}

/// A section the relay says this device may read.
///
/// The name comes from the server, always. `known` is non-nil for the six
/// sections this build renders with a purpose-built view; for anything else the
/// app still lists it and still shows its contents, just generically. That is
/// the difference between "the relay grew a section" being a release and being
/// a refresh.
public struct RelaySectionID: Hashable, Sendable, Identifiable, Comparable {
    public let name: String
    public var id: String { name }

    public init(_ name: String) {
        self.name = name
    }

    public var known: RelaySection? { RelaySection(rawValue: name) }

    public var displayName: String {
        if let known { return known.displayName }
        // "top-products" -> "Top products". Good enough for a name the app has
        // never heard of, and better than showing the raw key.
        let spaced = name.replacingOccurrences(of: "-", with: " ")
        return spaced.prefix(1).uppercased() + spaced.dropFirst()
    }

    public var symbolName: String { known?.symbolName ?? "doc.text" }

    /// Known sections first, in the canonical order above; then anything new,
    /// alphabetically. A stable order matters more than a clever one: the
    /// sidebar should not reshuffle between refreshes.
    public static func < (lhs: RelaySectionID, rhs: RelaySectionID) -> Bool {
        switch (lhs.known, rhs.known) {
        case let (l?, r?):
            let all = RelaySection.allCases
            return all.firstIndex(of: l)! < all.firstIndex(of: r)!
        case (_?, nil): return true
        case (nil, _?): return false
        case (nil, nil): return lhs.name < rhs.name
        }
    }
}

// MARK: - JSON

public enum RelayJSON {
    /// Shared coders.
    ///
    /// `nonisolated(unsafe)` rather than a fresh instance per call: these are
    /// configured once and never mutated afterwards, which is the condition
    /// under which `JSONDecoder` is safe to share, and a snapshot re-encodes up
    /// to 64 opaque section bodies per refresh.
    nonisolated(unsafe) public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            guard let date = parseRFC3339(text) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "not an RFC 3339 timestamp")
            }
            return date
        }
        return decoder
    }()

    nonisolated(unsafe) public static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    nonisolated(unsafe) static let rawEncoder = JSONEncoder()

    private static let iso8601WithFraction = Date.ISO8601FormatStyle(includingFractionalSeconds: true)
    private static let iso8601 = Date.ISO8601FormatStyle()

    /// Parses the timestamps the relay emits.
    ///
    /// Go marshals `time.Time` as RFC 3339 *Nano* with trailing zeros trimmed,
    /// so the same field arrives as `...:00Z`, `...:00.5Z` or
    /// `...:00.123456789Z` depending on the instant. `ISO8601FormatStyle` is
    /// specified for milliseconds, so anything else is normalised to three
    /// fractional digits and retried — a status screen should not go blank
    /// because a timestamp happened to land on a nanosecond boundary.
    static func parseRFC3339(_ text: String) -> Date? {
        if let date = try? iso8601WithFraction.parse(text) { return date }
        if let date = try? iso8601.parse(text) { return date }
        guard let normalized = normalizingFraction(text) else { return nil }
        return try? iso8601WithFraction.parse(normalized)
    }

    /// Rewrites the fractional-seconds part to exactly three digits.
    static func normalizingFraction(_ text: String) -> String? {
        guard let dot = text.firstIndex(of: ".") else { return nil }
        let afterDot = text.index(after: dot)
        guard let end = text[afterDot...].firstIndex(where: { !$0.isNumber }) else { return nil }

        let digits = text[afterDot..<end]
        guard !digits.isEmpty else { return nil }
        let millis = digits.count >= 3
            ? String(digits.prefix(3))
            : String(digits) + String(repeating: "0", count: 3 - digits.count)
        return String(text[..<afterDot]) + millis + String(text[end...])
    }
}

/// The shape every relay error uses.
struct RelayErrorBody: Decodable {
    let error: String?
    let requestId: String?
}
