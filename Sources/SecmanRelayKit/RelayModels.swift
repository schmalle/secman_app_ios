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
    /// The exact byte string the device key must sign to complete the binding.
    public let bindingInput: String
    public let algorithm: String
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
    public let signingInput: String
    public let algorithm: String
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
    /// The sections this device may read. The app builds its tab list from
    /// this rather than from a local guess, so a role change on the server
    /// changes the UI without an app update.
    public let sections: [String]
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
        data = try JSONEncoder().encode(value)
    }
}

/// A minimal `any JSON` representation, used only to round-trip an opaque
/// section back into `Data`.
indirect enum RelayJSONValue: Codable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([RelayJSONValue])
    case object([String: RelayJSONValue])

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
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

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
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

/// The section names the relay serves, and the roles secman gates them behind.
///
/// The role lists are for explanatory UI only ("you need SECCHAMPION to see
/// this"). Authorization happens on the relay; this table never decides
/// anything.
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

    public var explanatoryRoles: [String] {
        switch self {
        case .totals, .topProducts, .topServers: return ["ADMIN"]
        case .kpis, .exceptions: return ["ADMIN", "SECCHAMPION"]
        case .imports: return ["ADMIN", "VULN"]
        }
    }
}

// MARK: - JSON

public enum RelayJSON {
    /// The relay emits RFC 3339 with fractional seconds on some fields and
    /// without on others, so both are accepted rather than one being assumed.
    public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            if let date = iso8601WithFraction.date(from: text) ?? iso8601.date(from: text) {
                return date
            }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "not an RFC 3339 timestamp: \(text)")
        }
        return decoder
    }()

    public static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let iso8601WithFraction: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static let iso8601: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}

/// The shape every relay error uses.
struct RelayErrorBody: Decodable {
    let error: String?
    let requestId: String?
}
