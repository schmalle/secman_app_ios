import Foundation

/// Presentation helpers for what the relay sends.
///
/// Everything here is pure: given a value, produce a string or a small verdict
/// about it. It lives in the kit rather than in the views so the rules can be
/// unit-tested without a simulator — and so they exist exactly once. The three
/// questions answered here have all been answered wrongly by a status screen at
/// some point: "is this timestamp in my time zone?", "does this percentage
/// carry one decimal or four?", and "which number belongs next to the section's
/// name in the list?".
///
/// Nothing in this file decides *whether* something is shown. That is the
/// relay's job; see `RelaySectionID`.

// MARK: - Timestamps

/// A timestamp as the relay carries it, which comes in two very different kinds.
///
/// The envelope fields (`generatedAt`, `receivedAt`, `expiresAt`) are RFC 3339
/// instants with a zone, written by the relay's Go clock. Rendering them in
/// the device's own zone is correct.
///
/// The values *inside* a section — `importedAt`, `lastCalculatedAt` — are
/// different. secman reads them out of MariaDB as `LocalDateTime` with no
/// recorded offset and deliberately does not stamp a zone on them
/// (`RelaySnapshotBuilder.isoLocal`), because inventing UTC would silently
/// shift every displayed time by the server's offset. The app renders them as
/// written — "server local time" — and says so, rather than converting them
/// into something that looks precise and is wrong by a few hours.
public enum RelayTimestamp: Sendable, Equatable {
    /// An absolute instant. Displayed in the device's time zone.
    case instant(Date)
    /// Wall-clock time at the secman server, zone unknown. Displayed as written.
    case serverLocal(DateComponents)

    /// Parses either form. Returns nil for anything that is neither.
    public init?(_ text: String) {
        if let date = RelayJSON.parseRFC3339(text) {
            self = .instant(date)
            return
        }
        guard let components = Self.parseLocal(text) else { return nil }
        self = .serverLocal(components)
    }

    /// Whether this is a zone-less server time, so a view can add the caveat.
    public var isServerLocal: Bool {
        if case .serverLocal = self { return true }
        return false
    }

    /// A short, locale-aware rendering: "24 Aug 2026, 06:15".
    public var displayText: String {
        switch self {
        case .instant(let date):
            return date.formatted(date: .abbreviated, time: .shortened)
        case .serverLocal(let components):
            // Interpret and format in the same fixed zone so the digits come
            // out exactly as the server wrote them, with no DST surprise.
            guard let date = Self.utcCalendar.date(from: components) else {
                return "\(components.year ?? 0)-\(components.month ?? 0)-\(components.day ?? 0)"
            }
            return date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened, timeZone: Self.utc))
        }
    }

    /// `2026-08-24T06:15:03`, `2026-08-24T06:15:03.123456` or `2026-08-24T06:15`
    /// — the shapes `DateTimeFormatter.ISO_LOCAL_DATE_TIME` produces.
    static func parseLocal(_ text: String) -> DateComponents? {
        let halves = text.split(separator: "T", maxSplits: 1, omittingEmptySubsequences: false)
        guard halves.count == 2 else { return nil }

        let dateParts = halves[0].split(separator: "-", omittingEmptySubsequences: false)
        guard dateParts.count == 3,
              let year = Int(dateParts[0]), let month = Int(dateParts[1]), let day = Int(dateParts[2]),
              (1...12).contains(month), (1...31).contains(day) else {
            return nil
        }

        var timeText = halves[1]
        var nanoseconds = 0
        if let dot = timeText.firstIndex(of: ".") {
            let fraction = timeText[timeText.index(after: dot)...]
            guard !fraction.isEmpty, fraction.count <= 9, let value = Int(fraction) else { return nil }
            // Scale to nanoseconds whatever the precision was.
            nanoseconds = value * Int(pow(10.0, Double(9 - fraction.count)))
            timeText = timeText[..<dot]
        }

        let timeParts = timeText.split(separator: ":", omittingEmptySubsequences: false)
        guard (2...3).contains(timeParts.count),
              let hour = Int(timeParts[0]), let minute = Int(timeParts[1]),
              (0..<24).contains(hour), (0..<60).contains(minute) else {
            return nil
        }
        let second: Int
        if timeParts.count == 3 {
            guard let parsed = Int(timeParts[2]), (0..<60).contains(parsed) else { return nil }
            second = parsed
        } else {
            second = 0
        }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        components.nanosecond = nanoseconds
        return components
    }

    static let utc = TimeZone(secondsFromGMT: 0)!

    static let utcCalendar: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = utc
        return calendar
    }()
}

// MARK: - Numbers and durations

public enum RelayFormat {
    /// `92.4` → "92.4%". The relay carries percentages already scaled to 0–100
    /// with the precision secman chose; one decimal is what the web dashboard
    /// shows, so the phone matches it.
    public static func percent(_ value: Double) -> String {
        value.formatted(.percent.precision(.fractionLength(1)).scale(1))
    }

    /// `5400` → "1h 30m". Days, hours and minutes at most two units; anything
    /// under a minute is given in seconds so a fresh snapshot does not read
    /// as "0m old".
    public static func duration(seconds: Int) -> String {
        let clamped = max(0, seconds)
        if clamped < 60 { return "\(clamped)s" }
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .abbreviated
        formatter.maximumUnitCount = 2
        return formatter.string(from: TimeInterval(clamped)) ?? "\(clamped)s"
    }

    /// `42` → "just now"; `5400` → "1h 30m ago".
    public static func age(seconds: Int) -> String {
        seconds < 60 ? "just now" : "\(duration(seconds: seconds)) ago"
    }

    /// `["status:*"]` → "all sections"; `["status:kpis", "status:imports"]`
    /// → "kpis, imports". Scopes are the per-device narrowing an admin can
    /// apply on top of the user's roles; most devices carry the wildcard.
    public static func scopes(_ scopes: [String]) -> String {
        if scopes.isEmpty { return "none" }
        if scopes.contains("status:*") { return "all sections" }
        let names = scopes.map { scope -> String in
            scope.hasPrefix("status:") ? String(scope.dropFirst("status:".count)) : scope
        }
        return names.sorted().joined(separator: ", ")
    }
}

// MARK: - Section highlights

/// The one number worth showing next to a section's name in the list.
///
/// On an iPhone the list is the whole first screen, and a list of six nouns
/// tells an on-call admin nothing. A trailing "14 pending" or "3 errors" turns
/// it into a dashboard without a second screen. The tone is a hint for colour
/// only — it never hides or reorders anything.
public struct RelaySectionHighlight: Sendable, Equatable {
    public enum Tone: Sendable, Equatable {
        /// Informational.
        case neutral
        /// Something is waiting on a human, or has not been measured.
        case attention
        /// Something went wrong on the secman side.
        case problem
    }

    public let text: String
    public let tone: Tone

    public init(text: String, tone: Tone) {
        self.text = text
        self.tone = tone
    }
}

extension RelaySnapshot {
    /// A highlight for a known section, or nil when the section is unknown,
    /// absent from this snapshot, or shaped differently from what this build
    /// expects. Nil means "show the name alone" — the detail view still
    /// renders the raw rows, so nothing is lost.
    public func highlight(for section: RelaySectionID) -> RelaySectionHighlight? {
        guard let known = section.known, sections[section.name] != nil else { return nil }
        let name = section.name

        switch known {
        case .totals:
            guard let totals = try? decode(RelayTotalsSection.self, section: name) else { return nil }
            return RelaySectionHighlight(
                text: "\(totals.vulnerabilities.formatted()) vulnerabilities",
                tone: .neutral
            )

        case .kpis:
            guard let kpis = try? decode(RelayKpisSection.self, section: name) else { return nil }
            let aws = kpis.awsCleanServers.available ? kpis.awsCleanServers.percentage : nil
            let edr = kpis.edrCoverage.available ? kpis.edrCoverage.percentage : nil
            let awsText = aws.map(RelayFormat.percent) ?? "–"
            let edrText = edr.map(RelayFormat.percent) ?? "–"
            return RelaySectionHighlight(
                text: "AWS \(awsText) · EDR \(edrText)",
                tone: (aws == nil || edr == nil) ? .attention : .neutral
            )

        case .exceptions:
            guard let exceptions = try? decode(RelayExceptionsSection.self, section: name) else { return nil }
            return exceptions.pending == 0
                ? RelaySectionHighlight(text: "none pending", tone: .neutral)
                : RelaySectionHighlight(text: "\(exceptions.pending.formatted()) pending", tone: .attention)

        case .imports:
            guard let imports = try? decode(RelayImportsSection.self, section: name) else { return nil }
            let crowdstrike = imports.crowdstrike
            guard crowdstrike.available else {
                return RelaySectionHighlight(text: "no import yet", tone: .attention)
            }
            if let errors = crowdstrike.errorCount, errors > 0 {
                return RelaySectionHighlight(text: "\(errors.formatted()) errors", tone: .problem)
            }
            return RelaySectionHighlight(text: "no errors", tone: .neutral)

        case .topProducts, .topServers:
            guard let list = try? decode(RelayTopListSection.self, section: name) else { return nil }
            guard let first = list.items.first else {
                return RelaySectionHighlight(text: "empty", tone: .neutral)
            }
            return RelaySectionHighlight(
                text: "\(first.name) · \(first.vulnerabilities.formatted())",
                tone: .neutral
            )
        }
    }
}

extension RelaySection {
    /// One line on what the section contains, matching the `description`
    /// secman attaches to each section's policy in `RelaySnapshotBuilder`.
    public var blurb: String {
        switch self {
        case .totals: return "Asset, vulnerability and user counts"
        case .kpis: return "AWS clean-server and EDR coverage KPIs"
        case .exceptions: return "Vulnerability exception requests awaiting review"
        case .imports: return "Freshness of the last CrowdStrike import"
        case .topProducts: return "Products with the most vulnerabilities"
        case .topServers: return "Servers with the most vulnerabilities"
        }
    }
}
