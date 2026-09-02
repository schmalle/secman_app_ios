import SecmanRelayKit
import SwiftUI

/// The status screen.
///
/// A `NavigationSplitView` so the same code is a sidebar on iPad and a stack on
/// iPhone. The list is built from the relay's answer to "what may this device
/// read" — so a user with only VULN sees one entry and an admin sees six, with
/// no client-side role logic anywhere.
///
/// On an iPhone the list *is* the first screen, so it carries more than names:
/// a freshness line at the top, and next to each section the one number worth
/// glancing at (pending exceptions, import errors, the two KPI percentages).
/// The banners for "stale", "unreachable" and "update the app" live here too
/// and are repeated inside the detail view at compact width, where the list is
/// off screen.
struct StatusView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var selection: RelaySectionID?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section {
                    FreshnessRow()
                    StatusBanners()
                }

                Section {
                    ForEach(model.visibleSections) { section in
                        NavigationLink(value: section) {
                            SectionRow(section: section, highlight: model.snapshot?.highlight(for: section))
                        }
                    }
                    if model.visibleSections.isEmpty {
                        ContentUnavailableView(
                            "Nothing to show",
                            systemImage: "lock",
                            description: Text("Your secman roles do not grant access to any of the sections this relay publishes.")
                        )
                    }
                } header: {
                    Text("Sections")
                } footer: {
                    Text("Exactly the sections the relay allows for your secman roles, as of the last check. A role change in secman changes this list on the next refresh.")
                }
            }
            .navigationTitle("secman")
            .refreshable { await model.refresh() }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink { SettingsView() } label: { Image(systemName: "person.crop.circle") }
                }
            }
        } detail: {
            if let selection {
                SectionDetailView(section: selection)
            } else {
                ContentUnavailableView("Select a section", systemImage: "sidebar.left")
            }
        }
        .onAppear(perform: selectFirstSectionOnIPad)
        .onChange(of: model.visibleSections) { _, sections in
            // A demotion in secman can take the open section away. Falling back
            // to the placeholder beats leaving a detail view up that the server
            // has just said this user may not read.
            if let selection, !sections.contains(selection) {
                self.selection = nil
            }
            selectFirstSectionOnIPad()
        }
    }

    /// Preselects a section on iPad only.
    ///
    /// A `NavigationSplitView` collapses to a stack at compact width, where a
    /// non-nil selection is not "highlight the sidebar row" but "push the detail
    /// view" — so doing this unconditionally would drop every iPhone user
    /// straight into a section on launch, with the list they never saw behind a
    /// back button.
    private func selectFirstSectionOnIPad() {
        guard sizeClass == .regular, selection == nil else { return }
        selection = model.visibleSections.first
    }
}

// MARK: - Freshness and banners

/// The first row of the list: how old the status is, and when the app last
/// asked. Both numbers tick on their own so a phone left on a desk does not
/// show "2 min ago" for an hour.
struct FreshnessRow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let meta = model.meta {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    (Text("Status from ") + Text(meta.generatedAt, style: .relative) + Text(" ago"))
                        .font(.subheadline.weight(.semibold))
                        .monospacedDigit()
                    checkedLine(instance: meta.instanceId)
                }
            } icon: {
                Image(systemName: meta.stale ? "clock.badge.exclamationmark" : "checkmark.circle")
                    .foregroundStyle(meta.stale ? Color.orange : Color.green)
            }
        } else if model.snapshotProblem == nil {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Waiting for secman").font(.subheadline.weight(.semibold))
                    Text("The relay is reachable but has not received a status update yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "antenna.radiowaves.left.and.right")
            }
        }
    }

    private func checkedLine(instance: String) -> some View {
        let text: Text
        if let checked = model.lastRefreshedAt {
            text = Text("Checked ") + Text(checked, style: .relative) + Text(" ago · \(instance)")
        } else {
            text = Text(instance)
        }
        return text.font(.caption).foregroundStyle(.secondary).monospacedDigit()
    }
}

/// The three conditions that need saying wherever data is shown.
///
/// Stacked in order of how much they change the meaning of the numbers on
/// screen: unreachable (the numbers may be old and the app cannot tell how
/// old), stale (the relay itself says they are old), and a schema problem (there
/// are no numbers, and refreshing will not produce any).
struct StatusBanners: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let failure = model.lastRefreshFailure {
            UnreachableBanner(failure: failure)
        }
        if let meta = model.meta, meta.stale {
            StaleBanner(generatedAt: meta.generatedAt, maxAgeSeconds: meta.maxAgeSeconds)
        }
        if let problem = model.snapshotProblem {
            SnapshotProblemBanner(problem: problem)
        }
    }
}

/// Stale data is labelled, never hidden.
///
/// The relay serves the last snapshot it has along with its age, because on an
/// incident call "42 minutes old" is far more useful than an empty screen — and
/// far safer than an unlabelled number that looks current.
struct StaleBanner: View {
    let generatedAt: Date
    /// The relay's own threshold, so the explanation quotes the deployment's
    /// number rather than a constant compiled into the app.
    let maxAgeSeconds: Int

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                (Text("Data is ") + Text(generatedAt, style: .relative) + Text(" old"))
                    .font(.subheadline.weight(.semibold))
                    .monospacedDigit()
                Text("secman has not pushed an update in the last \(RelayFormat.duration(seconds: maxAgeSeconds)). Check the publisher in secman.")
                    .font(.caption)
            }
        } icon: {
            Image(systemName: "clock.badge.exclamationmark")
        }
        .foregroundStyle(.orange)
        .listRowBackground(Color.orange.opacity(0.12))
    }
}

/// The relay did not answer the last refresh.
///
/// What is on screen is the last data received, and its own age line still
/// ticks — so the user can see both "how old" and "since when we cannot tell".
struct UnreachableBanner: View {
    let failure: AppModel.RefreshFailure

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                (Text("Relay unreachable for ") + Text(failure.at, style: .relative))
                    .font(.subheadline.weight(.semibold))
                    .monospacedDigit()
                Text(failure.message).font(.caption)
            }
        } icon: {
            Image(systemName: "wifi.slash")
        }
        .foregroundStyle(.red)
        .listRowBackground(Color.red.opacity(0.12))
    }
}

/// The relay answered with a status format this build cannot render.
struct SnapshotProblemBanner: View {
    let problem: AppModel.SnapshotProblem

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text("Update the app").font(.subheadline.weight(.semibold))
                Text(problem.explanation).font(.caption)
            }
        } icon: {
            Image(systemName: "arrow.down.app")
        }
        .foregroundStyle(.orange)
        .listRowBackground(Color.orange.opacity(0.12))
    }
}

extension AppModel.SnapshotProblem {
    var explanation: String {
        switch self {
        case .unsupportedSchema(let found, let supported):
            return "This relay publishes status format v\(found); this app understands v\(supported). The relay and your account are fine — a newer app is needed to show status."
        }
    }
}

/// One section in the list: its name, and the number worth glancing at.
struct SectionRow: View {
    let section: RelaySectionID
    let highlight: RelaySectionHighlight?

    var body: some View {
        LabeledContent {
            if let highlight {
                Text(highlight.text)
                    .font(.subheadline)
                    .foregroundStyle(Self.style(for: highlight.tone))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .monospacedDigit()
            }
        } label: {
            Label(section.displayName, systemImage: section.symbolName)
        }
    }

    static func style(for tone: RelaySectionHighlight.Tone) -> AnyShapeStyle {
        switch tone {
        case .neutral: return AnyShapeStyle(HierarchicalShapeStyle.secondary)
        case .attention: return AnyShapeStyle(Color.orange)
        case .problem: return AnyShapeStyle(Color.red)
        }
    }
}

// MARK: - Detail

struct SectionDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.horizontalSizeClass) private var sizeClass
    let section: RelaySectionID

    var body: some View {
        List {
            if sizeClass == .compact {
                // On iPhone the sidebar — and its banners — is off screen
                // while a section is open. A stale or unreachable state must
                // not disappear the moment the user drills in.
                Section { StatusBanners() }
            }

            if let problem = model.snapshotProblem {
                ContentUnavailableView {
                    Label("Update the app", systemImage: "arrow.down.app")
                } description: {
                    Text(problem.explanation)
                }
            } else if let snapshot = model.snapshot {
                content(for: snapshot)
                SourceSection(snapshot: snapshot, meta: model.meta)
            } else {
                ContentUnavailableView(
                    "Waiting for secman",
                    systemImage: "antenna.radiowaves.left.and.right",
                    description: Text("The relay is reachable but has not received a status update yet.")
                )
            }
        }
        .navigationTitle(section.displayName)
        .refreshable { await model.refresh() }
    }

    @ViewBuilder
    private func content(for snapshot: RelaySnapshot) -> some View {
        switch section.known {
        case .totals:
            typed(RelayTotalsSection.self, from: snapshot) { totals in
                Section {
                    MetricRow(title: "Assets", value: totals.assets.formatted())
                    MetricRow(title: "Vulnerabilities", value: totals.vulnerabilities.formatted())
                    MetricRow(title: "Users", value: totals.users.formatted())
                } footer: {
                    Text("\(RelaySection.totals.blurb), across everything secman holds, as of the snapshot.")
                }
            }

        case .kpis:
            typed(RelayKpisSection.self, from: snapshot) { kpis in
                Section {
                    // `available: false` means "not measured yet", which is not
                    // the same as 0% and must never be rendered as such.
                    if kpis.awsCleanServers.available, let percentage = kpis.awsCleanServers.percentage {
                        KpiGauge(title: "AWS servers with no finding open past 30 days", percentage: percentage)
                        if let total = kpis.awsCleanServers.totalServers, let clean = kpis.awsCleanServers.cleanServers {
                            MetricRow(title: "Clean / all AWS servers", value: "\(clean.formatted()) / \(total.formatted())")
                        }
                        if let at = kpis.awsCleanServers.lastCalculatedAt {
                            TimestampRow(title: "Calculated", raw: at)
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                } header: {
                    Text("AWS clean servers")
                } footer: {
                    Text("A server is clean when none of its open, non-excepted findings has been open for more than 30 days. secman measures that age from the date a fix became available where one is published, and from detection otherwise, so re-imaging a host does not reset the clock. Installer artifacts are not counted. Recalculated after every CrowdStrike import.")
                }

                Section {
                    if kpis.edrCoverage.available, let percentage = kpis.edrCoverage.percentage {
                        KpiGauge(title: "Eligible EC2 instances with a live CrowdStrike sensor", percentage: percentage)
                        if let covered = kpis.edrCoverage.coveredInstances, let eligible = kpis.edrCoverage.eligibleInstances {
                            MetricRow(title: "Covered / eligible", value: "\(covered.formatted()) / \(eligible.formatted())")
                        }
                        if let total = kpis.edrCoverage.totalInstances {
                            MetricRow(title: "All EC2 instances", value: total.formatted())
                        }
                        if let excluded = kpis.edrCoverage.excludedByException, excluded > 0 {
                            MetricRow(title: "Excluded by “No EDR possible” exception", value: excluded.formatted())
                        }
                        if let days = kpis.edrCoverage.agentSeenWithinDays {
                            MetricRow(title: "Sensor seen within", value: "\(days) days")
                        }
                        if let at = kpis.edrCoverage.lastCalculatedAt {
                            TimestampRow(title: "Calculated", raw: at)
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                } header: {
                    Text("EDR coverage")
                } footer: {
                    Text("Covered means CrowdStrike reported the instance's sensor within the window shown. Instances with an approved “No EDR possible” exception leave the denominator; the raw total is listed so that effect stays visible rather than hidden inside the percentage.")
                }
            }

        case .exceptions:
            typed(RelayExceptionsSection.self, from: snapshot) { exceptions in
                Section {
                    HStack {
                        Image(systemName: exceptions.pending > 0 ? "tray.full.fill" : "tray.fill")
                            .foregroundStyle(exceptions.pending > 0 ? Color.orange : Color.secondary)
                        Text(exceptions.pending > 0 ? "Waiting on a reviewer" : "Nothing waiting")
                    }
                    MetricRow(title: "Awaiting review", value: exceptions.pending.formatted())
                } footer: {
                    Text("Vulnerability exception requests in the pending state. Review and approval happen in secman; this app is read-only.")
                }
            }

        case .imports:
            typed(RelayImportsSection.self, from: snapshot) { imports in
                let crowdstrike = imports.crowdstrike
                let errors = crowdstrike.errorCount ?? 0
                Section {
                    if crowdstrike.available {
                        HStack {
                            Image(systemName: errors > 0 ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundStyle(errors > 0 ? Color.orange : Color.green)
                            Text(errors > 0 ? "Completed with errors" : "Completed")
                        }
                        if let at = crowdstrike.importedAt {
                            TimestampRow(title: "Last import", raw: at)
                        }
                        if let servers = crowdstrike.serversProcessed {
                            MetricRow(title: "Servers processed", value: servers.formatted())
                        }
                        if let vulns = crowdstrike.vulnerabilitiesImported {
                            MetricRow(title: "Vulnerabilities imported", value: vulns.formatted())
                        }
                        if crowdstrike.errorCount != nil {
                            MetricRow(title: "Errors", value: errors > 0 ? errors.formatted() : "none")
                                .foregroundStyle(errors > 0 ? Color.red : Color.primary)
                        }
                    } else {
                        Text("No import has run yet").foregroundStyle(.secondary)
                    }
                } header: {
                    Text("CrowdStrike")
                } footer: {
                    Text("The most recent CrowdStrike Falcon import into secman. Errors are hosts that failed during that run; a host whose fetch failed keeps its previous findings rather than having them swept as remediated. Times inside the import are secman's server clock, shown as written.")
                }
            }

        case .topProducts, .topServers:
            typed(RelayTopListSection.self, from: snapshot) { list in
                let top = list.items.map(\.vulnerabilities).max() ?? 0
                Section {
                    ForEach(Array(list.items.enumerated()), id: \.element.id) { index, item in
                        RankedRow(
                            rank: index + 1,
                            name: item.name,
                            count: item.vulnerabilities,
                            share: top > 0 ? Double(item.vulnerabilities) / Double(top) : 0
                        )
                    }
                    if list.items.isEmpty {
                        Text("Nothing to rank").foregroundStyle(.secondary)
                    }
                } footer: {
                    Text("\(section.known?.blurb ?? "Ranking"), by open vulnerability count as of the snapshot. Bars are relative to the top entry. The same list secman's admin summary sends.")
                }
            }

        case nil:
            GenericSectionView(value: snapshot.value(section: section.name))
        }
    }

    /// Renders a known section, or falls back to the generic view.
    ///
    /// The fallback is the point. If secman renames a field this build expects,
    /// the typed decode fails — and rendering nothing at that moment leaves an
    /// operator looking at a blank screen with no hint that data did arrive.
    /// Showing the raw rows is worse-looking and far more useful.
    @ViewBuilder
    private func typed<T: Decodable, Content: View>(
        _ type: T.Type,
        from snapshot: RelaySnapshot,
        @ViewBuilder content: (T) -> Content
    ) -> some View {
        // One `let`, not two: since Swift 5, `try?` on an already-optional
        // expression flattens rather than nesting.
        if let value = try? snapshot.decode(type, section: section.name) {
            content(value)
        } else {
            GenericSectionView(value: snapshot.value(section: section.name))
        }
    }
}

/// Where the numbers came from and when.
///
/// `generatedAt` is secman's clock when it built the snapshot; `receivedAt` is
/// the relay's when the push landed. Both are shown because the gap between
/// them is the one diagnostic a phone can offer about the publisher.
struct SourceSection: View {
    let snapshot: RelaySnapshot
    let meta: RelayMeta?

    var body: some View {
        Section {
            LabeledContent("Generated") {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(snapshot.generatedAt.formatted(date: .abbreviated, time: .standard)).monospacedDigit()
                    (Text(snapshot.generatedAt, style: .relative) + Text(" ago"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            if let meta {
                LabeledContent("Received by relay", value: meta.receivedAt.formatted(date: .abbreviated, time: .standard))
                LabeledContent("Stale after", value: RelayFormat.duration(seconds: meta.maxAgeSeconds))
            }
            LabeledContent("secman instance", value: snapshot.instanceId)
            LabeledContent("Status format", value: "v\(snapshot.schemaVersion)")
        } header: {
            Text("Source")
        } footer: {
            Text("Pull down to check for a newer snapshot. Nothing shown here is stored on this device.")
        }
    }
}

// MARK: - Rows

/// A percentage with a bar under it.
///
/// No thresholds and no red/green: secman defines none for these KPIs, and a
/// colour the server did not choose would be the app inventing a policy.
struct KpiGauge: View {
    let title: String
    let percentage: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.subheadline)
                Spacer()
                Text(RelayFormat.percent(percentage))
                    .font(.title3.weight(.semibold))
                    .monospacedDigit()
            }
            Gauge(value: min(max(percentage, 0), 100), in: 0...100) {
                EmptyView()
            }
            .gaugeStyle(.accessoryLinearCapacity)
            .tint(Color.accentColor)
        }
        .accessibilityElement(children: .combine)
    }
}

/// A timestamp from inside a section, rendered by `RelayTimestamp` so a
/// zone-less server time is labelled as such instead of passed off as local.
struct TimestampRow: View {
    let title: String
    let raw: String

    var body: some View {
        if let stamp = RelayTimestamp(raw) {
            LabeledContent(title) {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(stamp.displayText).monospacedDigit()
                    if stamp.isServerLocal {
                        Text("server local time").font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        } else {
            MetricRow(title: title, value: raw)
        }
    }
}

/// One entry of a top-N list: rank, name, count, and a bar relative to the
/// largest entry so the shape of the list is visible without reading numbers.
struct RankedRow: View {
    let rank: Int
    let name: String
    let count: Int
    let share: Double

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text("\(rank).")
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                    .frame(minWidth: 28, alignment: .trailing)
                Text(name).lineLimit(1).truncationMode(.middle)
                Spacer()
                Text(count.formatted()).monospacedDigit()
            }
            ProgressView(value: min(max(share, 0), 1))
                .tint(Color.accentColor)
                .padding(.leading, 34)
        }
        .accessibilityElement(children: .combine)
    }
}

/// Renders a section this build has no purpose-built view for.
///
/// The relay treats section bodies as opaque and re-serves them byte for byte,
/// specifically so secman can add one without a relay release. This view is the
/// same bargain on the app side: a new section shows up as labelled rows after a
/// refresh rather than after a trip through App Review.
struct GenericSectionView: View {
    let value: RelayJSONValue?

    var body: some View {
        if let value {
            Section {
                ForEach(Self.rows(from: value)) { row in
                    Group {
                        if row.isHeader {
                            Text(row.label).font(.subheadline.weight(.semibold))
                        } else {
                            MetricRow(title: row.label, value: row.value)
                        }
                    }
                    .padding(.leading, CGFloat(row.depth) * 12)
                }
            } footer: {
                Text("This section is newer than the app. It is shown as the relay sent it.")
            }
        } else {
            ContentUnavailableView(
                "Not in this snapshot",
                systemImage: "questionmark.folder",
                description: Text("The relay lists this section but the current snapshot does not carry it.")
            )
        }
    }

    struct Row: Identifiable {
        let id: String
        let label: String
        let value: String
        let depth: Int
        /// A nested object or array announces itself before its members. Kept
        /// as a flag rather than inferred from an empty `value`, so a genuinely
        /// empty string in the data does not turn into a heading.
        var isHeader = false
    }

    static func rows(from value: RelayJSONValue) -> [Row] {
        var rows: [Row] = []
        flatten(value, label: "", path: "$", depth: 0, into: &rows)
        return rows
    }

    private static func flatten(_ value: RelayJSONValue, label: String, path: String, depth: Int, into rows: inout [Row]) {
        if let text = value.displayText {
            rows.append(Row(id: path, label: label, value: text, depth: depth))
            return
        }
        switch value {
        case .object(let members):
            // The root object has no label of its own, so its members sit at
            // the same depth rather than being indented under nothing.
            let childDepth = label.isEmpty ? depth : depth + 1
            if !label.isEmpty {
                rows.append(Row(id: path, label: label, value: "", depth: depth, isHeader: true))
            }
            for key in members.keys.sorted() {
                guard let member = members[key] else { continue }
                flatten(member, label: humanized(key), path: "\(path).\(key)", depth: childDepth, into: &rows)
            }
        case .array(let items):
            if !label.isEmpty {
                rows.append(Row(id: path, label: label, value: "", depth: depth, isHeader: true))
            }
            for (index, item) in items.enumerated() {
                flatten(item, label: "\(index + 1)", path: "\(path)[\(index)]", depth: depth + 1, into: &rows)
            }
        default:
            break
        }
    }

    /// `serversProcessed` -> `Servers processed`.
    static func humanized(_ key: String) -> String {
        var words = ""
        for character in key {
            if character.isUppercase, !words.isEmpty {
                words.append(" ")
                words.append(contentsOf: character.lowercased())
            } else {
                words.append(character)
            }
        }
        return words.prefix(1).uppercased() + words.dropFirst()
    }
}

struct MetricRow: View {
    let title: String
    let value: String

    var body: some View {
        LabeledContent(title) {
            Text(value).monospacedDigit()
        }
    }
}
