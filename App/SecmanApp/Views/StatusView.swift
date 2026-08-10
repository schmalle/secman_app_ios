import SecmanRelayKit
import SwiftUI

/// The status screen.
///
/// A `NavigationSplitView` so the same code is a sidebar on iPad and a stack on
/// iPhone. The list is built from the relay's answer to "what may this device
/// read" — so a user with only VULN sees one entry and an admin sees six, with
/// no client-side role logic anywhere.
struct StatusView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var selection: RelaySectionID?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                if let meta = model.meta, meta.stale {
                    StaleBanner(ageSeconds: meta.ageSeconds, maxAgeSeconds: meta.maxAgeSeconds)
                }
                ForEach(model.visibleSections) { section in
                    NavigationLink(value: section) {
                        Label(section.displayName, systemImage: section.symbolName)
                    }
                }
                if model.visibleSections.isEmpty {
                    ContentUnavailableView(
                        "Nothing to show",
                        systemImage: "lock",
                        description: Text("Your secman roles do not grant access to any of the sections this relay publishes.")
                    )
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

/// Stale data is labelled, never hidden.
///
/// The relay serves the last snapshot it has along with its age, because on an
/// incident call "42 minutes old" is far more useful than an empty screen — and
/// far safer than an unlabelled number that looks current.
struct StaleBanner: View {
    let ageSeconds: Int
    /// The relay's own threshold, so the explanation quotes the deployment's
    /// number rather than a constant compiled into the app.
    let maxAgeSeconds: Int

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text("Data is \(Self.duration(ageSeconds)) old").font(.subheadline.weight(.semibold))
                Text("secman has not pushed an update in the last \(Self.duration(maxAgeSeconds)).")
                    .font(.caption)
            }
        } icon: {
            Image(systemName: "clock.badge.exclamationmark")
        }
        .foregroundStyle(.orange)
        .listRowBackground(Color.orange.opacity(0.12))
    }

    static func duration(_ seconds: Int) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .abbreviated
        formatter.maximumUnitCount = 2
        return formatter.string(from: TimeInterval(seconds)) ?? "\(seconds)s"
    }
}

struct SectionDetailView: View {
    @Environment(AppModel.self) private var model
    let section: RelaySectionID

    var body: some View {
        List {
            if let snapshot = model.snapshot {
                content(for: snapshot)
                Section("Source") {
                    LabeledContent("Generated", value: snapshot.generatedAt.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Instance", value: snapshot.instanceId)
                }
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
                }
            }

        case .kpis:
            typed(RelayKpisSection.self, from: snapshot) { kpis in
                Section("AWS clean servers") {
                    // `available: false` means "not measured yet", which is not
                    // the same as 0% and must never be rendered as such.
                    if kpis.awsCleanServers.available, let percentage = kpis.awsCleanServers.percentage {
                        MetricRow(title: "No finding older than 30 days", value: Self.percent(percentage))
                        if let total = kpis.awsCleanServers.totalServers, let clean = kpis.awsCleanServers.cleanServers {
                            MetricRow(title: "Clean / total", value: "\(clean) / \(total)")
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                }
                Section("EDR coverage") {
                    if kpis.edrCoverage.available, let percentage = kpis.edrCoverage.percentage {
                        MetricRow(title: "EC2 instances with a sensor", value: Self.percent(percentage))
                        if let covered = kpis.edrCoverage.coveredInstances, let eligible = kpis.edrCoverage.eligibleInstances {
                            MetricRow(title: "Covered / eligible", value: "\(covered) / \(eligible)")
                        }
                        if let excluded = kpis.edrCoverage.excludedByException, excluded > 0 {
                            MetricRow(title: "Excluded by exception", value: excluded.formatted())
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                }
            }

        case .exceptions:
            typed(RelayExceptionsSection.self, from: snapshot) { exceptions in
                Section {
                    MetricRow(title: "Awaiting review", value: exceptions.pending.formatted())
                } footer: {
                    Text("Review and approval happen in secman. This app is read-only.")
                }
            }

        case .imports:
            typed(RelayImportsSection.self, from: snapshot) { imports in
                Section("CrowdStrike") {
                    if imports.crowdstrike.available {
                        if let at = imports.crowdstrike.importedAt {
                            MetricRow(title: "Last import", value: at)
                        }
                        if let servers = imports.crowdstrike.serversProcessed {
                            MetricRow(title: "Servers processed", value: servers.formatted())
                        }
                        if let vulns = imports.crowdstrike.vulnerabilitiesImported {
                            MetricRow(title: "Vulnerabilities imported", value: vulns.formatted())
                        }
                        if let errors = imports.crowdstrike.errorCount, errors > 0 {
                            MetricRow(title: "Errors", value: errors.formatted()).foregroundStyle(.red)
                        }
                    } else {
                        Text("No import has run yet").foregroundStyle(.secondary)
                    }
                }
            }

        case .topProducts, .topServers:
            typed(RelayTopListSection.self, from: snapshot) { list in
                Section {
                    ForEach(list.items) { item in
                        MetricRow(title: item.name, value: item.vulnerabilities.formatted())
                    }
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

    private static func percent(_ value: Double) -> String {
        value.formatted(.percent.precision(.fractionLength(1)).scale(1))
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
