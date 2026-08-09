import SecmanRelayKit
import SwiftUI

/// The status screen.
///
/// A `NavigationSplitView` so the same code is a sidebar on iPad and a stack on
/// iPhone. The sidebar is built from `session.sections` — the server's answer to
/// "what may this device read" — so a user with only VULN sees one entry and an
/// admin sees six, with no client-side role logic anywhere.
struct StatusView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: RelaySection?

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                if let snapshot = model.snapshot, snapshot.stale {
                    StaleBanner(ageSeconds: snapshot.ageSeconds)
                }
                ForEach(model.visibleSections, id: \.self) { section in
                    NavigationLink(value: section) {
                        Label(section.displayName, systemImage: icon(for: section))
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
        .onAppear {
            if selection == nil { selection = model.visibleSections.first }
        }
    }

    private func icon(for section: RelaySection) -> String {
        switch section {
        case .totals: return "square.grid.2x2"
        case .kpis: return "gauge.with.needle"
        case .exceptions: return "exclamationmark.triangle"
        case .imports: return "arrow.down.circle"
        case .topProducts: return "shippingbox"
        case .topServers: return "server.rack"
        }
    }
}

/// Stale data is labelled, never hidden.
///
/// The relay serves the last snapshot it has along with its age, because on an
/// incident call "42 minutes old" is far more useful than an empty screen — and
/// far safer than an unlabelled number that looks current.
struct StaleBanner: View {
    let ageSeconds: Int

    var body: some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text("Data is \(formatted) old").font(.subheadline.weight(.semibold))
                Text("secman has not pushed an update recently.").font(.caption)
            }
        } icon: {
            Image(systemName: "clock.badge.exclamationmark")
        }
        .foregroundStyle(.orange)
        .listRowBackground(Color.orange.opacity(0.12))
    }

    private var formatted: String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .abbreviated
        formatter.maximumUnitCount = 2
        return formatter.string(from: TimeInterval(ageSeconds)) ?? "\(ageSeconds)s"
    }
}

struct SectionDetailView: View {
    @Environment(AppModel.self) private var model
    let section: RelaySection

    var body: some View {
        List {
            if let snapshot = model.snapshot {
                content(for: snapshot)
                Section {
                    LabeledContent("Generated", value: snapshot.generatedAt.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Instance", value: snapshot.instanceId)
                } header: {
                    Text("Source")
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
        switch section {
        case .totals:
            if let totals = try? snapshot.decode(RelayTotalsSection.self, section: section.rawValue), let totals {
                Section {
                    MetricRow(title: "Assets", value: "\(totals.assets)")
                    MetricRow(title: "Vulnerabilities", value: "\(totals.vulnerabilities)")
                    MetricRow(title: "Users", value: "\(totals.users)")
                }
            }

        case .kpis:
            if let kpis = try? snapshot.decode(RelayKpisSection.self, section: section.rawValue), let kpis {
                Section("AWS clean servers") {
                    // `available: false` means "not measured yet", which is not
                    // the same as 0% and must never be rendered as such.
                    if kpis.awsCleanServers.available, let percentage = kpis.awsCleanServers.percentage {
                        MetricRow(title: "No finding older than 30 days", value: percentage.formatted(.percent.precision(.fractionLength(1)).scale(1)))
                        if let total = kpis.awsCleanServers.totalServers, let clean = kpis.awsCleanServers.cleanServers {
                            MetricRow(title: "Clean / total", value: "\(clean) / \(total)")
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                }
                Section("EDR coverage") {
                    if kpis.edrCoverage.available, let percentage = kpis.edrCoverage.percentage {
                        MetricRow(title: "EC2 instances with a sensor", value: percentage.formatted(.percent.precision(.fractionLength(1)).scale(1)))
                        if let covered = kpis.edrCoverage.coveredInstances, let eligible = kpis.edrCoverage.eligibleInstances {
                            MetricRow(title: "Covered / eligible", value: "\(covered) / \(eligible)")
                        }
                        if let excluded = kpis.edrCoverage.excludedByException, excluded > 0 {
                            MetricRow(title: "Excluded by exception", value: "\(excluded)")
                        }
                    } else {
                        Text("Not calculated yet").foregroundStyle(.secondary)
                    }
                }
            }

        case .exceptions:
            if let exceptions = try? snapshot.decode(RelayExceptionsSection.self, section: section.rawValue), let exceptions {
                Section {
                    MetricRow(title: "Awaiting review", value: "\(exceptions.pending)")
                } footer: {
                    Text("Review and approval happen in secman. This app is read-only.")
                }
            }

        case .imports:
            if let imports = try? snapshot.decode(RelayImportsSection.self, section: section.rawValue), let imports {
                Section("CrowdStrike") {
                    if imports.crowdstrike.available {
                        if let at = imports.crowdstrike.importedAt {
                            MetricRow(title: "Last import", value: at)
                        }
                        if let servers = imports.crowdstrike.serversProcessed {
                            MetricRow(title: "Servers processed", value: "\(servers)")
                        }
                        if let vulns = imports.crowdstrike.vulnerabilitiesImported {
                            MetricRow(title: "Vulnerabilities imported", value: "\(vulns)")
                        }
                        if let errors = imports.crowdstrike.errorCount, errors > 0 {
                            MetricRow(title: "Errors", value: "\(errors)").foregroundStyle(.red)
                        }
                    } else {
                        Text("No import has run yet").foregroundStyle(.secondary)
                    }
                }
            }

        case .topProducts, .topServers:
            if let list = try? snapshot.decode(RelayTopListSection.self, section: section.rawValue), let list {
                Section {
                    ForEach(list.items) { item in
                        MetricRow(title: item.name, value: "\(item.vulnerabilities)")
                    }
                }
            }
        }
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
