import SwiftUI

struct NetworkTab: View {
    let state: AppState

    var body: some View {
        if let snapshot = state.panelNetworkSnapshot {
            ConnectionsList(snapshot: snapshot, captureStatus: state.network.captureStatus, state: state)
        } else {
            ListPlaceholder(loading: "Reading connections", error: state.network.error)
        }
    }
}

private struct ConnectionsList: View {
    let snapshot: NetworkSnapshot
    let captureStatus: Sniffer.Status
    let state: AppState

    var body: some View {
        let fresh = snapshot.connections.filter(\.isNew).sorted { $0.connection.firstSeen > $1.connection.firstSeen }
        let seen = NetworkSnapshot(connections: snapshot.connections.filter { !$0.isNew }, takenAt: snapshot.takenAt)
        let summary = ListSummary(network: snapshot, observer: state.network)
        VStack(alignment: .leading, spacing: 0) {
            // On glass the summary is at the bottom of the panel, and only what went wrong
            // stays above the list.
            if let line = PanelLook.glass ? state.network.accessError : summary.full {
                Text(line)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 12 + PanelLook.titleInset)
                    .padding(.bottom, 10)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if !fresh.isEmpty {
                        PanelSection(title: "First contact", marked: true) {
                            CardRows(items: fresh) { live in
                                NavRow(route: .connection(live)) { FirstContactRow(live: live, now: snapshot.takenAt, state: state) }
                            }
                        }
                    }
                    if !seen.connections.isEmpty {
                        PanelSection(title: "Seen before", trailing: seen.connections.count == 1 ? "1 connection" : "\(seen.connections.count) connections",
                                     follows: !fresh.isEmpty) {
                            CardRows(items: seen.groups) { group in
                                // The page is the app's, with every connection it has open.
                                NavRow(route: .connectionGroup(snapshot.group(id: group.id) ?? group)) { ConnectionGroupRow(group: group) }
                            }
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 4)
            }
        }
    }
}

extension ListSummary {
    @MainActor
    init(network snapshot: NetworkSnapshot, observer network: NetworkObserver) {
        let groups = snapshot.groups.count
        let apps = "\(groups) \(groups == 1 ? "app" : "apps")"
        var parts = ["\(snapshot.connections.count) open from \(apps)"]
        var few = ["\(snapshot.connections.count) open", apps]
        if snapshot.preExistingCount > 0 { parts.append("\(snapshot.preExistingCount) open since before Tattle started") }
        switch network.captureStatus {
        case .capturing:
            var named: [String] = []
            if snapshot.namedCount > 0 { named.append("\(snapshot.namedCount) named") }
            if snapshot.dnsCount > 0 { named.append("\(snapshot.dnsCount) from DNS") }
            if snapshot.relayedCount > 0 { named.append("\(snapshot.relayedCount) relayed") }
            if snapshot.hiddenCount > 0 { named.append("\(snapshot.hiddenCount) with the name hidden") }
            parts.append(named.isEmpty ? "Names appear as connections open" : named.joined(separator: ", "))
            if snapshot.namedCount > 0 { few.append("\(snapshot.namedCount) named") }
            if let error = network.accessError { parts.append(error) }
        case .unavailable, .stopped:
            parts.append(PacketAccessView.namesOff(network.broker.installation))
        }
        self.init(short: few.joined(separator: " \u{00B7} "), full: parts.joined(separator: " \u{00B7} "))
    }
}

/// A connection to an address this Mac has not reached before: who opened it, where to, and
/// what is known of the destination.
private struct FirstContactRow: View {
    let live: LiveConnection
    let now: Date
    let state: AppState
    @State private var rule: Rule?

    var body: some View {
        HStack(spacing: 10) {
            IconTile(name: live.owner.displayName, path: live.owner.app?.path, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                (Text("\(live.owner.displayName) to ").foregroundStyle(PanelColor.sub) + Text(live.title).fontWeight(.medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let known {
                    Text(known)
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.sub)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 0)
            Text(LiveConnection.ago(live.connection.firstSeen, now: now))
                .font(PanelFont.small)
                .monospacedDigit()
                .foregroundStyle(PanelColor.sub)
        }
        .padding(.vertical, 7)
        .frame(minHeight: 44)
        .task(id: live.explainKey) {
            rule = try? await state.explainer.lookup(ExplainRequest(kind: .host, key: live.explainKey, facts: []))
        }
    }

    /// What the knowledge base says of the destination, in a line; without an answer, only
    /// why the row shows a bare address.
    private var known: String? {
        guard let rule else { return live.name == nil ? "No name seen" : nil }
        if rule.source == .llm { return rule.sourceText }
        return "\(rule.purpose) \u{00B7} \(rule.sourceText)"
    }
}

private struct ConnectionGroupRow: View {
    let group: ConnectionGroup

    var body: some View {
        HStack(spacing: 10) {
            IconTile(name: group.name, path: group.connections.first?.owner.app?.path)
            VStack(alignment: .leading, spacing: 0) {
                Text(group.name).lineLimit(1)
                Text(subtitle)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Text(String(group.connections.count))
                .monospacedDigit()
                .foregroundStyle(PanelColor.sub)
        }
        .frame(minHeight: 38)
    }

    private var subtitle: String {
        var parts = group.reachSummary
        if let signature = group.signature { parts.append(signature.summary) }
        return parts.joined(separator: " \u{00B7} ")
    }
}

private struct ConnectionRow: View {
    let live: LiveConnection
    let now: Date

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(live.title).fontWeight(.medium).monospacedDigit().lineLimit(1).truncationMode(.middle)
                    if live.isNew { Pill(text: "new", kind: .new) }
                    if live.isFromDNS { Pill(text: "from DNS") }
                    if live.connection.direction == .inbound { Pill(text: "incoming") }
                }
                Text(subtitle)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Text(live.connection.preExisting ? "already open" : LiveConnection.ago(live.connection.firstSeen, now: now))
                .font(PanelFont.small)
                .monospacedDigit()
                .foregroundStyle(PanelColor.sub)
        }
        .padding(.vertical, 7)
    }

    private var subtitle: String {
        var parts: [String] = []
        if live.name != nil { parts.append(live.destination) }
        parts.append(live.connection.proto.rawValue.uppercased())
        if let state = live.connection.stateText { parts.append(state) }
        if live.connection.scope == .local { parts.append("this network") }
        if live.owner.app != nil, live.owner.processName != live.owner.displayName { parts.append(live.owner.processName) }
        return parts.joined(separator: " \u{00B7} ")
    }
}

struct ConnectionGroupDetail: View {
    let group: ConnectionGroup
    let back: String
    let state: AppState

    /// The group as it is now; gone once its last connection closed.
    private var current: ConnectionGroup? { state.panelNetworkSnapshot?.group(id: group.id) }

    var body: some View {
        let group = current ?? self.group
        let gone = current == nil
        let now = state.panelNetworkSnapshot?.takenAt ?? Date()
        let facts = group.facts(gone: gone)
        let path = group.connections.first?.owner.app?.path ?? group.connections.first?.owner.path
        DetailPage(back: back, title: group.name) {
            ItemHeader(name: group.name, path: group.connections.first?.owner.app?.path, signature: group.signature,
                       gone: gone ? "No open connections now" : nil) {
                if let path { RevealButton(path: path) }
            }
            // The same key as the Processes tab, so an explanation of the program
            // given there is shown here and the other way round.
            ExplainSection(request: ExplainRequest(kind: .process, key: group.name, facts: facts,
                                                     isApplesProgram: group.isApplesProgram, identity: group.identity),
                           whyHere: group.whyHere(gone: gone), state: state)
            CountsCard(facts: facts.filter { !Self.headerFacts.contains($0.name) })
            VStack(alignment: .leading, spacing: 6) {
                SectionTitle(title: "Connections")
                CardRows(items: group.connections) { live in
                    NavRow(route: .connection(live)) { ConnectionRow(live: live, now: now) }
                }
            }
        } bar: {
            EmptyView()
        }
    }

    /// Said by the line under the name.
    private static let headerFacts: Set<String> = ["Signed by", "Team"]
}

/// A few counts side by side.
private struct CountsCard: View {
    let facts: [Fact]

    var body: some View {
        Card {
            HStack(spacing: 0) {
                ForEach(Array(facts.enumerated()), id: \.offset) { index, fact in
                    if index > 0 { Rectangle().fill(PanelColor.line).frame(width: 1) }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(fact.name).font(PanelFont.label).foregroundStyle(PanelColor.sub)
                        Text(fact.value).fontWeight(.semibold).monospacedDigit()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityElement(children: .combine)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct ConnectionDetail: View {
    let live: LiveConnection
    let back: String
    let state: AppState

    /// The connection as it is now; the one opened stays readable once it has closed.
    private var current: LiveConnection? { state.panelNetworkSnapshot?.connection(id: live.id) }

    var body: some View {
        let live = current ?? self.live
        let now = state.panelNetworkSnapshot?.takenAt ?? Date()
        DetailPage(back: back, title: live.title) {
            if let path = live.owner.app?.path ?? live.owner.path { RevealButton(path: path) }
        } content: {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(live.title).font(PanelFont.title).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                    if live.isNew { Pill(text: "new", kind: .new) }
                    if current == nil { Pill(text: "Closed") }
                }
                Text(Self.opened(live, now: now))
                    .font(PanelFont.button)
                    .foregroundStyle(PanelColor.sub)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 4)
            ExplainSection(request: ExplainRequest(kind: .host, key: live.explainKey, facts: live.facts(now: now)), whyHere: live.whyHere, state: state)
            FactsCard(facts: live.facts(now: now))
        } bar: {
            EmptyView()
        }
    }

    /// Who holds the connection and since when, under its name.
    static func opened(_ live: LiveConnection, now: Date) -> String {
        let owner = live.owner.displayName
        let since = live.connection.preExisting ? "before Tattle started" : LiveConnection.ago(live.connection.firstSeen, now: now)
        let line = switch live.connection.direction {
        case .outbound: "Opened by \(owner) \(since)"
        case .inbound: "Came in to \(owner) \(since)"
        case .unknown: "Held by \(owner), seen \(since)"
        }
        return live.isNew ? line + " \u{00B7} first time this Mac has contacted it" : line
    }
}

extension ConnectionGroup: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

extension LiveConnection: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
