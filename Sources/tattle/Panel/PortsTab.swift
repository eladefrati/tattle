import SwiftUI

struct PortsTab: View {
    let state: AppState

    var body: some View {
        Group {
            if let snapshot = state.ports.snapshot {
                PortsList(snapshot: snapshot)
            } else {
                ListPlaceholder(loading: "Reading listening ports", error: state.ports.error)
            }
        }
        .task(id: state.panelIsShowing) {
            guard state.panelIsShowing else { return }
            // Ports come and go; keep the list current while it is on screen.
            while !Task.isCancelled {
                await state.ports.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

private struct PortsList: View {
    let snapshot: PortsSnapshot

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                let shown = PortItem.Group.allCases.filter { !snapshot.items(in: $0).isEmpty }
                ForEach(shown, id: \.self) { group in
                    let items = snapshot.items(in: group)
                    if !items.isEmpty {
                        PanelSection(title: group.title, description: group.description, follows: group != shown.first) {
                            CardRows(items: items) { item in
                                NavRow(route: .port(item)) { PortRow(item: item) }
                            }
                        }
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 4)
        }
    }
}

extension ListSummary {
    init(ports snapshot: PortsSnapshot) {
        let reachable = snapshot.items(in: .network).count
        let groups = PortItem.Group.allCases.compactMap { group -> String? in
            let count = snapshot.items(in: group).count
            return count == 0 ? nil : "\(count) \(group.title.prefix(1).lowercased() + group.title.dropFirst())"
        }
        var few = ["\(snapshot.items.count) listening"]
        if reachable > 0 { few.append("\(reachable) reachable from your network") }
        self.init(short: few.joined(separator: " \u{00B7} "),
                  full: groups.isEmpty ? few[0] : "\(snapshot.items.count) listening: \(groups.joined(separator: ", "))")
    }
}

private struct PortRow: View {
    let item: PortItem

    var body: some View {
        HStack(spacing: 10) {
            Text(String(item.port))
                .fontWeight(.semibold)
                .monospacedDigit()
                .frame(width: 44, alignment: .trailing)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.processName).lineLimit(1)
                Text(subtitle)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .frame(minHeight: 44)
    }

    private var subtitle: String {
        var parts = [item.proto.rawValue.uppercased(), item.binding.text]
        if let signature = item.signature { parts.append(signature.summary) }
        return parts.joined(separator: " \u{00B7} ")
    }
}

struct PortDetail: View {
    let item: PortItem
    let back: String
    let state: AppState
    @State private var actionError: String?

    /// Said by the line under the name.
    private static let headerFacts: Set<String> = ["Signed by", "Team"]

    /// Whether the port is still in the latest snapshot. The facts shown are the ones
    /// from when the row was opened; a port that closed stays readable.
    private var isGone: Bool {
        guard let snapshot = state.ports.snapshot else { return false }
        return !snapshot.items.contains { $0.id == item.id }
    }

    var body: some View {
        let canQuit = ProcessControl.canQuit(uid: item.uid)
        DetailPage(back: back, title: String(item.port)) {
            ItemHeader(name: "\(item.processName) on \(String(item.port)) \(item.proto.rawValue.uppercased())",
                       signature: item.signature, gone: isGone ? "No longer listening" : nil)
            ExplainSection(request: ExplainRequest(kind: .port, key: item.explainKey, facts: item.facts, isApplesProgram: item.isApplesProgram, identity: item.identity),
                           whyHere: item.whyHere(gone: isGone), state: state)
            FactsCard(facts: item.facts.filter { !Self.headerFacts.contains($0.name) })
        } bar: {
            if item.process?.path != nil || !isGone {
                ActionBar(note: isGone || canQuit ? nil : ProcessControl.whyNoQuit(uid: item.uid), error: actionError) {
                    if let path = item.process?.path { RevealButton(path: path) }
                } right: {
                    if !isGone, canQuit {
                        Button("Quit \(item.processName)") { quit() }
                    }
                }
            }
        }
    }

    private func quit() {
        do {
            try ProcessControl.quit(pid: item.pid, uid: item.uid)
            actionError = nil
        } catch {
            actionError = String(describing: error)
            return
        }
        // Show the result sooner than the five-second cycle would.
        Task {
            try? await Task.sleep(for: .milliseconds(500))
            await state.ports.refresh()
        }
    }
}

extension PortItem: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
