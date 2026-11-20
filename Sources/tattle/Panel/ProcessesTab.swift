import SwiftUI

struct ProcessesTab: View {
    let state: AppState
    @State private var sort = ProcessSnapshot.Sort.memory

    var body: some View {
        Group {
            if let snapshot = state.processes.snapshot {
                ProcessesList(snapshot: snapshot, sort: $sort, state: state)
            } else {
                ListPlaceholder(loading: "Reading processes", error: state.processes.error)
            }
        }
        .task(id: state.panelIsShowing) {
            guard state.panelIsShowing else { return }
            state.processes.beginReadings()
            // Memory moves and CPU is a difference between readings, so the list is
            // kept current while it is on screen. The first reading has no CPU, so the
            // next one follows after a second rather than a whole cycle.
            await state.processes.refresh()
            try? await Task.sleep(for: .seconds(1))
            while !Task.isCancelled {
                await state.processes.refresh()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
}

private struct ProcessesList: View {
    let snapshot: ProcessSnapshot
    @Binding var sort: ProcessSnapshot.Sort
    let state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: PanelLook.glass ? 6 : 12) {
                if PanelLook.glass {
                    // The columns' titles sort, as in Activity Monitor, and sit on the line
                    // just above the rows' figures.
                    // How many there are is at the bottom of the panel.
                    HStack(alignment: .lastTextBaseline, spacing: 0) {
                        Spacer(minLength: 12)
                        sortTitle(.memory).frame(width: 64, alignment: .trailing)
                        sortTitle(.cpu).frame(width: 44, alignment: .trailing)
                    }
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 10)
                    .padding(.trailing, 25)
                } else {
                    let summary = ListSummary(processes: snapshot)
                    HStack(alignment: .top, spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(summary.short)
                                .fontWeight(.semibold)
                                .accessibilityAddTraits(.isHeader)
                            Text(ListSummary.processesExplained)
                                .font(PanelFont.small)
                                .foregroundStyle(PanelColor.sub)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                        Picker("Sort by", selection: $sort) {
                            ForEach(ProcessSnapshot.Sort.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .controlSize(.small)
                        .frame(width: 120)
                    }
                    .padding(.horizontal, 4)
                    .padding(.top, 2)
                }
                // A reading that failed leaves the last one on screen.
                if let error = state.processes.error {
                    Text("The processes could not be read, so this list is from \(snapshot.takenAt.formatted(date: .omitted, time: .standard)). \(error)")
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.sub)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }
                CardRows(items: snapshot.groups(sortedBy: sort)) { group in
                    NavRow(route: group.members.count == 1 ? .process(group.members[0]) : .processGroup(group)) { GroupRow(group: group) }
                }
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 4)
        }
    }
}

extension ListSummary {
    static let processesExplained = "Each app with its helpers, each program with what it started. Everything that is part of macOS is one row."

    init(processes snapshot: ProcessSnapshot) {
        let count = "\(snapshot.groups.count) apps and programs, \(snapshot.items.count) processes"
        self.init(short: count, full: "\(count). \(Self.processesExplained)")
    }
}

private extension ProcessesList {
    /// A column's title: pressing it sorts by that column, and the arrow marks the one in use.
    func sortTitle(_ column: ProcessSnapshot.Sort) -> some View {
        Button {
            sort = column
        } label: {
            HStack(spacing: 2) {
                Text(column.rawValue)
                if sort == column {
                    Image(systemName: "chevron.down").font(.system(size: 7, weight: .bold)).accessibilityHidden(true)
                }
            }
            .foregroundStyle(sort == column ? .primary : .secondary)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(column == .cpu ? ResourcesLine.perCoreHelp : "Memory this row's processes hold now.")
        .accessibilityLabel(column.rawValue)
        // The value is what the accessibility tree's text shows, so the list's sort can be read
        // there as well as from the selected state.
        .accessibilityValue(sort == column ? "sorted" : "")
        .accessibilityAddTraits(sort == column ? .isSelected : [])
    }
}

/// Memory and CPU in fixed columns on the right of a row.
private struct UsageColumns: View {
    let memoryBytes: UInt64
    let cpu: Double?

    var body: some View {
        HStack(spacing: 0) {
            Text(ProcessItem.memoryText(memoryBytes))
                .frame(width: 64, alignment: .trailing)
            Text(cpu.map(ProcessItem.cpuText) ?? "\u{2013}")
                .frame(width: 44, alignment: .trailing)
        }
        .monospacedDigit()
        .foregroundStyle(PanelColor.sub)
    }
}

private struct GroupRow: View {
    let group: ProcessGroup

    var body: some View {
        HStack(spacing: 10) {
            IconTile(name: group.name, path: group.kind == .process ? nil : group.path, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(group.name).lineLimit(1)
                Text(subtitle)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            UsageColumns(memoryBytes: group.memoryBytes, cpu: group.cpu)
        }
        .frame(minHeight: 44)
    }

    private var subtitle: String {
        var parts = [group.members.count == 1 ? "1 process" : "\(group.members.count) processes"]
        if let text = group.signerText { parts.append(text) }
        return parts.joined(separator: " \u{00B7} ")
    }
}

private struct ProcessRow: View {
    let item: ProcessItem
    var depth = 0
    var showsDirectory = true

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name)
                    .lineLimit(1)
                Text("pid \(String(item.pid))" + (item.signerText.map { " \u{00B7} \($0)" } ?? ""))
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.sub)
                    .lineLimit(1)
                if showsDirectory, let directory = item.workingDirectoryText {
                    // The end of the path is the part that tells copies apart.
                    Text(directory)
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.sub)
                        .lineLimit(1)
                        .truncationMode(.head)
                }
            }
            .padding(.leading, CGFloat(min(depth, 6)) * 14)
            Spacer(minLength: 0)
            UsageColumns(memoryBytes: item.memoryBytes, cpu: item.cpu)
        }
        .padding(.vertical, 6)
    }
}

/// One row of a group's tree, which a card's rows are told apart by.
private struct TreeEntry: Identifiable {
    let item: ProcessItem
    let depth: Int
    let showsDirectory: Bool

    var id: Int32 { item.pid }
}

struct ProcessGroupDetail: View {
    let group: ProcessGroup
    let back: String
    let state: AppState
    @State private var actionError: String?
    @State private var armed = false

    /// The group as it is now; the one opened stays readable once it is gone.
    private var current: ProcessGroup? { state.processes.snapshot?.group(id: group.id) }

    var body: some View {
        let group = current ?? self.group
        let gone = current == nil
        DetailPage(back: back, title: group.name) {
            ItemHeader(name: group.name, path: group.kind == .process ? nil : group.path, signature: group.signature,
                       gone: gone ? "No longer running" : nil)
            if let key = group.explainKey {
                ExplainSection(request: ExplainRequest(kind: .process, key: key, facts: group.facts, isApplesProgram: group.isApplesProgram, identity: group.identity),
                               whyHere: group.whyHere(gone: gone), state: state)
            }
            FactsCard(facts: group.facts.filter { !ProcessDetail.headerFacts.contains($0.name) })
            VStack(alignment: .leading, spacing: 6) {
                SectionTitle(title: group.kind == .system ? "What macOS is running" : "Processes")
                CardRows(items: group.tree.map { TreeEntry(item: $0.item, depth: $0.depth, showsDirectory: $0.showsDirectory) }) { entry in
                    NavRow(route: .process(entry.item)) { ProcessRow(item: entry.item, depth: entry.depth, showsDirectory: entry.showsDirectory) }
                }
            }
        } bar: {
            QuitBar(path: group.path, item: gone ? nil : group.leader, name: group.name, state: state, error: $actionError, armed: $armed)
        }
    }
}

struct ProcessDetail: View {
    let item: ProcessItem
    let back: String
    let state: AppState
    @State private var actionError: String?
    @State private var armed = false

    /// Said by the line under the name.
    static let headerFacts: Set<String> = ["Signed by", "Team"]

    /// The process as it is now, so memory and CPU move; a pid reused by a new process
    /// counts as gone.
    private var current: ProcessItem? {
        guard let now = state.processes.snapshot?.item(pid: item.pid),
              abs(now.started.timeIntervalSince(item.started)) < 1 else { return nil }
        return now
    }

    var body: some View {
        let item = current ?? self.item
        let gone = current == nil
        DetailPage(back: back, title: item.name) {
            ItemHeader(name: item.name, signature: item.signature, gone: gone ? "No longer running" : nil)
            ExplainSection(request: ExplainRequest(kind: .process, key: item.explainKey, facts: item.facts, isApplesProgram: item.isApplesProgram, identity: item.identity),
                           whyHere: item.whyHere(gone: gone), state: state)
            FactsCard(facts: item.facts.filter { !Self.headerFacts.contains($0.name) })
        } bar: {
            QuitBar(path: item.path, item: gone ? nil : item, name: item.name, state: state, error: $actionError, armed: $armed)
        }
    }
}

/// Reveal on the left; on the right Quit, and Force Quit behind a second click, for the user's
/// own processes. `item` is nil once the process is gone.
private struct QuitBar: View {
    let path: String?
    let item: ProcessItem?
    let name: String
    let state: AppState
    @Binding var error: String?
    @Binding var armed: Bool

    var body: some View {
        let canQuit = item.map { ProcessControl.canQuit(uid: $0.uid) } ?? false
        if path != nil || item != nil {
            ActionBar(note: note(canQuit: canQuit), error: error) {
                if let path { RevealButton(path: path) }
            } right: {
                if let item, canQuit {
                    if armed {
                        Button("Cancel") { armed = false }
                        Button("Force Quit \(name)") {
                            armed = false
                            perform { try ProcessControl.forceQuit(pid: item.pid, uid: item.uid) }
                        }
                        .buttonStyle(.panelDanger)
                    } else {
                        Button("Quit \(name)") { perform { try ProcessControl.quit(pid: item.pid, uid: item.uid) } }
                        Button("Force Quit\u{2026}") { armed = true }
                    }
                }
            }
        }
    }

    private func note(canQuit: Bool) -> String? {
        guard let item else { return nil }
        if !canQuit { return ProcessControl.whyNoQuit(uid: item.uid) }
        return armed ? "Unsaved work is lost." : nil
    }

    private func perform(_ action: @MainActor () throws -> Void) {
        do {
            try action()
            error = nil
        } catch {
            self.error = String(describing: error)
            return
        }
        // Show the result sooner than the three-second cycle would.
        Task {
            try? await Task.sleep(for: .milliseconds(500))
            await state.processes.refresh()
        }
    }
}

extension ProcessGroup: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

extension ProcessItem: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(pid) }
}
