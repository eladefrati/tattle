import SwiftUI

struct StartupTab: View {
    let state: AppState

    var body: some View {
        Group {
            if let snapshot = state.startup.snapshot {
                StartupList(snapshot: snapshot, state: state)
            } else {
                ListPlaceholder(loading: "Reading startup items")
            }
        }
        .task(id: state.panelIsShowing) {
            // Read each time the list comes on screen, like Ports and Processes; the last
            // reading stays up meanwhile. Startup items rarely change under it, so not again
            // while it is watched.
            guard state.panelIsShowing else { return }
            await state.startup.refresh()
        }
    }
}

private struct StartupList: View {
    let snapshot: StartupSnapshot
    let state: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let error = snapshot.loginItemsError {
                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(error)
                                .lineSpacing(2)
                                .fixedSize(horizontal: false, vertical: true)
                            if snapshot.loginItemsNeedFullDiskAccess {
                                Button("Open Full Disk Access Settings") {
                                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                                        NSWorkspace.shared.open(url)
                                    }
                                }
                                .buttonStyle(.panelPrimary)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                    }
                }
                let shown = StartupItem.Group.allCases.filter { !snapshot.items(in: $0).isEmpty }
                ForEach(shown, id: \.self) { group in
                    let items = snapshot.items(in: group)
                    if !items.isEmpty {
                        PanelSection(title: group.title, description: group.description, follows: group != shown.first) {
                            CardRows(items: items) { item in
                                NavRow(route: .startupItem(item)) { StartupRow(item: item) }
                            }
                        }
                    }
                }
                Card {
                    HStack {
                        Text("Apple")
                        Spacer()
                        Text("\(snapshot.appleCount) system jobs").foregroundStyle(PanelColor.sub)
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 44)
                    .accessibilityElement(children: .combine)
                }
                HStack {
                    Spacer()
                    Button {
                        Task { await state.startup.refresh() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .foregroundStyle(PanelColor.sub)
                            .frame(width: 24, height: 24)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Refresh")
                    .disabled(state.startup.isLoading)
                }
                .padding(.horizontal, 4)
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 4)
        }
    }
}

extension ListSummary {
    init(startup snapshot: StartupSnapshot) {
        let running = snapshot.items.filter { if case .running = $0.state { true } else { false } }.count
        let items = "\(snapshot.items.count) \(snapshot.items.count == 1 ? "item" : "items")"
        self.init(short: "\(items) \u{00B7} \(running) running",
                  full: "\(items) that start by themselves, \(running) running now, and \(snapshot.appleCount) system jobs of Apple's")
    }
}

private struct StartupRow: View {
    let item: StartupItem

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(item.state.isActive ? PanelColor.ok : PanelColor.track)
                .frame(width: 8, height: 8)
                .padding(.horizontal, 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.name).lineLimit(1).truncationMode(.middle)
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
        var parts = [item.trigger ?? "unknown", item.state.text]
        if let signature = item.signature { parts.append(signature.summary) }
        else if let developer = item.developer { parts.append(developer) }
        return parts.joined(separator: " \u{00B7} ")
    }
}

struct StartupDetail: View {
    let item: StartupItem
    let back: String
    let state: AppState
    @State private var actionError: String?

    /// Said by the line under the name.
    private static let headerFacts: Set<String> = ["Signed by", "Team"]

    /// The row as it is after a refresh, so an action's effect shows without going back; the
    /// one opened stays readable once it is gone.
    private var current: StartupItem? {
        state.startup.snapshot?.items.first { $0.id == item.id }
    }

    var body: some View {
        let item = current ?? self.item
        let gone = current == nil
        DetailPage(back: back, title: item.name) {
            ItemHeader(name: item.name, path: item.program, signature: item.signature, gone: gone ? "No longer installed" : nil)
            if item.canExplain {
                ExplainSection(request: ExplainRequest(kind: .launchItem, key: item.explainKey, facts: item.facts, identity: item.identity),
                               whyHere: item.whyHere(gone: gone), state: state)
            }
            FactsCard(facts: item.facts.filter { item.signature == nil || !Self.headerFacts.contains($0.name) })
        } bar: {
            let daemon = !gone && Self.needsRoot(item)
            if item.plistURL != nil || item.isLoginItem || !gone {
                ActionBar(note: daemon ? "Loading or unloading a daemon needs root" : Self.heldNote(item, gone: gone), error: actionError) {
                    if let plist = item.plistURL {
                        Button(item.isUnlistedFolder ? "Reveal Folder" : "Reveal Plist") { NSWorkspace.shared.activateFileViewerSelecting([plist]) }
                    }
                    if item.isLoginItem {
                        Button("Login Items Settings") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                    }
                } right: {
                    if !gone { controls(item) }
                }
            }
        }
    }

    /// launchd refuses to load a plist while another plist's job holds its label.
    private static func heldNote(_ item: StartupItem, gone: Bool) -> String? {
        guard !gone, item.labelHeldBy != nil, item.state == .notLoaded else { return nil }
        return "Another plist's job holds this label, so launchd will not load this one"
    }

    /// A daemon that is not Tattle's own broker: launchd lets only root load or unload it.
    private static func needsRoot(_ item: StartupItem) -> Bool {
        guard let scope = item.launchdScope, item.plistURL != nil, !item.isCaptureBroker else { return false }
        return !Launchctl.canControl(scope)
    }

    @ViewBuilder
    private func controls(_ item: StartupItem) -> some View {
        if let scope = item.launchdScope, let plist = item.plistURL {
            if item.isCaptureBroker {
                // Removed through the administrator dialog.
                Button("Remove") {
                    actionError = nil
                    Task {
                        if await !state.network.removeBroker() { actionError = state.network.accessError }
                        await state.startup.refresh()
                    }
                }
                .disabled(state.network.accessBusy)
            } else if Launchctl.canControl(scope) {
                switch item.state {
                case .notLoaded where item.labelHeldBy == nil:
                    Button("Load") { perform { try Launchctl.load(plist: plist, in: item.launchDomain) } }
                case .running, .idle:
                    Button("Unload") { perform { try Launchctl.unload(label: item.label, in: item.launchDomain, from: plist) } }
                case .notLoaded, .disabled, .placeholder, .enabled, .off, .notTurnedOn, .unreadable, .unlisted, .unknown:
                    EmptyView()
                }
            }
        }
    }

    /// Off the main thread: removing the broker waits on the administrator dialog.
    private func perform(_ action: @escaping @Sendable () throws -> Void) {
        actionError = nil
        Task {
            do {
                try await Task.detached { try action() }.value
                await state.startup.refresh()
            } catch Launchctl.ControlError.failed(_, let message) {
                actionError = message
            } catch {
                actionError = String(describing: error)
            }
        }
    }
}

extension StartupItem: Hashable {
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}
