import SwiftUI

/// A page pushed over a tab's list.
enum PanelRoute: Hashable {
    case connectionGroup(ConnectionGroup)
    case connection(LiveConnection)
    case packetAccess
    case processGroup(ProcessGroup)
    case process(ProcessItem)
    case port(PortItem)
    case startupItem(StartupItem)

    /// What the page after this one names on its way back.
    var title: String {
        switch self {
        case .connectionGroup(let group): group.name
        case .connection(let live): live.title
        case .packetAccess: "Packet access"
        case .processGroup(let group): group.name
        case .process(let item): item.name
        case .port(let item): String(item.port)
        case .startupItem(let item): item.name
        }
    }
}

/// The pages open over the list, oldest first, and the groups folded away in the lists.
@MainActor @Observable
final class PanelRouter {
    var path: [PanelRoute] = []
    /// The titles of the groups whose rows are folded away, kept while the app runs.
    var folded: Set<String> = []

    func push(_ route: PanelRoute) { path.append(route) }
    func pop() { if !path.isEmpty { path.removeLast() } }
}

/// The window that drops down from the menu bar item.
struct PanelView: View {
    enum Tab: String, CaseIterable, Identifiable {
        case network = "Network"
        case processes = "Processes"
        case ports = "Ports"
        case startup = "Startup"

        var id: String { rawValue }

        var symbol: String {
            switch self {
            case .network: "globe"
            case .processes: "cpu"
            case .ports: "door.left.hand.open"
            // On glass the power symbol is Quit's, at the bottom of the panel.
            case .startup: PanelLook.glass ? "sun.max" : "power"
            }
        }
    }

    let state: AppState
    @State private var tab = Tab.network
    @State private var router = PanelRouter()
    @Namespace private var tabSelection
    @Environment(\.openSettings) private var openSettings
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: 0) {
            // Every page stays alive under the one on top, so a list keeps reading and keeps
            // its place while a page is open over it.
            // On glass a page slides in over the one it came from, which steps aside.
            let slides = PanelLook.glass && !reduceMotion
            ZStack {
                list.shown(router.path.isEmpty)
                    .offset(x: slides && !router.path.isEmpty ? -Self.stepAside : 0)
                ForEach(Array(router.path.enumerated()), id: \.offset) { index, route in
                    let top = index == router.path.count - 1
                    page(route, back: index == 0 ? tab.rawValue : router.path[index - 1].title)
                        .shown(top)
                        .offset(x: slides && !top ? -Self.stepAside : 0)
                        .transition(slides ? .move(edge: .trailing).combined(with: .opacity) : .identity)
                }
            }
            .animation(slides ? .snappy(duration: 0.28) : nil, value: router.path.count)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            if PanelLook.glass { RowLine().padding(.horizontal, 12) }
            footer
        }
        .environment(router)
        .font(.system(size: 13))
        .foregroundStyle(PanelColor.text)
        .frame(width: 480, height: 636)
        .background(PanelColor.background)
        .background(WindowOnScreenReader { state.panelIsShowing = $0 })
    }

    /// How far a page moves to the side when another opens over it.
    private static let stepAside: CGFloat = 60

    private var list: some View {
        VStack(spacing: 0) {
            ResourcesLine(sample: state.panelSample)
                .padding(.horizontal, 12)
                .padding(.top, PanelLook.glass ? 16 : 12)
            Group {
                if #available(macOS 26.0, *) { glassTabs } else { tabs }
            }
            .padding(.horizontal, PanelLook.glass ? 16 : 12)
            .padding(.top, PanelLook.glass ? 14 : 10)
            .padding(.bottom, PanelLook.glass ? 12 : 8)
            switch tab {
            case .network: NetworkTab(state: state)
            case .processes: ProcessesTab(state: state)
            case .ports: PortsTab(state: state)
            case .startup: StartupTab(state: state)
            }
        }
    }

    /// The tabs from macOS 26: the four in a row on the window with nothing behind them, the
    /// selected one a raised pill that slides to wherever it is picked.
    @available(macOS 26.0, *)
    private var glassTabs: some View {
        HStack(spacing: 0) {
            ForEach(Tab.allCases) { item in
                let selected = item == tab
                let fresh = item == .network ? state.panelNetworkSnapshot?.newCount ?? 0 : 0
                Button {
                    tab = item
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: item.symbol)
                            .font(.system(size: 12, weight: .medium))
                            .accessibilityHidden(true)
                        Text(item.rawValue).fontWeight(selected ? .semibold : .medium)
                        if fresh > 0 {
                            Text(String(fresh))
                                .font(.system(size: 10.5, weight: .bold))
                                .monospacedDigit()
                                .padding(.horizontal, 4)
                                .frame(minWidth: 16, minHeight: 16)
                                .foregroundStyle(.white)
                                .background(PanelColor.newDot, in: Capsule())
                        }
                    }
                    .font(.system(size: 12.5))
                    .foregroundStyle(selected ? .primary : .secondary)
                    .frame(maxWidth: .infinity)
                    .frame(height: 30)
                    .background {
                        if selected {
                            Capsule()
                                .fill(.primary.opacity(0.13))
                                // A whole point wide: half a point is half a pixel on a display
                                // that is not Retina, where the bottom of the outline went missing.
                                .overlay { Capsule().strokeBorder(.white.opacity(0.16), lineWidth: 1) }
                                .matchedGeometryEffect(id: "selection", in: tabSelection)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(item.rawValue)
                .accessibilityValue(fresh > 0 ? "\(fresh) first contact" : "")
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        // Only the row animates the change, so the pill slides while the list and the footer
        // switch at once.
        .animation(.snappy(duration: 0.3, extraBounce: 0.12), value: tab)
    }

    /// The tabs before macOS 26.
    private var tabs: some View {
        HStack(spacing: 2) {
            ForEach(Array(Tab.allCases.enumerated()), id: \.element) { index, item in
                let selected = item == tab
                // A hairline between two tabs that are not selected; the selected one's fill
                // already sets it apart.
                let divided = index > 0 && !selected && Tab.allCases[index - 1] != tab
                let fresh = item == .network ? state.panelNetworkSnapshot?.newCount ?? 0 : 0
                Button {
                    tab = item
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: item.symbol).font(.system(size: 12)).accessibilityHidden(true)
                        Text(item.rawValue).fontWeight(selected ? .semibold : .regular)
                        if fresh > 0 {
                            Text(String(fresh))
                                .font(.system(size: 11, weight: .semibold))
                                .monospacedDigit()
                                .padding(.horizontal, 4)
                                .frame(minWidth: 16, minHeight: 16)
                                .foregroundStyle(PanelColor.newText)
                                .background(PanelColor.newBackground, in: Capsule())
                        }
                    }
                    .foregroundStyle(selected ? PanelColor.text : PanelColor.sub)
                    .frame(maxWidth: .infinity)
                    .frame(height: 28)
                    .background(selected ? PanelColor.selectedTab : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .overlay(alignment: .leading) {
                    Rectangle()
                        .fill(PanelColor.line)
                        .opacity(divided ? 0.7 : 0)
                        .frame(width: 1, height: 14)
                        .offset(x: -1.5)
                        .accessibilityHidden(true)
                }
                .accessibilityLabel(item.rawValue)
                .accessibilityValue(fresh > 0 ? "\(fresh) first contact" : "")
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(3)
        .background(PanelColor.tabs, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    @ViewBuilder
    private func page(_ route: PanelRoute, back: String) -> some View {
        switch route {
        case .connectionGroup(let group): ConnectionGroupDetail(group: group, back: back, state: state)
        case .connection(let live): ConnectionDetail(live: live, back: back, state: state)
        case .packetAccess: PacketAccessView(back: back, state: state)
        case .processGroup(let group): ProcessGroupDetail(group: group, back: back, state: state)
        case .process(let item): ProcessDetail(item: item, back: back, state: state)
        case .port(let item): PortDetail(item: item, back: back, state: state)
        case .startupItem(let item): StartupDetail(item: item, back: back, state: state)
        }
    }

    private var footer: some View {
        HStack {
            Button {
                // The panel is the key window while open; it must go before the
                // settings window takes focus, or both stay on screen.
                NSApplication.shared.keyWindow?.close()
                openSettings()
                // A Settings window left open behind another app's windows is already
                // open, so opening it again does nothing: bring it forward.
                NSApplication.shared.activate()
                NSApplication.shared.windows.first { $0.identifier?.rawValue.contains("Settings") == true }?.makeKeyAndOrderFront(nil)
            } label: {
                if PanelLook.glass {
                    FooterSymbol(name: "gearshape")
                } else {
                    Text("Settings\u{2026}")
                }
            }
            .accessibilityLabel("Settings\u{2026}")
            .help(PanelLook.glass ? "Settings" : "")
            if PanelLook.glass, router.path.isEmpty {
                FooterSummary(tab: tab, state: state)
            }
            Spacer()
            if tab == .network, router.path.isEmpty {
                let capturing = if case .capturing = state.network.captureStatus { true } else { false }
                Button {
                    router.push(.packetAccess)
                } label: {
                    HStack(spacing: 5) {
                        Circle().fill(capturing ? PanelColor.ok : PanelColor.newDot).frame(width: 7, height: 7).accessibilityHidden(true)
                        Text(PacketAccessView.linkTitle(state.network.broker.installation, capturing: capturing)).font(PanelFont.small)
                    }
                    .contentShape(Rectangle())
                }
                if !PanelLook.glass { Spacer() }
            }
            QuitButton(symbolOnly: PanelLook.glass)
        }
        .buttonStyle(FooterButtonStyle())
        .foregroundStyle(PanelColor.sub)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }
}

/// A word at the bottom of the panel that lights up under the pointer, as a menu's rows do.
private struct FooterButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        Label(configuration: configuration)
    }

    private struct Label: View {
        let configuration: Configuration
        @State private var hovered = false

        var body: some View {
            configuration.label
                .padding(.horizontal, 6)
                .padding(.vertical, 4)
                .foregroundStyle(hovered ? PanelColor.text : PanelColor.sub)
                .background(hovered || configuration.isPressed ? PanelColor.fill : .clear, in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                .onHover { hovered = $0 }
        }
    }
}

/// The list's summary in a few words; the whole of it for a pointer held here and for
/// VoiceOver. A view of its own, so that a new reading redraws these words and not the panel.
private struct FooterSummary: View {
    let tab: PanelView.Tab
    let state: AppState

    var body: some View {
        if let summary {
            Text(summary.short)
                .font(PanelFont.small)
                .monospacedDigit()
                .lineLimit(1)
                .help(summary.full)
                .accessibilityLabel(summary.full)
        }
    }

    private var summary: ListSummary? {
        switch tab {
        case .network: state.panelNetworkSnapshot.map { ListSummary(network: $0, observer: state.network) }
        case .processes: state.processes.snapshot.map { ListSummary(processes: $0) }
        case .ports: state.ports.snapshot.map { ListSummary(ports: $0) }
        case .startup: state.startup.snapshot.map { ListSummary(startup: $0) }
        }
    }
}

/// A symbol that stands for a word at the bottom of the panel.
private struct FooterSymbol: View {
    let name: String

    var body: some View {
        Image(systemName: name)
            .font(.system(size: 13, weight: .medium))
            .frame(width: 18, height: 18)
            .contentShape(Rectangle())
    }
}

/// Quit, with its shortcut beside it, or as the power symbol alone.
private struct QuitButton: View {
    var symbolOnly = false

    var body: some View {
        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            if symbolOnly {
                FooterSymbol(name: "power")
            } else {
                HStack(spacing: 8) {
                    Text("Quit Tattle")
                    Text("\u{2318}Q").font(PanelFont.small).accessibilityHidden(true)
                }
                .contentShape(Rectangle())
            }
        }
        .keyboardShortcut("q")
        .accessibilityLabel("Quit Tattle")
        .help(symbolOnly ? "Quit Tattle (\u{2318}Q)" : "")
    }
}

private extension View {
    /// Keeps a page that is under another alive, unseen and out of reach.
    func shown(_ isShown: Bool) -> some View {
        opacity(isShown ? 1 : 0)
            .allowsHitTesting(isShown)
            .accessibilityHidden(!isShown)
    }
}

/// Reports when the window this view is in goes on or off screen. Follows occlusion rather than
/// key status: another app taking focus without a click takes key from the panel, and the panel
/// stays on screen.
private struct WindowOnScreenReader: NSViewRepresentable {
    let onChange: @MainActor (Bool) -> Void

    func makeNSView(context: Context) -> ReaderView { ReaderView(onChange: onChange) }
    func updateNSView(_ view: ReaderView, context: Context) { view.onChange = onChange }

    final class ReaderView: NSView {
        var onChange: @MainActor (Bool) -> Void
        private var observers: [NSObjectProtocol] = []

        init(onChange: @escaping @MainActor (Bool) -> Void) {
            self.onChange = onChange
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("not used from a nib") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            let center = NotificationCenter.default
            for observer in observers { center.removeObserver(observer) }
            observers = []
            guard let window else { return }
            // On glass the panel is dark whatever the Mac's appearance, as Control Center's are.
            if PanelLook.glass { window.appearance = NSAppearance(named: .darkAqua) }
            observers = [
                center.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: window, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated { self?.reportOcclusion() }
                },
                center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { [weak self] _ in
                    MainActor.assumeIsolated { self?.reportIfOnScreen() }
                },
            ]
            reportIfOnScreen()
        }

        private func reportOcclusion() {
            guard let window else { return }
            onChange(window.occlusionState.contains(.visible))
        }

        /// Recovers a change that went unreported, so the panel cannot stay frozen on screen.
        /// Only ever reports on screen: on an ordinary open the window still reads as occluded
        /// at both of these moments, and the occlusion notification follows.
        private func reportIfOnScreen() {
            if window?.occlusionState.contains(.visible) == true { onChange(true) }
        }
    }
}

/// Shown instead of the panel when the database could not be opened.
struct StartupFailureView: View {
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Tattle could not start.").font(.system(size: 15, weight: .semibold))
            Text(message).lineSpacing(3).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                QuitButton().buttonStyle(.panel)
            }
            .padding(.top, 4)
        }
        .font(.system(size: 13))
        .foregroundStyle(PanelColor.text)
        .padding(16)
        .frame(width: 480)
        .background(PanelColor.background)
    }
}
