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
}

/// The pages open over the list, oldest first.
@MainActor @Observable
final class PanelRouter {
    var path: [PanelRoute] = []

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
            case .startup: "power"
            }
        }
    }

    let state: AppState
    @State private var tab = Tab.network
    @State private var router = PanelRouter()
    @Namespace private var tabSelection
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(spacing: 0) {
            // Every page stays alive under the one on top, so a list keeps reading and keeps
            // its place while a page is open over it.
            ZStack {
                list.shown(router.path.isEmpty)
                ForEach(Array(router.path.enumerated()), id: \.offset) { index, route in
                    page(route).shown(index == router.path.count - 1)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            RowLine().padding(.horizontal, 12)
            footer
        }
        .environment(router)
        .font(.system(size: 13))
        .foregroundStyle(PanelColor.text)
        .frame(width: 480, height: 636)
        .background(PanelColor.background)
        .background(WindowOnScreenReader { state.panelIsShowing = $0 })
    }

    private var list: some View {
        VStack(spacing: 0) {
            ResourcesLine(sample: state.panelSample)
                .padding(.horizontal, 12)
                .padding(.top, 16)
            tabs
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 12)
            switch tab {
            case .network: NetworkTab(state: state)
            case .processes: ProcessesTab(state: state)
            case .ports: PortsTab(state: state)
            case .startup: StartupTab(state: state)
            }
        }
    }

    /// The tabs: one glass capsule holding the four, the selected one a raised pill that slides
    /// to wherever it is picked.
    private var tabs: some View {
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
                                .overlay { Capsule().strokeBorder(.white.opacity(0.22), lineWidth: 0.5) }
                                .shadow(color: .black.opacity(0.14), radius: 3, y: 1)
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
        // Only the capsule animates the change, so the pill slides while the list and the
        // footer switch at once.
        .animation(.snappy(duration: 0.3, extraBounce: 0.12), value: tab)
        .padding(4)
        .glassEffect(.regular.interactive(), in: .capsule)
    }

    @ViewBuilder
    private func page(_ route: PanelRoute) -> some View {
        switch route {
        case .connectionGroup(let group): ConnectionGroupDetail(group: group, state: state)
        case .connection(let live): ConnectionDetail(live: live, state: state)
        case .packetAccess: PacketAccessView(state: state)
        case .processGroup(let group): ProcessGroupDetail(group: group, state: state)
        case .process(let item): ProcessDetail(item: item, state: state)
        case .port(let item): PortDetail(item: item, state: state)
        case .startupItem(let item): StartupDetail(item: item, state: state)
        }
    }

    private var footer: some View {
        HStack {
            Button("Settings\u{2026}") {
                // The panel is the key window while open; it must go before the
                // settings window takes focus, or both stay on screen.
                NSApplication.shared.keyWindow?.close()
                openSettings()
                // A Settings window left open behind another app's windows is already
                // open, so opening it again does nothing: bring it forward.
                NSApplication.shared.activate()
                NSApplication.shared.windows.first { $0.identifier?.rawValue.contains("Settings") == true }?.makeKeyAndOrderFront(nil)
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
                Spacer()
            }
            QuitButton()
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

/// Quit, with its shortcut beside it.
private struct QuitButton: View {
    var body: some View {
        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            HStack(spacing: 8) {
                Text("Quit Tattle")
                Text("\u{2318}Q").font(PanelFont.small).accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .keyboardShortcut("q")
        .accessibilityLabel("Quit Tattle")
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
