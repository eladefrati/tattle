import SwiftUI

/// Installing and removing the packet-access broker (ADR-0003): what it does, in plain
/// words, and the exact launch daemon that goes in, before the administrator dialog.
/// Pushed inside the panel; the work and its outcome live in the observer, so that they do
/// not depend on the panel being open.
struct PacketAccessView: View {
    let state: AppState
    @Environment(PanelRouter.self) private var router

    var body: some View {
        let network = state.network
        let broker = network.broker
        let capturing = if case .capturing = network.captureStatus { true } else { false }
        DetailPage(title: "Packet access") {
            Card {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 10) {
                        Circle()
                            .fill(capturing ? PanelColor.ok : broker.installation == .absent ? PanelColor.track : PanelColor.newDot)
                            .frame(width: 8, height: 8)
                            .accessibilityHidden(true)
                        Text(statusText(network.captureStatus)).fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                        if network.accessBusy { ProgressView().controlSize(.small) }
                        if broker.installation != .absent {
                            Button("Remove") { run(network.removeBroker) }
                                .buttonStyle(.panel)
                        }
                        if let label = Self.installLabel(broker.installation) {
                            Button(label) { run(network.installBroker) }
                                .buttonStyle(.panelPrimary)
                                .disabled((try? broker.proposed.get()) == nil)
                        }
                    }
                    .disabled(network.accessBusy)
                    if let error = network.accessError {
                        Text(error)
                            .font(PanelFont.small)
                            .foregroundStyle(PanelColor.bad)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }
            if let explanation = Self.explanation(broker.installation, capturing: capturing) {
                paragraph(explanation)
            }
            paragraph(CaptureBroker.installExplanation)
            switch broker.proposed {
            case .success(let plist):
                plistBlock(broker.installation == .current ? "Installed as \(CaptureBroker.plistPath):" : "What will be installed, at \(CaptureBroker.plistPath):", plist)
            case .failure(let error):
                Text(error.text)
                    .font(PanelFont.small)
                    .foregroundStyle(PanelColor.bad)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 4)
            }
            if let installed = broker.installed {
                plistBlock("Installed now:", installed)
            }
        } bar: {
            EmptyView()
        }
        .onAppear { network.refreshBroker() }
    }

    private func paragraph(_ text: String) -> some View {
        Card {
            Text(text)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 12)
                .padding(.vertical, 11)
        }
    }

    private func plistBlock(_ caption: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(caption).font(PanelFont.small).foregroundStyle(PanelColor.sub).padding(.horizontal, 4)
            Text(text)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(PanelColor.sub)
                .textSelection(.enabled)
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(PanelColor.fill, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
    }

    private func statusText(_ status: Sniffer.Status) -> String {
        switch status {
        case .capturing(let interface): "Capturing on \(interface)\(CaptureBroker.isReachable ? " through the broker" : "")."
        case .unavailable(let error): "Not capturing: \(error.text)."
        case .stopped: "Not capturing."
        }
    }

    /// Back to the tab when it worked; the tab's summary says what changed.
    private func run(_ action: @escaping () async -> Bool) {
        Task {
            let done = await action()
            await state.startup.refresh()
            if done { router.pop() }
        }
    }

    // MARK: Words for each state

    /// The Network list's way here, at the bottom of the panel: that names are being read, or
    /// what to do when they are not.
    static func linkTitle(_ installation: CaptureBroker.Installation, capturing: Bool) -> String {
        if capturing { return "Packet access on" }
        return switch installation {
        case .absent: "Allow packet access"
        case .current: "Packet access off"
        case .stale: "Packet access: install again"
        }
    }

    /// The Network tab's sentence when it has no names.
    static func namesOff(_ installation: CaptureBroker.Installation) -> String {
        if case .stale = installation { return "Destinations are addresses: the packet-access broker on this Mac does not serve this copy of Tattle" }
        return "Destinations are addresses: names need packet access, which Tattle does not have yet"
    }

    /// What is wrong with the installed broker, when something is.
    static func explanation(_ installation: CaptureBroker.Installation, capturing: Bool) -> String? {
        guard case .stale(let staleness) = installation else { return nil }
        return switch staleness {
        case .otherBuild where capturing: "The installed broker is from another build of Tattle. It still serves this one; install it again to update it."
        case .otherBuild: "The installed broker is from another build of Tattle. Install it again so it recognises this one."
        case .otherUser(let uid): "The installed broker serves another account on this Mac (user ID \(uid)), so it refuses this one. Installing it here replaces theirs."
        case .incomplete: "The packet-access broker is only partly installed and cannot run. Install it again, or remove what is left."
        case .notLoaded: "The packet-access broker is installed but not running. Install it again to start it."
        }
    }

    /// The install button's label; none when this build's broker is installed and running.
    static func installLabel(_ installation: CaptureBroker.Installation) -> String? {
        switch installation {
        case .absent: "Install"
        case .current: nil
        case .stale(.otherUser): "Install for this account"
        case .stale: "Install again"
        }
    }
}
