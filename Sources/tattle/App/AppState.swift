import Foundation
import Observation

/// Everything that lives for the whole run: the database and what is built on it.
@MainActor @Observable
final class AppState {
    let sampler = ResourceSampler()
    let startup = StartupObserver()
    let ports = PortsObserver()
    let processes = ProcessesObserver()
    let network: NetworkObserver
    let settings: AppSettings
    let rules: RuleStore
    let connections: ConnectionStore
    let explainer: Explainer

    /// Whether the panel is on screen. MenuBarExtra keeps the panel's views alive when it
    /// closes, so what they do while open follows this rather than their lifetime. True
    /// until the first close: nothing reads it before the panel first opens.
    var panelIsShowing = true {
        didSet {
            guard !panelIsShowing else { return }
            heldSample = sampler.sample
            heldNetworkSnapshot = network.snapshot
        }
    }
    @ObservationIgnored private var heldSample = ResourceSample.zero
    @ObservationIgnored private var heldNetworkSnapshot: NetworkSnapshot?
    /// Deletes expired unconfirmed answers while the app runs, which can be weeks: a lookup
    /// ignores one, but until it is deleted its text stays in the database.
    private let pruning: Task<Void, Never>

    /// The sampler and the network readings keep running with the panel closed, for the menu
    /// bar label and the history. The panel reads them through these, which do not touch the
    /// sources while it is closed, so a new reading leaves its views nothing to update for.
    var panelSample: ResourceSample { panelIsShowing ? sampler.sample : heldSample }
    var panelNetworkSnapshot: NetworkSnapshot? { panelIsShowing ? network.snapshot : heldNetworkSnapshot }

    init(
        database: AppDatabase, socketTable: @escaping @Sendable () throws -> [SocketEntry] = { try SocketTable.read() },
        pruneInterval: Duration = .seconds(3600)
    ) throws {
        rules = try RuleStore(database: database)
        connections = ConnectionStore(database: database)
        settings = try AppSettings(store: SettingsStore(database: database))
        explainer = Explainer(store: rules, settings: settings)
        network = NetworkObserver(store: connections, rules: rules, settings: settings, socketTable: socketTable)
        if let resources = Bundle.main.resourceURL {
            SeedLoader(rules: rules).load(from: resources.appending(path: "knowledge"))
        }
        let pruned = try rules.pruneExpired()
        if pruned > 0 {
            Log.app.info("pruned \(pruned) expired unconfirmed LLM rules")
        }
        pruning = Task.detached(priority: .utility) { [rules] in
            while true {
                try? await Task.sleep(for: pruneInterval)
                guard !Task.isCancelled else { return }
                do {
                    let pruned = try rules.pruneExpired()
                    if pruned > 0 { Log.app.info("pruned \(pruned) expired unconfirmed LLM rules") }
                } catch {
                    Log.app.error("pruning expired LLM rules failed: \(error, privacy: .public)")
                }
            }
        }
    }

    deinit { pruning.cancel() }
}
