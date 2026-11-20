import Foundation
import Observation

/// Reads the socket table on demand and keeps names and signatures cached.
@MainActor @Observable
final class PortsObserver {
    private(set) var snapshot: PortsSnapshot?
    private(set) var error: String?
    private let signatures = SignatureCache()
    private var services: ServiceNames?
    private let loadServices: @Sendable () -> ServiceNames

    init(loadServices: @escaping @Sendable () -> ServiceNames = { ServiceNames.load() }) {
        self.loadServices = loadServices
    }

    func refresh() async {
        let signatures = signatures
        let cached = services
        let loadServices = loadServices
        // /etc/services is read here, not on the main actor: parsing it is slow enough to hold
        // the panel at the first refresh.
        let (services, result) = await Task.detached(priority: .userInitiated) { () -> (ServiceNames, Result<PortsSnapshot, Error>) in
            let services = cached ?? loadServices()
            return (services, Result {
                let entries = try SocketTable.read()
                // Listed without their signatures: each listener's is read when it is named.
                let byPid = Dictionary(try ProcessTable.list(signature: { _, _ in nil }).map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
                return PortsSnapshot.build(
                    entries: entries, services: services,
                    processes: { byPid[$0] }, executable: signatures.signature(of:at:))
            })
        }.value
        self.services = services
        switch result {
        case .success(let snapshot):
            self.snapshot = snapshot
            error = nil
        case .failure(let failure):
            error = String(describing: failure)
            Log.app.error("ports snapshot failed: \(failure, privacy: .public)")
        }
    }
}
