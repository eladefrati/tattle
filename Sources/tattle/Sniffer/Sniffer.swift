import Foundation
import os

/// Reads packets from the default route's interface on its own thread and reports flow
/// events. Follows the interface when the default route moves; retries when the device
/// cannot be opened, which is the state while the broker (ADR-0003) is not installed, and
/// when a read fails: at once if the route has left the interface, and otherwise after a
/// wait that grows while reads keep failing.
final class Sniffer: @unchecked Sendable {
    enum Status: Equatable, Sendable {
        case stopped
        case capturing(interface: String)
        case unavailable(CaptureError)
    }

    /// How the capture is obtained for an interface: the broker's descriptor when the
    /// broker is installed, else the device directly.
    typealias Opener = @Sendable (String) throws -> any CaptureSource

    /// What the loop reads about the machine's interfaces; tests change it underneath.
    struct Host: Sendable {
        var primaryInterface: @Sendable () -> String? = { PacketCapture.primaryInterface() }
        var hardwareAddress: @Sendable (String) -> [UInt8]? = { PacketCapture.hardwareAddress(of: $0) }
        /// One interface's addresses.
        var addresses: @Sendable (String) -> Set<IPAddress> = { localAddresses(of: $0) }
        var resolvers: @Sendable () -> Set<IPAddress> = { systemResolvers() }
        var interfaceCheckEvery: TimeInterval = 5
        /// The wait before reopening after the first failed read, where the route is still
        /// on the interface; it doubles at each one that follows, up to `retryAfter`.
        var readRetryAfter: TimeInterval = 1
    }

    private let open: Opener
    private let host: Host
    private let onEvents: @Sendable ([FlowEvent]) -> Void
    private let onStatus: @Sendable (Status) -> Void
    /// The current run's stop flag and the signal that it has ended. Each run has its own,
    /// so a start right after a stop cannot clear the flag the old run is still to read.
    private var current: (stopping: OSAllocatedUnfairLock<Bool>, ended: DispatchSemaphore)?
    /// The stopped run the next one must wait for: runs form a chain, so two never overlap and
    /// a stopped run's last report always precedes the next run's first.
    private var predecessor: DispatchSemaphore?

    private static let retryAfter: TimeInterval = 30
    private static let addressRefreshEvery: TimeInterval = 60
    /// How often a packet from an unknown address, IP or hardware, may trigger a refresh.
    private static let staleRefreshEvery: TimeInterval = 1
    private static let readTimeout: Duration = .milliseconds(500)
    /// How often the time-driven work runs. In immediate mode every burst ends a read, so
    /// running it per read cost a pass over every flow per burst; its deadlines are seconds
    /// apart, and a second late changes nothing.
    private static let expireEvery: TimeInterval = 1
    /// Longest a run can be unreachable by its stop flag: a broker request, or one read. A
    /// predecessor still going after this and a margin is wedged, and is left to end on its
    /// own, under its own stop flag.
    private static let predecessorWait = CaptureBroker.requestTimeout + 3

    init(open: @escaping Opener = { try PacketCapture.obtain(interface: $0, timeout: Sniffer.readTimeout) },
         host: Host = Host(),
         onEvents: @escaping @Sendable ([FlowEvent]) -> Void,
         onStatus: @escaping @Sendable (Status) -> Void) {
        self.open = open
        self.host = host
        self.onEvents = onEvents
        self.onStatus = onStatus
    }

    func start() {
        guard current == nil else { return }
        let stopping = OSAllocatedUnfairLock(initialState: false)
        let ended = DispatchSemaphore(value: 0)
        current = (stopping, ended)
        let previous = predecessor
        predecessor = nil
        let thread = Thread { [self] in
            if let previous, previous.wait(timeout: .now() + Self.predecessorWait) == .timedOut {
                Log.sniffer.error("the previous capture run did not end within \(Self.predecessorWait) s")
            }
            run { stopping.withLock { $0 } }
            ended.signal()
        }
        thread.name = "tattle.sniffer"
        thread.qualityOfService = .utility
        thread.start()
    }

    /// Asks the run to end and returns at once, so the caller (the main actor, after an
    /// install) never waits on a broker request. The next `start` begins only after this run
    /// has closed its capture device and reported `.stopped`.
    func stop() {
        guard let run = current else { return }
        current = nil
        predecessor = run.ended
        run.stopping.withLock { $0 = true }
    }

    /// Why a capture's reading ended.
    private enum CaptureEnd {
        case stopped
        /// The default route moved to another interface.
        case moved
        case readFailed(CaptureError)
    }

    private func run(shouldStop: () -> Bool) {
        var lastFailure: CaptureError?
        /// Captures in a row that ended in a failed read.
        var readFailures = 0
        while !shouldStop() {
            guard let interface = host.primaryInterface() else {
                report(.unavailable(.noInterface), previous: &lastFailure)
                wait(Self.retryAfter, shouldStop: shouldStop)
                continue
            }
            let capture: any CaptureSource
            do {
                capture = try open(interface)
            } catch let error as CaptureError {
                guard !shouldStop() else { break }
                report(.unavailable(error), previous: &lastFailure)
                wait(Self.retryAfter, shouldStop: shouldStop)
                continue
            } catch {
                guard !shouldStop() else { break }
                report(.unavailable(.open(errno: EIO)), previous: &lastFailure)
                wait(Self.retryAfter, shouldStop: shouldStop)
                continue
            }
            // Stopped while the broker was answering: the descriptor is dropped unused.
            guard !shouldStop() else { break }
            lastFailure = nil
            let direction = direction(for: capture, interface: interface)
            installFilter(on: capture, direction: direction, interface: interface)
            onStatus(.capturing(interface: interface))
            // Notice, not info: the unified log keeps notices, so a later comparison can
            // tell when capture was on.
            Log.sniffer.notice("capturing on \(interface, privacy: .public), link type \(capture.dataLinkType), \(capture.isFromBroker ? "through the broker" : "from the device", privacy: .public)")
            let opened = Date()
            switch captureLoop(capture, interface: interface, direction: direction, shouldStop: shouldStop) {
            case .stopped:
                break
            case .moved:
                readFailures = 0
            case .readFailed(let error):
                // A device that opens and then fails its reads would otherwise be reopened
                // as fast as the broker answers. One that read for a while first is a new
                // trouble, and starts the waits over.
                if Date().timeIntervalSince(opened) >= Self.retryAfter { readFailures = 0 }
                readFailures += 1
                guard !shouldStop() else { break }
                // An interface that goes away fails its read, and the route is by then on
                // another, which is opened at once, as when the route moves under a capture
                // that still reads. Only after the first failure in a row: two interfaces
                // failing by turns wait like one. With no route at all there is nothing to
                // open, and the wait below gives one time to come back.
                if readFailures == 1, let current = host.primaryInterface(), current != interface {
                    Log.sniffer.notice("the default route moved to \(current, privacy: .public); reopening without a wait")
                    continue
                }
                let delay = min(Self.retryAfter, host.readRetryAfter * pow(2, Double(readFailures - 1)))
                report(.unavailable(error), previous: &lastFailure)
                Log.sniffer.notice("reopening the capture in \(delay, format: .fixed(precision: 1)) s, after \(readFailures) in a row ended in a failed read")
                wait(delay, shouldStop: shouldStop)
            }
        }
        onStatus(.stopped)
    }

    /// Reports a failure once, not every retry.
    private func report(_ status: Status, previous: inout CaptureError?) {
        guard case .unavailable(let error) = status else { return }
        if error != previous {
            Log.sniffer.notice("packet capture unavailable: \(error.text, privacy: .public)")
            onStatus(status)
        }
        previous = error
    }

    /// How the kernel filter tells this interface's outbound packets, as the interface is now.
    private func direction(for capture: any CaptureSource, interface: String) -> CaptureFilter.Direction {
        if capture.dataLinkType == PacketCapture.linkEthernet, let mac = host.hardwareAddress(interface) {
            return .hardwareAddress(mac)
        }
        // Only this interface's: every address costs instructions, and a packet captured
        // here leaves from one of them. Sorted, so an unchanged set compares equal.
        return .sourceAddresses(host.addresses(interface).map(\.bytes).sorted { $0.lexicographicallyPrecedes($1) })
    }

    private func installFilter(on capture: any CaptureSource, direction: CaptureFilter.Direction, interface: String) {
        guard let filter = CaptureFilter.program(linkType: capture.dataLinkType, direction: direction) else {
            let why = CaptureFilter.linkHeaderLength(capture.dataLinkType) == nil
                ? "link type \(capture.dataLinkType) has no layout" : "its addresses are too many for one program"
            Log.sniffer.notice("no kernel filter on \(interface, privacy: .public), \(why, privacy: .public); copying every packet")
            return
        }
        do {
            try capture.install(filter)
        } catch {
            Log.sniffer.error("kernel filter rejected, copying every packet: \(String(describing: error), privacy: .public)")
        }
    }

    /// Reads until the interface changes, the device fails, or stop is called.
    private func captureLoop(_ capture: any CaptureSource, interface: String, direction installed: CaptureFilter.Direction, shouldStop: () -> Bool) -> CaptureEnd {
        var installed = installed
        var namer = FlowNamer(localAddresses: host.addresses(interface), resolvers: host.resolvers(), hardwareAddress: installed.hardwareAddress)
        // Every way out drops the namer, and with it the flows whose handshake was not read.
        defer {
            let events = namer.endCapture()
            if !events.isEmpty { onEvents(events) }
        }
        var lastInterfaceCheck = Date()
        var lastAddressRefresh = Date()
        var lastHardwareCheck = Date.distantPast
        var lastExpire = Date.distantPast
        while !shouldStop() {
            var events: [FlowEvent] = []
            do {
                try capture.readPackets { timestamp, bytes in
                    guard let packet = Packet.parse(bytes, dlt: capture.dataLinkType) else { return }
                    // A packet between two addresses that are not ours means ours changed:
                    // refresh now rather than at the next timer, or every flow until then
                    // goes unnamed.
                    if namer.endpointsUnknown(packet), Date().timeIntervalSince(lastAddressRefresh) >= Self.staleRefreshEvery {
                        namer.updateLocalAddresses(host.addresses(interface))
                        namer.updateResolvers(host.resolvers())
                        lastAddressRefresh = Date()
                        Log.sniffer.debug("refreshed local addresses on an unknown packet")
                    }
                    // A frame under this Mac's address from a hardware address that is not the
                    // interface's as last read: another host's, or this Mac's own after the
                    // address changed (Wi-Fi joining a network under another private address).
                    // Reading it again now tells which, so the first frame sent from a new
                    // address is already read as sent.
                    if namer.hardwareSourceUnknown(packet), Date().timeIntervalSince(lastHardwareCheck) >= Self.staleRefreshEvery {
                        lastHardwareCheck = Date()
                        follow(capture, interface: interface, installed: &installed, namer: &namer)
                    }
                    events += namer.observe(packet, at: timestamp)
                }
            } catch {
                Log.sniffer.error("packet read failed: \(String(describing: error), privacy: .public)")
                return .readFailed(error as? CaptureError ?? .read(errno: EIO))
            }
            let now = Date()
            if now.timeIntervalSince(lastExpire) >= Self.expireEvery {
                events += namer.expire(now: now.timeIntervalSince1970)
                lastExpire = now
            }
            if !events.isEmpty { onEvents(events) }
            if now.timeIntervalSince(lastAddressRefresh) >= Self.addressRefreshEvery {
                namer.updateLocalAddresses(host.addresses(interface))
                namer.updateResolvers(host.resolvers())
                lastAddressRefresh = now
            }
            if now.timeIntervalSince(lastInterfaceCheck) >= host.interfaceCheckEvery {
                lastInterfaceCheck = now
                if let current = host.primaryInterface(), current != interface {
                    Log.sniffer.info("default route moved to \(current, privacy: .public); reopening")
                    return .moved
                }
                follow(capture, interface: interface, installed: &installed, namer: &namer)
                // An address the interface has gained is this Mac's from here on; a packet
                // sent from it tells sooner, a reply sent to it does not. It comes with a
                // network whose resolvers the system names a moment later, and once the
                // address is known no packet prompts a reading, so they are read each time.
                namer.gainLocalAddresses(host.addresses(interface))
                namer.updateResolvers(host.resolvers())
            }
        }
        return .stopped
    }

    /// Brings the kernel filter and the namer to the interface's addresses as they are now. A
    /// rotated private Wi-Fi address or a renumbered tunnel would make the filter class every
    /// outbound packet as inbound and drop it.
    private func follow(_ capture: any CaptureSource, interface: String, installed: inout CaptureFilter.Direction, namer: inout FlowNamer) {
        let direction = direction(for: capture, interface: interface)
        guard direction != installed else { return }
        Log.sniffer.notice("\(interface, privacy: .public) changed its addresses; rebuilding the kernel filter")
        installFilter(on: capture, direction: direction, interface: interface)
        namer.updateHardwareAddress(direction.hardwareAddress)
        installed = direction
    }

    private func wait(_ seconds: TimeInterval, shouldStop: () -> Bool) {
        let deadline = Date().addingTimeInterval(seconds)
        while !shouldStop(), Date() < deadline {
            Thread.sleep(forTimeInterval: min(0.5, max(0, deadline.timeIntervalSinceNow)))
        }
    }
}
