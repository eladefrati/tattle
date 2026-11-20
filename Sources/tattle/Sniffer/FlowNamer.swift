import Foundation

/// Which packet named a connection, in order of preference (ADR-0001). The first three are
/// the program's own word: the server it asked for, which nothing checks against the
/// address it connected to, so `text` says who said it.
enum NameSource: String, Sendable {
    /// The server name in a TLS ClientHello over TCP.
    case sni
    /// The same, inside a decrypted QUIC Initial packet.
    case quic
    /// The Host header of a plaintext HTTP request.
    case http
    /// Only a DNS reply seen earlier named the address: a fallback, and ambiguous
    /// wherever one address serves many names.
    case dns

    var text: String {
        switch self {
        case .sni: "what the program asked for in its TLS handshake"
        case .quic: "what the program asked for in its QUIC handshake"
        case .http: "what the program asked for in its HTTP request"
        case .dns: "a DNS reply for the address"
        }
    }
}

/// An outbound flow as the socket table also sees it: protocol, local port and peer.
/// The pid is the socket table's to add.
struct FlowKey: Hashable, Sendable {
    let proto: Packet.Proto
    let localPort: UInt16
    let remote: IPAddress
    let remotePort: UInt16

    /// The join key shared with `Connection.flowKey`.
    var text: String { "\(proto == .tcp ? "tcp" : "udp")/\(localPort)>\(remote.text):\(remotePort)" }
}

struct FlowEvent: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        /// A connection just started: the moment to read the socket table for its owner.
        case opened
        case named(String, NameSource)
        /// Nothing more can name this flow, and why: what the spike could not tell apart.
        case unnamed(Reason)
    }

    enum Reason: Equatable, Sendable {
        /// The first bytes were neither a TLS record nor an HTTP request.
        case notHandshake
        /// A segment arrived out of order before the handshake was complete.
        case gap
        /// A ClientHello without a valid server name, an HTTP request without a Host header,
        /// or a handshake too large to buffer.
        case noServerName
        /// An HTTP request whose Host header is not a host name: an address, or a value
        /// `HostName` refuses.
        case noHostName
        case quic(QUIC.Failure)
        /// No handshake within the window: no payload, or one that never completed.
        case timeout
        /// Too many newer flows opened before this one's handshake was read, and it was
        /// dropped to stay within `flowCapacity`.
        case evicted
        /// The packet capture stopped or reopened (a stop, a restart, the default route moving,
        /// a failed read) before this flow's handshake was read.
        case captureEnded

        /// Stored in history as the name source of an unnamed connection.
        static let codePrefix = "none:"

        var code: String {
            switch self {
            case .notHandshake: Self.codePrefix + "not-handshake"
            case .gap: Self.codePrefix + "gap"
            case .noServerName: Self.codePrefix + "no-server-name"
            case .noHostName: Self.codePrefix + "no-host-name"
            case .quic(let failure): Self.codePrefix + "quic-" + failure.rawValue
            case .timeout: Self.codePrefix + "timeout"
            case .evicted: Self.codePrefix + "evicted"
            case .captureEnded: Self.codePrefix + "capture-ended"
            }
        }

        var text: String {
            switch self {
            case .notHandshake: "the connection did not start with a TLS or HTTP handshake"
            case .gap: "part of the handshake was missed"
            case .noServerName: "the handshake carried no server name"
            case .noHostName: "the HTTP request's Host header was not a host name"
            case .quic(.unsupportedVersion): "a QUIC version Tattle cannot read"
            case .quic: "the QUIC handshake could not be read"
            case .timeout: "no complete handshake came in the connection's first \(Int(FlowNamer.finalizeAfter)) seconds"
            case .evicted: "too many connections opened at once for Tattle to follow this one"
            case .captureEnded: "the packet capture stopped or restarted before this connection's handshake was read"
            }
        }
    }

    var key: FlowKey
    var kind: Kind
}

/// Turns captured packets into names for connections. Keeps, per flow, only the handshake
/// bytes until a name is found or ruled out, and of this Mac's DNS queries what their
/// replies are matched by, until the reply; keeps no packet contents otherwise.
struct FlowNamer: Sendable {
    /// A wire name must arrive within this long, or the DNS map is consulted.
    static let dnsFallbackAfter = 3.0
    /// A flow still unnamed after this long is given up on and its buffers freed.
    static let finalizeAfter = 20.0
    /// A flow not seen for this long is forgotten; a later packet with the same
    /// addresses is a new connection.
    static let idleAfter = 120.0
    static let dnsRemembered = 3600.0
    /// The most DNS answers remembered; the oldest goes first.
    static let dnsCapacity = 4096
    /// The most flows tracked; the one that started first goes.
    static let flowCapacity = 4096
    /// The most handshake bytes buffered for one flow, TCP or QUIC.
    static let bufferLimit = 16_384
    /// How long a reply can answer a DNS query this Mac sent (ADR-0006). A query older than
    /// this is dropped at the next `expire`.
    static let queryAwaited = 10.0
    /// The most queries held; the oldest goes first.
    static let queryCapacity = 1024

    private struct Flow {
        var start: Double
        var lastSeen: Double
        /// Named from its own packets.
        var named = false
        var dnsTried = false
        /// Named from the DNS map, a stand-in until the wire names it: a later wire name
        /// replaces it, a later failure does not.
        var dnsNamed = false
        var tlsBuffer: [UInt8]? = []  // nil once the stream is known not to be TLS or HTTP
        var nextSeq: UInt32 = 0
        var quicAssembly = QUICAssembly()
        var quicDone = false
        /// The destination connection id of the latest Initial that decrypted.
        var quicDCID: [UInt8]?
        /// Its place in `flowOrder`.
        var serial = 0

        /// Nothing more can come of this flow; packets only refresh lastSeen.
        var finished: Bool { named || (tlsBuffer == nil && quicDone) }
    }

    /// The capture interface's addresses, as the kernel filter has them on a tunnel: the ones
    /// a packet on it can carry as this Mac's. An address of another interface can be another
    /// host's on this link: loopback's fe80::1 is also what many routers answer DNS from, and
    /// a bridge of this Mac's can number the subnet a resolver is on.
    private var local: Set<IPAddress>
    private var resolvers: Set<IPAddress>
    /// The capture interface's hardware address, on a link whose frames carry one.
    private var hardwareAddress: [UInt8]?
    private var dnsMap = DNSMap()
    /// This Mac's DNS queries still waiting for a reply.
    private var queries = AwaitedQueries()
    private var flows: [FlowKey: Flow] = [:]
    private var flowOrder = ArrivalOrder<FlowKey>()

    init(localAddresses: Set<IPAddress>, resolvers: Set<IPAddress>, hardwareAddress: [UInt8]? = nil) {
        local = localAddresses
        self.resolvers = resolvers
        self.hardwareAddress = hardwareAddress
    }

    /// A private Wi-Fi address rotates under an open capture.
    mutating func updateHardwareAddress(_ address: [UInt8]?) {
        hardwareAddress = address
    }

    /// Addresses change with DHCP leases and network switches.
    mutating func updateLocalAddresses(_ addresses: Set<IPAddress>) {
        if !addresses.isEmpty { local = addresses }
    }

    /// Adds the addresses of a reading that this namer lacks. What the reading lacks is
    /// kept, unlike `updateLocalAddresses`: a reading taken every few seconds will now and
    /// then find the interface with only part of its addresses, as while a lease is renewed.
    mutating func gainLocalAddresses(_ addresses: Set<IPAddress>) {
        local.formUnion(addresses)
    }

    /// The resolvers change with the network, as the addresses do; an empty reading keeps
    /// the old set for the same reason.
    mutating func updateResolvers(_ addresses: Set<IPAddress>) {
        if !addresses.isEmpty { resolvers = addresses }
    }

    var flowCount: Int { flows.count }
    var dnsCount: Int { dnsMap.count }
    var queryCount: Int { queries.count }

    /// The packet goes to a public address from one this namer does not know as ours:
    /// the address set is stale, since this Mac sees no other host's traffic. Wi-Fi
    /// reconnecting after a wake drops and re-adds the interface's address, and a refresh
    /// that lands in the gap loses it. The source is usually private (a home network),
    /// so its scope says nothing; the destination's does.
    func endpointsUnknown(_ p: Packet) -> Bool {
        !local.contains(p.src) && !local.contains(p.dst) && !p.dst.isLocalScope
    }

    /// Whether a packet under one of this Mac's addresses came from this Mac. Its IP source
    /// is whatever the sender wrote, and any host on the network can write this Mac's, so
    /// where frames carry a hardware address the frame must come from the interface's own,
    /// which is how the kernel filter tells direction. A link without one (a tunnel) has only
    /// the IP source to go by.
    private func isFromInterface(_ p: Packet) -> Bool {
        guard let hardwareAddress else { return true }
        return p.linkSource.map { $0.elementsEqual(hardwareAddress) } ?? false
    }

    /// The packet is under one of this Mac's addresses and from a hardware address this namer
    /// does not hold: another host's, or the interface's own since it changed.
    func hardwareSourceUnknown(_ p: Packet) -> Bool {
        local.contains(p.src) && !isFromInterface(p)
    }

    mutating func observe(_ p: Packet, at ts: Double) -> [FlowEvent] {
        // No link carries a loopback address, and the capture is on the default route's
        // interface, never on loopback: a packet from one is nobody's, a local resolver's least.
        guard !p.src.isLoopback else { return [] }
        // Under this Mac's address but from another host: neither sent nor a reply to it.
        let outbound = local.contains(p.src)
        guard !outbound || isFromInterface(p) else { return [] }
        if p.proto == .udp && p.srcPort == 53 && !outbound {
            // Only an answer to a query this Mac sent may name addresses (ADR-0006): from
            // the resolver that was asked, to the port that asked, under the query's id and
            // repeating its question. Any host on the network can write a resolver's address
            // on a reply, so one that answers nothing is dropped on its first two bytes,
            // before it is parsed.
            if resolvers.contains(p.src), local.contains(p.dst), let id = DNS.transactionID(p.payload) {
                let key = AwaitedQueries.Key(resolver: p.src, port: p.dstPort, id: id)
                if queries.awaits(key, sentAfter: ts - Self.queryAwaited), let reply = DNS.parseReply(p.payload),
                   queries.take(key, asking: reply.question) {
                    for address in reply.addresses { dnsMap.insert(reply.name, for: address, at: ts) }
                }
            }
            return []
        }
        if p.proto == .udp && p.dstPort == 53 && outbound {
            // This Mac's query to one of its resolvers, held until its reply comes. It opens
            // no flow, whatever its bytes look like: a query's id can pass for a QUIC header.
            if resolvers.contains(p.dst), let query = DNS.parseQuery(p.payload) {
                queries.insert(query.question, for: AwaitedQueries.Key(resolver: p.dst, port: p.srcPort, id: query.id), at: ts)
            }
            return []
        }
        guard outbound, !p.dst.isLocalScope, !local.contains(p.dst) else { return [] }

        let key = FlowKey(proto: p.proto, localPort: p.srcPort, remote: p.dst, remotePort: p.dstPort)
        switch p.proto {
        case .tcp:
            let syn = p.tcpFlags & 0x02 != 0 && p.tcpFlags & 0x10 == 0
            var events: [FlowEvent] = []
            if syn {
                events = start(Flow(start: ts, lastSeen: ts, nextSeq: p.tcpSeq &+ 1, quicDone: true), for: key)
                events.append(FlowEvent(key: key, kind: .opened))
            }
            guard var flow = flows[key] else { return events }
            flow.lastSeen = ts
            defer { flows[key] = flow }
            guard !flow.finished, !p.payload.isEmpty else { return events }
            // A SYN takes a sequence number of its own, and with TCP Fast Open carries the
            // stream's first bytes after it.
            let seq = syn ? p.tcpSeq &+ 1 : p.tcpSeq
            // Only bytes that continue the stream extend the buffer. A segment that starts
            // ahead of them is a gap, which ends buffering rather than risk a shifted parse.
            // One that starts behind is a retransmit: its bytes already read are dropped, and
            // any past them are taken, since data resent is not always cut where it was first
            // (a server that refuses a SYN's data gets it again from the start). The stream
            // advances by the segment's length on the wire, captured or not.
            let behind = flow.nextSeq &- seq
            guard behind < 0x8000_0000 else {
                flow.tlsBuffer = nil
                return flow.dnsNamed ? events : events + [FlowEvent(key: key, kind: .unnamed(.gap))]
            }
            let length = p.payload.count + p.uncaptured
            guard Int(behind) < length else { return events }
            flow.nextSeq = seq &+ UInt32(length)
            let fresh = p.payload.dropFirst(Int(behind))
            // New bytes none of which were captured say nothing yet; the cut is told below.
            switch fresh.isEmpty ? .pending : inspectTCP(&flow, payload: fresh) {
            case .named(let name, let source):
                flow.named = true
                return events + [FlowEvent(key: key, kind: .named(name, source))]
            case .unnamed(let reason):
                return flow.dnsNamed ? events : events + [FlowEvent(key: key, kind: .unnamed(reason))]
            case .pending:
                // The server name has not come, and the rest of this segment was cut by
                // the snap length: what holds the name was not captured, so say so now.
                guard p.uncaptured > 0, flow.tlsBuffer != nil else { return events }
                flow.tlsBuffer = nil
                return flow.dnsNamed ? events : events + [FlowEvent(key: key, kind: .unnamed(.gap))]
            }
        case .udp:
            let datagram = Array(p.payload)
            var events: [FlowEvent] = []
            if var flow = flows[key], !(flow.finished && Self.startsNewConnection(datagram, after: flow)) {
                flow.lastSeen = ts
                flows[key] = flow
            } else {
                // Only a client Initial starts a flow: a QUIC connection whose first packet
                // seen is a short one was open before capture began and has no ClientHello left.
                guard QUIC.mayBeClientInitial(datagram) else { return [] }
                events = start(Flow(start: ts, lastSeen: ts, tlsBuffer: nil), for: key)
                events.append(FlowEvent(key: key, kind: .opened))
            }
            guard var flow = flows[key], !flow.finished, QUIC.mayBeClientInitial(datagram) else { return events }
            switch inspectUDP(&flow, datagram: datagram) {
            case .named(let name, _):
                flow.named = true
                events.append(FlowEvent(key: key, kind: .named(name, .quic)))
            case .unnamed(let reason):
                if !flow.dnsNamed { events.append(FlowEvent(key: key, kind: .unnamed(reason))) }
            case .pending:
                break
            }
            flows[key] = flow
            return events
        }
    }

    /// Tracks a new flow, or a new connection on a key, past `flowCapacity` at the cost of
    /// the flow that started first.
    private mutating func start(_ flow: Flow, for key: FlowKey) -> [FlowEvent] {
        var flow = flow
        flow.serial = flowOrder.append(key)
        flows[key] = flow
        var events: [FlowEvent] = []
        while flows.count > Self.flowCapacity, let oldest = flowOrder.oldest(in: flows, serial: { $0.serial }) {
            if var evicted = flows[oldest], !evicted.finished, let event = giveUp(on: &evicted, at: oldest, reason: .evicted) {
                events.append(event)
            }
            flows[oldest] = nil
            flowOrder.removeOldest()
        }
        flowOrder.sweep(capacity: Self.flowCapacity, in: flows, serial: { $0.serial })
        return events
    }

    private enum Inspection {
        case named(String, NameSource)
        case unnamed(FlowEvent.Reason)
        case pending
    }

    private func inspectTCP(_ flow: inout Flow, payload: ArraySlice<UInt8>) -> Inspection {
        guard var buffer = flow.tlsBuffer else { return .pending }
        if buffer.isEmpty, payload.first != 0x16 {
            flow.tlsBuffer = nil
            guard let request = HTTP.request(payload) else { return .unnamed(.notHandshake) }
            return request.host.map { .named($0, .http) } ?? .unnamed(request.hasHostHeader ? .noHostName : .noServerName)
        }
        buffer.append(contentsOf: payload)
        switch TLS.clientHelloFromRecords(buffer) {
        case .hello(let sni):
            flow.tlsBuffer = nil
            return sni.map { .named($0, .sni) } ?? .unnamed(.noServerName)
        case .notClientHello:
            flow.tlsBuffer = nil
            return .unnamed(.notHandshake)
        case .needMore:
            guard buffer.count < Self.bufferLimit else {
                flow.tlsBuffer = nil
                return .unnamed(.noServerName)
            }
            flow.tlsBuffer = buffer
            return .pending
        }
    }

    /// A client Initial that opens under its own connection id, a different one from the
    /// flow's: a new connection on a reused port, as a SYN is over TCP. The client's later
    /// Initials carry the id the server chose, which the keys do not derive from.
    private static func startsNewConnection(_ datagram: [UInt8], after flow: Flow) -> Bool {
        guard QUIC.mayBeClientInitial(datagram),
              case .success(let initial) = QUIC.parseInitial(datagram, at: 0) else { return false }
        return initial.dcid != flow.quicDCID
    }

    private func inspectUDP(_ flow: inout Flow, datagram: [UInt8]) -> Inspection {
        var offset = 0
        while offset < datagram.count, datagram[offset] & 0x80 != 0 {
            switch QUIC.parseInitial(datagram, at: offset) {
            case .success(let initial):
                flow.quicDCID = initial.dcid
                flow.quicAssembly.add(initial.chunks)
                offset = initial.nextOffset
                if flow.quicAssembly.overLimit {
                    flow.quicDone = true
                    flow.quicAssembly = QUICAssembly()
                    return .unnamed(.noServerName)
                }
                switch TLS.clientHello(flow.quicAssembly.stream) {
                case .hello(let sni):
                    flow.quicDone = true
                    flow.quicAssembly = QUICAssembly()
                    return sni.map { .named($0, .quic) } ?? .unnamed(.noServerName)
                case .notClientHello:
                    // As over TCP: what it starts with is not a handshake, and no wait changes that.
                    flow.quicDone = true
                    flow.quicAssembly = QUICAssembly()
                    return .unnamed(.notHandshake)
                case .needMore:
                    break
                }
            case .failure(.unsupportedVersion) where offset == 0:
                // Not a version whose Initial can be read; nothing more will come of it. Only
                // the datagram's first packet says so: bytes after an Initial that was read
                // are not the connection's version.
                flow.quicDone = true
                flow.quicAssembly = QUICAssembly()
                return .unnamed(.quic(.unsupportedVersion))
            case .failure:
                // A later Initial may still complete the handshake; the timeout reports
                // the failure if none does.
                return .pending
            }
        }
        return .pending
    }

    /// Time-driven work: the DNS fallback for flows nothing else named, giving up on old
    /// ones, forgetting idle ones and stale DNS answers.
    mutating func expire(now: Double) -> [FlowEvent] {
        var events: [FlowEvent] = []
        for (key, var flow) in flows {
            if !flow.named, !flow.dnsTried, now - flow.start >= Self.dnsFallbackAfter {
                flow.dnsTried = true
                if let name = dnsMap[key.remote] {
                    flow.dnsNamed = true
                    events.append(FlowEvent(key: key, kind: .named(name, .dns)))
                }
            }
            if !flow.named, !flow.finished, now - flow.start >= Self.finalizeAfter,
               let event = giveUp(on: &flow, at: key, reason: .timeout) {
                events.append(event)
            }
            if now - flow.lastSeen >= Self.idleAfter {
                flows[key] = nil
            } else {
                flows[key] = flow
            }
        }
        dnsMap.forget(arrivedBy: now - Self.dnsRemembered)
        queries.forget(sentBy: now - Self.queryAwaited)
        return events
    }

    /// The capture this namer reads is over: every flow still waiting for its handshake is
    /// given up on, as at a timeout.
    mutating func endCapture() -> [FlowEvent] {
        var events: [FlowEvent] = []
        for (key, var flow) in flows where !flow.finished {
            if let event = giveUp(on: &flow, at: key, reason: .captureEnded) { events.append(event) }
            flows[key] = flow
        }
        return events
    }

    private func giveUp(on flow: inout Flow, at key: FlowKey, reason: FlowEvent.Reason) -> FlowEvent? {
        flow.tlsBuffer = nil
        flow.quicDone = true
        flow.quicAssembly = QUICAssembly()
        if !flow.dnsTried, let name = dnsMap[key.remote] {
            flow.dnsTried = true
            flow.dnsNamed = true
            return FlowEvent(key: key, kind: .named(name, .dns))
        }
        return flow.dnsNamed ? nil : FlowEvent(key: key, kind: .unnamed(reason))
    }
}

/// DNS answers by address, kept past `FlowNamer.dnsCapacity` and until older than
/// `FlowNamer.dnsRemembered`, the oldest going first.
private struct DNSMap {
    private var entries: [IPAddress: (name: String, at: Double, serial: Int)] = [:]
    private var order = ArrivalOrder<IPAddress>()

    var count: Int { entries.count }

    subscript(address: IPAddress) -> String? { entries[address]?.name }

    mutating func insert(_ name: String, for address: IPAddress, at ts: Double) {
        entries[address] = (name, ts, order.append(address))
        while entries.count > FlowNamer.dnsCapacity { dropOldest(arrivedBy: nil) }
        order.sweep(capacity: FlowNamer.dnsCapacity, in: entries, serial: { $0.serial })
    }

    mutating func forget(arrivedBy cutoff: Double) {
        while dropOldest(arrivedBy: cutoff) {}
    }

    /// Removes the oldest answer, if it arrived by `cutoff` (or at all, for nil). False when
    /// nothing was removed.
    @discardableResult
    private mutating func dropOldest(arrivedBy cutoff: Double?) -> Bool {
        guard let address = order.oldest(in: entries, serial: { $0.serial }) else { return false }
        if let cutoff, entries[address]!.at > cutoff { return false }
        entries[address] = nil
        order.removeOldest()
        return true
    }
}

/// DNS queries this Mac sent and has no reply to yet, by what a reply must repeat: who was
/// asked, from which port, under which id, and the question. A query is here for that match
/// alone, and never more of them than `FlowNamer.queryCapacity`, the oldest going first. Its
/// reply takes its question out; `forget` drops the ones older than `FlowNamer.queryAwaited`
/// and what the order still lists of any that are gone, so nothing of a query outlasts the
/// first `forget` after its reply or its time.
private struct AwaitedQueries {
    struct Key: Hashable, Sendable {
        let resolver: IPAddress
        let port: UInt16
        let id: UInt16
    }

    private var entries: [Key: (question: DNS.Question, at: Double, serial: Int)] = [:]
    private var order = ArrivalOrder<Key>()

    var count: Int { entries.count }

    mutating func insert(_ question: DNS.Question, for key: Key, at ts: Double) {
        entries[key] = (question, ts, order.append(key))
        while entries.count > FlowNamer.queryCapacity { dropOldest(sentBy: nil) }
        order.sweep(capacity: FlowNamer.queryCapacity, in: entries, serial: { $0.serial })
    }

    /// Whether a query is waiting under `key`, sent after `cutoff`: asked before the reply
    /// is parsed, so a reply nobody is waiting for costs one lookup.
    func awaits(_ key: Key, sentAfter cutoff: Double) -> Bool {
        entries[key].map { $0.at > cutoff } ?? false
    }

    /// Takes the query under `key` out if `question` is what it asked. A reply to another
    /// question leaves it waiting for its own.
    mutating func take(_ key: Key, asking question: DNS.Question) -> Bool {
        guard entries[key]?.question == question else { return false }
        entries[key] = nil
        return true
    }

    mutating func forget(sentBy cutoff: Double) {
        while dropOldest(sentBy: cutoff) {}
        // The order keeps a query's resolver, port and id after its reply took it out, and
        // after it was dropped above until the list is next cut down.
        order.sweep(capacity: 0, in: entries, serial: { $0.serial })
    }

    /// Removes the oldest query, if it was sent by `cutoff` (or at all, for nil). False when
    /// nothing was removed.
    @discardableResult
    private mutating func dropOldest(sentBy cutoff: Double?) -> Bool {
        guard let key = order.oldest(in: entries, serial: { $0.serial }) else { return false }
        if let cutoff, entries[key]!.at > cutoff { return false }
        entries[key] = nil
        order.removeOldest()
        return true
    }
}

/// Keys in the order they arrived, so the oldest can go first without a sort. A key that
/// arrives again is appended anew; its earlier place is left behind, recognized by the
/// serial its owner keeps with the entry, and skipped.
private struct ArrivalOrder<Key: Hashable & Sendable>: Sendable {
    private var places: [(key: Key, serial: Int)] = []
    private var head = 0
    private var serial = 0

    /// Appends `key`, returning the serial for the owner to keep with its entry.
    mutating func append(_ key: Key) -> Int {
        serial += 1
        places.append((key, serial))
        return serial
    }

    /// One key arriving over and over leaves only stale places behind; sweeps them once
    /// they outnumber the capacity twice over.
    mutating func sweep<Value>(capacity: Int, in entries: [Key: Value], serial: (Value) -> Int) {
        guard places.count - head > 2 * capacity else { return }
        places = places[head...].filter { place in entries[place.key].map(serial) == place.serial }
        head = 0
    }

    /// The oldest key still in `entries`, skipping stale places on the way.
    mutating func oldest<Value>(in entries: [Key: Value], serial: (Value) -> Int) -> Key? {
        while head < places.count {
            let place = places[head]
            if entries[place.key].map(serial) == place.serial { return place.key }
            advance()
        }
        return nil
    }

    /// Drops the place `oldest` returned.
    mutating func removeOldest() {
        advance()
    }

    private mutating func advance() {
        head += 1
        if head >= places.count / 2 {
            places.removeFirst(head)
            head = 0
        }
    }
}
