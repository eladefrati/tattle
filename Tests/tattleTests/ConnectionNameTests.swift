import XCTest
@testable import tattle

final class ConnectionNameTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    private func connection(_ remote: String, port: UInt16 = 443, v6: Bool = false, proto: SocketEntry.Proto = .tcp) -> Connection {
        Connection(id: "100:\(proto.rawValue)/50000>\(remote):\(port)", proto: proto, pid: 100, uid: 501, localPort: 50000,
                   remoteAddress: remote, remotePort: port, isIPv6: v6, scope: .remote, tcpState: proto == .tcp ? 4 : nil,
                   firstSeen: t0, lastSeen: t0, ended: nil, preExisting: false, direction: .outbound)
    }

    /// A row first seen just after the flow opened is that connection; an old opening is
    /// an earlier connection on the same four-tuple.
    func testPendingNamesSaysWhetherAnOpeningWasJustSeen() {
        var table = PendingNames()
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 1, 1, 1]), remotePort: 443)
        XCTAssertFalse(table.openingSeen(key.text, at: t0))
        _ = table.apply([FlowEvent(key: key, kind: .opened)], at: t0, kind: { _, _ in .destination })
        XCTAssertTrue(table.openingSeen(key.text, at: t0 + 2))
        XCTAssertFalse(table.openingSeen(key.text, at: t0 + 10))
    }

    func testFlowKeyMatchesWhatTheSnifferSees() {
        XCTAssertEqual(connection("17.253.144.10").flowKey, "tcp/50000>17.253.144.10:443")
        XCTAssertEqual(connection("2606:4700::1111", v6: true, proto: .udp).flowKey, "udp/50000>2606:4700::1111:443")
        XCTAssertEqual(connection("::ffff:17.253.144.10", v6: true).flowKey, "tcp/50000>17.253.144.10:443", "an IPv6 socket talking IPv4 is IPv4 on the wire")
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 253, 144, 10]), remotePort: 443)
        XCTAssertEqual(key.text, connection("17.253.144.10").flowKey)
    }

    func testKindFromRuleCategory() {
        XCTAssertEqual(ConnectionName.kind(forCategory: "relay"), .relay)
        XCTAssertEqual(ConnectionName.kind(forCategory: "ech-cover"), .hidden)
        XCTAssertEqual(ConnectionName.kind(forCategory: "cdn"), .destination)
        XCTAssertEqual(ConnectionName.kind(forCategory: nil), .destination)
    }

    func testTitleExplainKeyAndFactsByKind() {
        let owner = ConnectionOwner(processName: "Safari")
        let unnamed = LiveConnection(connection: connection("17.253.144.10"), owner: owner, isNew: false)
        XCTAssertEqual(unnamed.title, "17.253.144.10:443")
        XCTAssertEqual(unnamed.explainKey, "17.253.144.10")
        XCTAssertEqual(LiveConnection(connection: connection("::ffff:17.253.144.10"), owner: owner, isNew: false).explainKey, "17.253.144.10")
        var facts = Dictionary(unnamed.facts(now: t0).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Destination"], "17.253.144.10:443")
        XCTAssertNil(facts["Address"])
        XCTAssertNil(facts["Name from"])

        let named = LiveConnection(connection: connection("17.253.144.10"), owner: owner, isNew: false,
                                   outcome: .named(ConnectionName(name: "www.apple.com", source: .sni, kind: .destination)))
        XCTAssertEqual(named.title, "www.apple.com")
        XCTAssertEqual(named.explainKey, "www.apple.com")
        facts = Dictionary(named.facts(now: t0).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Destination"], "www.apple.com")
        XCTAssertEqual(facts["Address"], "17.253.144.10:443")
        XCTAssertEqual(facts["Name from"], "what the program asked for in its TLS handshake", "the program's word, not what the address is")
        XCTAssertEqual(NameSource.quic.text, "what the program asked for in its QUIC handshake")
        XCTAssertEqual(NameSource.http.text, "what the program asked for in its HTTP request")

        let relayed = LiveConnection(connection: connection("17.253.144.10"), owner: owner, isNew: false,
                                     outcome: .named(ConnectionName(name: "mask.icloud.com", source: .quic, kind: .relay)))
        XCTAssertEqual(relayed.title, "relayed", "a relay's name is never shown as the destination")
        XCTAssertEqual(relayed.explainKey, "mask.icloud.com", "but the knowledge base explains the relay")
        facts = Dictionary(relayed.facts(now: t0).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Destination"], "hidden inside a relay")
        XCTAssertEqual(facts["Relay"], "mask.icloud.com")

        let hidden = LiveConnection(connection: connection("104.16.0.1"), owner: owner, isNew: false,
                                    outcome: .named(ConnectionName(name: "cloudflare-ech.com", source: .sni, kind: .hidden)))
        XCTAssertEqual(hidden.title, "name hidden")
        facts = Dictionary(hidden.facts(now: t0).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Cover name"], "cloudflare-ech.com")

        let dns = LiveConnection(connection: connection("17.253.144.10"), owner: owner, isNew: false,
                                 outcome: .named(ConnectionName(name: "cdn.example.net", source: .dns, kind: .destination)))
        XCTAssertEqual(dns.facts(now: t0).first { $0.name == "Name from" }?.value, "a DNS reply for the address", "marked, because the DNS map is ambiguous")
        // ADR-0001 decision 2: a DNS name is marked wherever it is shown, row and counts.
        XCTAssertEqual(dns.title, "cdn.example.net")
        XCTAssertTrue(dns.isFromDNS)
        XCTAssertFalse(named.isFromDNS)
        XCTAssertFalse(unnamed.isFromDNS)

        let snapshot = NetworkSnapshot(connections: [unnamed, named, relayed, hidden, dns], takenAt: t0)
        XCTAssertEqual(snapshot.namedCount, 1, "named from the connection's own packets")
        XCTAssertEqual(snapshot.dnsCount, 1)
        XCTAssertEqual(snapshot.relayedCount, 1)
        XCTAssertEqual(snapshot.hiddenCount, 1)
    }

    func testPendingNamesKeepsNamesForOpenFlowsAndForgetsTheRest() {
        var table = PendingNames()
        let apple = NameOutcome.named(ConnectionName(name: "www.apple.com", source: .sni, kind: .destination))
        table.set(apple, for: "tcp/50000>17.1.1.1:443", at: t0)
        table.set(.unnamed(.timeout), for: "udp/50001>1.1.1.1:443", at: t0 + 100)
        XCTAssertEqual(table.outcome(for: "tcp/50000>17.1.1.1:443"), apple)
        XCTAssertEqual(table.outcome(for: "udp/50001>1.1.1.1:443"), .unnamed(.timeout), "no name is an answer too")
        XCTAssertNil(table.outcome(for: "tcp/50000>17.1.1.1:80"))

        table.prune(now: t0 + PendingNames.keepFor + 1, keeping: ["tcp/50000>17.1.1.1:443"])
        XCTAssertEqual(table.count, 2, "the open flow's name stays past its age; the other is still young")
        table.prune(now: t0 + 100 + PendingNames.keepFor + 1, keeping: [])
        XCTAssertEqual(table.count, 0)

        table.set(apple, for: "k", at: t0)
        table.set(.named(ConnectionName(name: "later.apple.com", source: .dns, kind: .destination)), for: "k", at: t0 + 1)
        XCTAssertEqual(table.outcome(for: "k")?.name?.name, "later.apple.com", "the latest outcome wins")
    }

    /// A flow that no connection claims was held for five minutes, so what was held grew with
    /// the rate flows opened at, and each reading walked all of it.
    func testPendingNamesHoldsAtMostItsCapacityAndDropsTheOldest() {
        var table = PendingNames()
        func key(_ number: Int) -> FlowKey {
            FlowKey(proto: .tcp, localPort: UInt16(1024 + number % 60000), remote: IPAddress(bytes: [11, UInt8(number >> 16), UInt8(number >> 8 & 0xff), UInt8(number & 0xff)]), remotePort: 443)
        }
        let count = 3 * PendingNames.capacity
        for number in 0..<count {
            _ = table.apply([FlowEvent(key: key(number), kind: .opened), FlowEvent(key: key(number), kind: .named("h\(number).example", .sni))],
                            at: t0 + Double(number) / 1000) { _, _ in .destination }
            XCTAssertLessThanOrEqual(table.count, PendingNames.capacity)
            XCTAssertLessThanOrEqual(table.openingCount, PendingNames.capacity)
        }
        XCTAssertGreaterThanOrEqual(table.count, PendingNames.capacity * 3 / 4)
        let now = t0 + Double(count) / 1000
        let newest = key(count - 1), kept = key(count - PendingNames.capacity * 3 / 4), oldest = key(0)
        XCTAssertEqual(table.outcome(for: newest.text)?.name?.name, "h\(count - 1).example")
        XCTAssertTrue(table.openingSeen(newest.text, at: now))
        XCTAssertNotNil(table.outcome(for: kept.text), "the newest three quarters of a capacity are always held")
        XCTAssertNil(table.outcome(for: oldest.text), "the oldest went")
        XCTAssertFalse(table.openingSeen(oldest.text, at: t0 + 1), "and its opening")
    }

    /// A connection the table still shows after another opened on its four-tuple keeps
    /// waiting: the outcome is the later connection's, as it is for the row and for history.
    func testAnOutcomeWaitsForItsOwnConnection() {
        var table = PendingNames()
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 1, 1, 1]), remotePort: 443)
        _ = table.apply([FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("new.example.com", .sni))], at: t0 + 60) { _, _ in .destination }
        var older = connection("17.1.1.1")
        XCTAssertEqual(older.flowKey, key.text)
        XCTAssertNil(table.outcome(for: older), "first seen a minute before the flow opened")
        older.firstSeen = t0 + 60
        XCTAssertEqual(table.outcome(for: older)?.name?.name, "new.example.com")
    }

    /// Local ports are reused: a connection that opens on the four-tuple of one that closed a
    /// minute ago is a different connection and must not show the old one's name.
    func testAnOpenedFlowStartsWithoutThePreviousConnectionsOutcome() {
        var table = PendingNames()
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 1, 1, 1]), remotePort: 443)
        let destination: (String, NameSource) -> ConnectionName.Kind = { _, _ in .destination }
        let attached = table.apply([FlowEvent(key: key, kind: .named("old.example.com", .sni))], at: t0, kind: destination)
        XCTAssertEqual(attached.map(\.outcome.name?.name), ["old.example.com"])

        XCTAssertTrue(table.apply([FlowEvent(key: key, kind: .opened)], at: t0 + 60, kind: destination).isEmpty)
        XCTAssertNil(table.outcome(for: key.text), "the new connection waits for its own outcome")

        _ = table.apply([FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("new.example.com", .quic))], at: t0 + 120, kind: destination)
        XCTAssertEqual(table.outcome(for: key.text)?.name?.name, "new.example.com", "an outcome in the same batch as the open is kept")
        let later = table.apply([FlowEvent(key: key, kind: .unnamed(.timeout))], at: t0 + 140, kind: destination)
        XCTAssertEqual(later.map(\.openedAt), [t0 + 120], "history is told when the flow opened, so older rows are left alone")
    }

    /// A client may keep its UDP socket, or bind a new one to the same port, for a second
    /// QUIC connection to the same server. The socket table then shows one connection all
    /// along. The namer restarts the flow on the second connection's first Initial, and the
    /// row, live and in history, takes the second connection's outcome.
    func testAQUICRestartOnAReusedPortRenamesItsRow() throws {
        let store = ConnectionStore(database: try AppDatabase.inMemory())
        let me = IPAddress(bytes: [192, 168, 1, 5])
        let peer = IPAddress(bytes: [17, 253, 144, 10])
        let row = connection(peer.text, proto: .udp)
        var snapshot = NetworkSnapshot(connections: [LiveConnection(connection: row, owner: ConnectionOwner(processName: "Safari"), isNew: true)], takenAt: t0)
        try store.open(ConnectionRecord(row, processName: "Safari"))
        var namer = FlowNamer(localAddresses: [me], resolvers: [])
        var names = PendingNames()
        func send(_ datagram: [UInt8], at date: Date) throws {
            let packet = Packet(src: me, dst: peer, srcPort: 50000, dstPort: 443, proto: .udp, tcpFlags: 0, tcpSeq: 0, payload: datagram[...])
            for (flow, outcome, openedAt) in names.apply(namer.observe(packet, at: date.timeIntervalSince1970), at: date, kind: { _, _ in .destination }) {
                _ = snapshot.attach(outcome, to: flow, openedAt: openedAt)
                try store.record(outcome, flow: flow, openedAt: openedAt)
            }
        }
        func initial(sni: String, dcid: [UInt8]) -> [UInt8] {
            let hello = SnifferParserTests.clientHello(sni: Array(sni.utf8))
            return SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello, dcid: dcid)
        }

        try send(SnifferParserTests.rfcInitial, at: t0)
        XCTAssertEqual(snapshot.connections[0].name?.name, "example.com", "the first connection")
        XCTAssertEqual(try store.history(remoteAddress: peer.text).map(\.name), ["example.com"])

        try send(initial(sni: "example.org", dcid: [1, 2, 3, 4, 5, 6, 7, 8]), at: t0 + 30)
        XCTAssertEqual(snapshot.connections[0].name?.name, "example.org", "the second connection, on the same live row")
        XCTAssertEqual(snapshot.connections[0].connection.firstSeen, t0, "which keeps its duration")
        XCTAssertTrue(snapshot.connections[0].isNew)
        XCTAssertEqual(try store.history(remoteAddress: peer.text).map(\.name), ["example.org"], "history keeps only the latest name")

        try send(initial(sni: "", dcid: [9, 9, 9, 9, 9, 9, 9, 9]), at: t0 + 60)
        XCTAssertNil(snapshot.connections[0].name)
        XCTAssertEqual(snapshot.connections[0].unnamedReason, .noServerName, "a third connection's reason replaces the name")
        XCTAssertEqual(try store.history(remoteAddress: peer.text).map(\.nameSource), ["none:no-server-name"])

        try store.close(key: row.id, lastSeen: t0 + 70, ended: t0 + 72)
        try send(initial(sni: "example.net", dcid: [7, 7, 7, 7, 7, 7, 7, 7]), at: t0 + 90)
        XCTAssertEqual(try store.history(remoteAddress: peer.text).map(\.nameSource), ["none:no-server-name"],
                       "a closed row is not the new connection's: its own row takes the name when the poll adds it")
    }

    func testATCPFlowLeavesAnOlderOpenRowAlone() throws {
        let store = ConnectionStore(database: try AppDatabase.inMemory())
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 1, 1, 1]), remotePort: 443)
        let old = NameOutcome.named(ConnectionName(name: "old.example.com", source: .sni, kind: .destination))
        let row = connection(key.remote.text)
        var snapshot = NetworkSnapshot(connections: [LiveConnection(connection: row, owner: ConnectionOwner(processName: "Safari"), isNew: false, outcome: old)], takenAt: t0)
        var record = ConnectionRecord(row, processName: "Safari")
        record.name = "old.example.com"
        record.nameSource = "sni"
        try store.open(record)

        var names = PendingNames()
        let events = [FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("new.example.com", .sni))]
        for (flow, outcome, openedAt) in names.apply(events, at: t0 + 60, kind: { _, _ in .destination }) {
            XCTAssertFalse(snapshot.attach(outcome, to: flow, openedAt: openedAt), "the new connection waits for its own row")
            try store.record(outcome, flow: flow, openedAt: openedAt)
        }
        XCTAssertEqual(snapshot.connections[0].name?.name, "old.example.com")
        XCTAssertEqual(try store.history(remoteAddress: key.remote.text).map(\.name), ["old.example.com"])
        XCTAssertEqual(names.outcome(for: key.text)?.name?.name, "new.example.com", "kept for the row the next poll adds")
    }

    func testPendingNamesTellsTheKindClosureWhereTheNameCameFrom() {
        var table = PendingNames()
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: IPAddress(bytes: [17, 1, 1, 1]), remotePort: 443)
        var seen: [NameSource] = []
        _ = table.apply([FlowEvent(key: key, kind: .named("a.example", .dns))], at: t0) { _, source in
            seen.append(source)
            return .destination
        }
        XCTAssertEqual(seen, [.dns])
    }

    /// A DNS reply names an address, not a connection, and may be an attacker's: it can say
    /// where a row goes only as a marked guess, never that the row is hidden (ADR-0001, 2).
    @MainActor
    func testADnsNameIsNeverClassifiedAsRelayOrHidden() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        try rules.replaceShipped(source: .builtin, with: [
            Rule(kind: .host, pattern: "relay.example", purpose: "p", category: "relay", source: .builtin),
            Rule(kind: .host, pattern: "cover.example", purpose: "p", category: "ech-cover", source: .builtin),
        ])
        let observer = NetworkObserver(store: ConnectionStore(database: database), rules: rules,
                                       settings: try AppSettings(store: SettingsStore(database: database)))
        XCTAssertEqual(observer.kind(of: "relay.example", source: .sni), .relay)
        XCTAssertEqual(observer.kind(of: "cover.example", source: .quic), .hidden)
        XCTAssertEqual(observer.kind(of: "relay.example", source: .dns), .destination)
        XCTAssertEqual(observer.kind(of: "cover.example", source: .dns), .destination)
        XCTAssertEqual(observer.kind(of: "relay.example", source: .sni), .relay, "a DNS lookup does not poison the memo")
    }

    /// Every handshake can carry a name no other has, and the sender picks it: the memo of
    /// kinds grew by one for each, for as long as no rule was written.
    @MainActor
    func testTheKindsRememberedAreCapped() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        try rules.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "relay.example", purpose: "p", category: "relay", source: .builtin)])
        let observer = try observer(rules: rules, database: database)
        for number in 0..<(NetworkObserver.kindCapacity + 100) {
            XCTAssertEqual(observer.kind(of: "h\(number).example", source: .sni), .destination)
        }
        XCTAssertLessThanOrEqual(observer.held.kinds, NetworkObserver.kindCapacity)
        XCTAssertEqual(observer.kind(of: "relay.example", source: .sni), .relay, "a name is still looked up once the memo has started again")
    }

    private func opening(_ number: Int) -> FlowEvent {
        FlowEvent(key: FlowKey(proto: .tcp, localPort: UInt16(1024 + number % 60000), remote: IPAddress(bytes: [11, 0, UInt8(number >> 8 & 0xff), UInt8(number & 0xff)]), remotePort: 443),
                  kind: .opened)
    }

    func testTheMailboxHoldsAtMostItsCapacityAndCountsTheRest() {
        let mailbox = FlowEventMailbox()
        let events = (0..<(FlowEventMailbox.capacity + 500)).map(opening)
        XCTAssertTrue(mailbox.add(Array(events.prefix(100))), "nothing drains it yet: the caller starts a drain")
        XCTAssertFalse(mailbox.add(Array(events.dropFirst(100))), "one drain at a time")
        var taken: [FlowEvent] = [], dropped = 0
        while let next = mailbox.take(64) {
            XCTAssertLessThanOrEqual(next.events.count, 64)
            taken += next.events
            dropped += next.dropped
        }
        XCTAssertEqual(taken, Array(events.prefix(FlowEventMailbox.capacity)), "the oldest, in order")
        XCTAssertEqual(dropped, 500)
        XCTAssertTrue(mailbox.add([opening(0)]), "the drain ended, so the next events start one")
    }

    /// Each capture read queued a task of its own on the main actor, which handled all of a
    /// read's events in one turn: events arriving faster than they were handled queued without
    /// limit and held the main thread for as long as they took.
    @MainActor
    func testEventsReachTheMainActorABatchATurnAndNoMoreThanTheMailboxHolds() async throws {
        let database = try AppDatabase.inMemory()
        var deliver: (@Sendable ([FlowEvent]) -> Void)?
        let observer = NetworkObserver(store: ConnectionStore(database: database), rules: try RuleStore(database: database),
                                       settings: try AppSettings(store: SettingsStore(database: database)),
                                       socketTable: { [] }, processRecords: { nil },
                                       sniffer: { onEvents, onStatus in
                                           deliver = onEvents
                                           return Sniffer(open: { _ in throw CaptureError.open(errno: EACCES) }, onEvents: onEvents, onStatus: onStatus)
                                       })
        observer.start()
        defer { observer.stop() }
        let deliverEvents = try XCTUnwrap(deliver)
        deliverEvents((0..<100).map(opening))
        deliverEvents((100..<(FlowEventMailbox.capacity + 300)).map(opening))

        // Each turn this test gets, the count has grown by whole batches, and by a single one
        // whenever only one turn of the drain came in between.
        var smallestStep = Int.max, seen = 0
        let deadline = Date().addingTimeInterval(10)
        while seen < FlowEventMailbox.capacity, Date() < deadline {
            await Task.yield()
            let now = observer.held.openings
            if now > seen { smallestStep = min(smallestStep, now - seen) }
            seen = now
        }
        XCTAssertEqual(smallestStep, NetworkObserver.eventBatch, "a batch a turn, with turns for others in between")
        XCTAssertEqual(observer.held.openings, FlowEventMailbox.capacity, "all the mailbox held")
        XCTAssertEqual(observer.eventsDropped, 300, "and none of what it had no room for")
    }

    @MainActor
    private func observer(rules: RuleStore, database: AppDatabase) throws -> NetworkObserver {
        NetworkObserver(store: ConnectionStore(database: database), rules: rules,
                        settings: try AppSettings(store: SettingsStore(database: database)))
    }

    /// An LLM answer's category is free text from a process Tattle does not control: it must
    /// not decide that a host's name is hidden from every later row.
    @MainActor
    func testOnlyShippedRulesDecideAKind() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        let observer = try observer(rules: rules, database: database)
        try rules.save(Rule(kind: .host, pattern: "llm.example", purpose: "p", category: "relay", source: .llm))
        try rules.save(Rule(kind: .host, pattern: "confirmed.example", purpose: "p", category: "ech-cover", source: .llm, confirmed: t0))
        XCTAssertEqual(observer.kind(of: "llm.example", source: .sni), .destination)
        XCTAssertEqual(observer.kind(of: "confirmed.example", source: .sni), .destination, "confirming ranks it higher, it is still a model's text")

        // A model rule that outranks the seed (confirmed) must not mask the seed's category.
        try rules.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "seeded.example", purpose: "p", category: "relay", source: .builtin)])
        try rules.save(Rule(kind: .host, pattern: "seeded.example", purpose: "p", category: "cdn", source: .llm, confirmed: t0))
        XCTAssertEqual(observer.kind(of: "seeded.example", source: .sni), .relay)
    }

    @MainActor
    func testARuleShippedLaterIsSeenByTheNextLookup() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        let observer = try observer(rules: rules, database: database)
        XCTAssertEqual(observer.kind(of: "late.example", source: .sni), .destination)
        try rules.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "late.example", purpose: "p", category: "relay", source: .builtin)])
        XCTAssertEqual(observer.kind(of: "late.example", source: .sni), .relay)

        try rules.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "late.example", purpose: "p", category: "ech-cover", source: .builtin)])
        XCTAssertEqual(observer.kind(of: "late.example", source: .sni), .hidden, "the same key was replaced")
    }

    /// What a name is comes from the shipped rules, in memory: the file, which another
    /// process can damage, has no say in it.
    @MainActor
    func testAFileThatCannotBeReadDoesNotChangeAKind() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        let observer = try observer(rules: rules, database: database)
        try rules.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "relay.example", purpose: "p", category: "relay", source: .builtin)])
        try database.writer.write { try $0.execute(sql: "ALTER TABLE rule RENAME TO away") }
        XCTAssertThrowsError(try rules.candidates(kind: .host, key: "relay.example"))
        XCTAssertEqual(observer.kind(of: "relay.example", source: .sni), .relay)
    }

    func testPromptFactsOfAConnectionCarryNoLoginOrSigner() {
        let login = String(cString: getpwuid(getuid()).pointee.pw_name)
        var mine = connection("17.253.144.10")
        mine.uid = getuid()
        let owner = ConnectionOwner(processName: "Mine", signature: CodeSignature(signer: .development, teamIdentifier: "ABCDE12345"))
        let row = LiveConnection(connection: mine, owner: owner, isNew: false)
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .host, key: "x.example", facts: row.facts(now: t0)), redactor: .addressesOnly)
        XCTAssertEqual(row.facts(now: t0).first { $0.name == "Runs as" }?.value, "you (\(login))", "the panel is unchanged")
        XCTAssertFalse(sent.contains("you ("), sent)
        XCTAssertFalse(sent.contains("Apple Development"), "nor is the owner's signer told about a host: \(sent)")
    }

    func testEveryDnsNameIsMarkedWhateverItsKind() {
        let owner = ConnectionOwner(processName: "Safari")
        for kind in [ConnectionName.Kind.destination, .relay, .hidden] {
            let row = LiveConnection(connection: connection("17.253.144.10"), owner: owner, isNew: false,
                                     outcome: .named(ConnectionName(name: "x.example", source: .dns, kind: kind)))
            XCTAssertTrue(row.isFromDNS, "\(kind)")
        }
    }

    func testUnnamedReasonOnTheRowAndInHistoryCodes() {
        let owner = ConnectionOwner(processName: "RCMservice")
        let silent = LiveConnection(connection: connection("40.82.255.130", port: 80), owner: owner, isNew: false, outcome: .unnamed(.timeout))
        XCTAssertNil(silent.name)
        XCTAssertEqual(silent.title, "40.82.255.130:80")
        XCTAssertEqual(silent.facts(now: t0).first { $0.name == "No name" }?.value, "no complete handshake came in the connection's first 20 seconds")
        XCTAssertNil(LiveConnection(connection: connection("1.1.1.1"), owner: owner, isNew: false).facts(now: t0).first { $0.name == "No name" }, "nothing to say until the sniffer gives up")

        for reason in [FlowEvent.Reason.notHandshake, .gap, .noServerName, .quic(.unsupportedVersion), .quic(.decryptFailed), .timeout, .evicted, .captureEnded] {
            XCTAssertTrue(reason.code.hasPrefix("none:"), "a reason is never mistaken for a source")
        }
    }
}
