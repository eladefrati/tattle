import CPacketCapture
import os
import XCTest
@testable import tattle

final class SnifferTests: XCTestCase {
    /// A record of no length would leave the walk where it is, and the read loop would spin.
    /// A real Ethernet record has a header length of 18, below the struct's 20, and still walks.
    func testTheCaptureWalkEndsAtARecordThatWouldNotAdvance() {
        var buffer = [UInt8](repeating: 0, count: 64)
        var timestamp = 0.0, dataOffset = 0, next = 0
        var caplen: UInt32 = 0
        XCTAssertEqual(tattle_capture_next(buffer, buffer.count, 0, &timestamp, &dataOffset, &caplen, &next), 0)

        withUnsafeBytes(of: UInt32(10).littleEndian) { buffer.replaceSubrange(8..<12, with: $0) }  // bh_caplen
        withUnsafeBytes(of: UInt16(18).littleEndian) { buffer.replaceSubrange(16..<18, with: $0) }  // bh_hdrlen
        XCTAssertEqual(tattle_capture_next(buffer, buffer.count, 0, &timestamp, &dataOffset, &caplen, &next), 1)
        XCTAssertEqual(dataOffset, 18)
        XCTAssertEqual(caplen, 10)
        XCTAssertEqual(next, 28)
    }

    /// ADR-0003: other software can have made the devices readable, and then Tattle opens one
    /// itself, with no broker or with one that gives it nothing.
    func testTheDeviceIsOpenedWhenThereIsNoBrokerOrItGivesNoCapture() throws {
        let refused: () throws -> String = { throw CaptureBroker.RequestError.refused }
        let unreadable: () throws -> String = { throw CaptureError.open(errno: EACCES) }
        XCTAssertEqual(try PacketCapture.obtain(broker: { "broker" }, device: { "device" }), "broker")
        XCTAssertEqual(try PacketCapture.obtain(broker: nil, device: { "device" }), "device")
        XCTAssertEqual(try PacketCapture.obtain(broker: refused, device: { "device" }), "device")
        XCTAssertThrowsError(try PacketCapture.obtain(broker: refused, device: unreadable)) {
            XCTAssertEqual($0 as? CaptureError, .broker(.refused), "what the broker said, not that the device is root's")
        }
        XCTAssertThrowsError(try PacketCapture.obtain(broker: nil, device: unreadable)) {
            XCTAssertEqual($0 as? CaptureError, .open(errno: EACCES))
        }
    }

    private func eventually(within seconds: TimeInterval = 3, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() && Date() < deadline { usleep(20_000) }
        return condition()
    }

    private final class FakeCapture: CaptureSource, @unchecked Sendable {
        let dataLinkType: UInt32
        private let filters = OSAllocatedUnfairLock<[CaptureFilter]>(initialState: [])
        init(linkType: UInt32) { dataLinkType = linkType }
        var installed: [CaptureFilter] { filters.withLock { $0 } }
        func install(_ filter: CaptureFilter) throws { filters.withLock { $0.append(filter) } }
        func readPackets(_ handle: (Double, [UInt8]) -> Void) throws { usleep(10_000) }
    }

    /// The kernel filter tells outbound from the interface's hardware address, or on a tunnel
    /// from its addresses. When either changes under an open capture (a private Wi-Fi address
    /// rotates, a tunnel is renumbered) the old test would class every outbound packet as
    /// inbound and drop it, so the filter is rebuilt.
    func testTheFilterFollowsTheInterfacesAddresses() {
        let mac = OSAllocatedUnfairLock(initialState: [UInt8]([0x2a, 0, 0, 0, 0, 1]))
        let ethernet = FakeCapture(linkType: PacketCapture.linkEthernet)
        let wifi = Sniffer(open: { _ in ethernet },
                           host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in mac.withLock { $0 } }, gatewayHardwareAddresses: { _ in [] },
                                              addresses: { _ in [] }, interfaceCheckEvery: 0.05),
                           onEvents: { _ in }, onStatus: { _ in })
        wifi.start()
        XCTAssertTrue(eventually { ethernet.installed.count == 1 })
        mac.withLock { $0 = [0x2a, 0, 0, 0, 0, 2] }
        XCTAssertTrue(eventually { ethernet.installed.count == 2 }, "rebuilt for the new hardware address")
        XCTAssertEqual(ethernet.installed.last, CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress([0x2a, 0, 0, 0, 0, 2])))
        usleep(300_000)  // six more checks of the interface
        wifi.stop()
        XCTAssertEqual(ethernet.installed.count, 2, "and not again while nothing changed")

        let address = OSAllocatedUnfairLock(initialState: IPAddress(bytes: [10, 8, 0, 2]))
        let tunnel = FakeCapture(linkType: PacketCapture.linkNull)
        let vpn = Sniffer(open: { _ in tunnel },
                          host: Sniffer.Host(primaryInterface: { "utun4" }, hardwareAddress: { _ in nil },
                                             addresses: { _ in [address.withLock { $0 }] }, interfaceCheckEvery: 0.05),
                          onEvents: { _ in }, onStatus: { _ in })
        defer { vpn.stop() }
        vpn.start()
        XCTAssertTrue(eventually { tunnel.installed.count == 1 })
        address.withLock { $0 = IPAddress(bytes: [10, 8, 0, 3]) }
        XCTAssertTrue(eventually { tunnel.installed.count == 2 }, "rebuilt for the tunnel's new address")
        XCTAssertEqual(tunnel.installed.last, CaptureFilter.program(linkType: PacketCapture.linkNull, direction: .sourceAddresses([[10, 8, 0, 3]])))
    }

    /// A restart (after the broker is installed or removed) must end the old run: a run left
    /// going keeps its own capture device and reports every flow a second time.
    func testRestartEndsThePreviousRunBeforeTheNextBegins() {
        let statuses = OSAllocatedUnfairLock<[Sniffer.Status]>(initialState: [])
        let sniffer = Sniffer(open: { _ in throw CaptureError.open(errno: EACCES) },
                              onEvents: { _ in },
                              onStatus: { status in statuses.withLock { $0.append(status) } })
        defer { sniffer.stop() }
        sniffer.start()
        XCTAssertTrue(eventually { !statuses.withLock { $0 }.isEmpty }, "the first run reports its failure")
        let failure = statuses.withLock { $0[0] }

        sniffer.stop()
        sniffer.start()
        XCTAssertTrue(eventually { statuses.withLock { $0 }.count >= 3 })
        XCTAssertEqual(Array(statuses.withLock { $0 }.prefix(3)), [failure, .stopped, failure],
                       "the first run stopped before the second reported")
    }

    /// A raw-IP capture whose reads fail, as a device does that went away under it.
    private final class Failing: CaptureSource, @unchecked Sendable {
        let dataLinkType = PacketCapture.linkRaw
        func install(_ filter: CaptureFilter) throws {}
        func readPackets(_ handle: (Double, [UInt8]) -> Void) throws { throw CaptureError.read(errno: ENXIO) }
    }

    /// A device that opens and then fails every read was reopened at once, over and over:
    /// thousands of broker requests a second. Each failure now waits before the next open,
    /// twice as long as the one before, says it is not capturing, and still ends at a stop.
    func testAFailedReadWaitsLongerEachTimeBeforeReopening() {
        let opens = OSAllocatedUnfairLock<[Date]>(initialState: [])
        let healthy = OSAllocatedUnfairLock(initialState: false)
        let statuses = OSAllocatedUnfairLock<[Sniffer.Status]>(initialState: [])
        let sniffer = Sniffer(open: { _ in
                                  opens.withLock { $0.append(Date()) }
                                  return healthy.withLock { $0 } ? FakeCapture(linkType: PacketCapture.linkRaw) : Failing()
                              },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in nil },
                                                 addresses: { _ in [Self.me] }, resolvers: { [] }, readRetryAfter: 0.1),
                              onEvents: { _ in }, onStatus: { status in statuses.withLock { $0.append(status) } })
        defer { sniffer.stop() }
        sniffer.start()
        // Opens at 0, then after waits of 0.1, 0.2, 0.4 and 0.8 s: four by 0.7 s, the fifth at 1.5 s.
        usleep(1_100_000)
        let times = opens.withLock { $0 }
        XCTAssertGreaterThanOrEqual(times.count, 3, "it keeps trying")
        XCTAssertLessThanOrEqual(times.count, 4, "but not at once: \(times.count) opens in 1.1 s")
        if times.count >= 4 {
            XCTAssertGreaterThan(times[3].timeIntervalSince(times[2]), 1.5 * times[1].timeIntervalSince(times[0]), "each wait is longer than the first")
        }
        let failed = Sniffer.Status.unavailable(.read(errno: ENXIO))
        XCTAssertEqual(Array(statuses.withLock { $0 }.prefix(4)), [.capturing(interface: "en0"), failed, .capturing(interface: "en0"), failed],
                       "while it waits it says why it is not capturing")

        healthy.withLock { $0 = true }
        XCTAssertTrue(eventually { statuses.withLock { $0 }.last == .capturing(interface: "en0") }, "a device that reads again is captured again")
        let settled = opens.withLock { $0 }.count
        usleep(300_000)
        XCTAssertEqual(opens.withLock { $0 }.count, settled, "and is not reopened")

        // A stop during a wait ends the run without waiting it out.
        healthy.withLock { $0 = false }
        let waiting = Sniffer(open: { _ in Failing() },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in nil },
                                                 addresses: { _ in [Self.me] }, resolvers: { [] }, readRetryAfter: 20),
                              onEvents: { _ in }, onStatus: { status in statuses.withLock { $0.append(status) } })
        statuses.withLock { $0 = [] }
        sniffer.stop()
        XCTAssertTrue(eventually { statuses.withLock { $0 }.last == .stopped })
        waiting.start()
        XCTAssertTrue(eventually { statuses.withLock { $0 }.last == failed }, "waiting 20 s to reopen")
        waiting.stop()
        XCTAssertTrue(eventually(within: 2) { statuses.withLock { $0 }.last == .stopped }, "stopped within the wait")
    }

    /// A read fails when its interface goes away, and the default route is by then often on
    /// another: a wait before reopening would only miss the connections opened meanwhile.
    /// The first failed read in a row reopens at once when the route has left the interface;
    /// the next one waits wherever the route is, or two interfaces failing by turns would be
    /// opened as fast as the broker answers.
    func testAFailedReadOnAnInterfaceTheRouteHasLeftReopensAtOnce() {
        let route = OSAllocatedUnfairLock(initialState: "utun4")
        let statuses = OSAllocatedUnfairLock<[Sniffer.Status]>(initialState: [])
        func host() -> Sniffer.Host {
            Sniffer.Host(primaryInterface: { route.withLock { $0 } }, hardwareAddress: { _ in nil },
                         addresses: { _ in [Self.me] }, resolvers: { [] }, readRetryAfter: 20)
        }
        let sniffer = Sniffer(open: { interface in
                                  guard interface == "utun4" else { return FakeCapture(linkType: PacketCapture.linkRaw) }
                                  route.withLock { $0 = "en0" }
                                  return Failing()
                              },
                              host: host(), onEvents: { _ in }, onStatus: { status in statuses.withLock { $0.append(status) } })
        sniffer.start()
        XCTAssertTrue(eventually { statuses.withLock { $0 }.last == .capturing(interface: "en0") }, "reopened where the route is, without the 20 s wait")
        XCTAssertEqual(statuses.withLock { $0 }, [.capturing(interface: "utun4"), .capturing(interface: "en0")], "and never said it was not capturing")
        sniffer.stop()

        route.withLock { $0 = "utun4" }
        let opens = OSAllocatedUnfairLock<[String]>(initialState: [])
        let byTurns = Sniffer(open: { interface in
                                  opens.withLock { $0.append(interface) }
                                  route.withLock { $0 = interface == "utun4" ? "en0" : "utun4" }
                                  return Failing()
                              },
                              host: host(), onEvents: { _ in }, onStatus: { _ in })
        defer { byTurns.stop() }
        byTurns.start()
        XCTAssertTrue(eventually { opens.withLock { $0 }.count >= 2 })
        usleep(500_000)
        XCTAssertEqual(opens.withLock { $0 }, ["utun4", "en0"], "the second failure in a row waits, though the route moved again")

        // No default route is not a route elsewhere: there is nothing to reopen at once. It
        // says there is no route, which is why the read failed, and looks again after the
        // wait, by when one is back here.
        let back = OSAllocatedUnfairLock<Date?>(initialState: nil)
        let stranded = OSAllocatedUnfairLock<[Sniffer.Status]>(initialState: [])
        let routeless = Sniffer(open: { interface in
                                    guard interface == "utun4" else { return FakeCapture(linkType: PacketCapture.linkRaw) }
                                    back.withLock { $0 = Date().addingTimeInterval(0.2) }
                                    return Failing()
                                },
                                host: Sniffer.Host(primaryInterface: { back.withLock { $0 }.map { Date() < $0 ? nil : "en0" } ?? "utun4" },
                                                   hardwareAddress: { _ in nil }, addresses: { _ in [Self.me] }, resolvers: { [] }, readRetryAfter: 0.4),
                                onEvents: { _ in }, onStatus: { status in stranded.withLock { $0.append(status) } })
        defer { routeless.stop() }
        routeless.start()
        XCTAssertTrue(eventually { stranded.withLock { $0 }.count >= 3 }, "it looks again after the short wait, not the long one for no interface")
        XCTAssertEqual(Array(stranded.withLock { $0 }.prefix(3)),
                       [.capturing(interface: "utun4"), .unavailable(.noInterface), .capturing(interface: "en0")],
                       "the missing route is what it reports, not the read that failed for it")
    }

    /// A raw-IP capture that delivers its packets on the first read, then nothing.
    private final class OnePass: CaptureSource, @unchecked Sendable {
        let dataLinkType = PacketCapture.linkRaw
        private let packets: OSAllocatedUnfairLock<[[UInt8]]>
        init(_ packets: [[UInt8]]) { self.packets = OSAllocatedUnfairLock(initialState: packets) }
        func install(_ filter: CaptureFilter) throws {}
        func readPackets(_ handle: (Double, [UInt8]) -> Void) throws {
            for bytes in packets.withLock({ p in defer { p = [] }; return p }) { handle(Date().timeIntervalSince1970, bytes) }
            usleep(10_000)
        }
    }

    /// A run's flows end with it. One whose handshake was not read yet gets a reason when the
    /// capture stops or reopens, or its connection keeps neither a name nor a reason.
    func testFlowsPendingWhenARunEndsGetAReason() {
        let me = IPAddress(bytes: [192, 168, 1, 5])
        let remote = IPAddress(bytes: [203, 0, 113, 7])
        @Sendable func syn(from port: UInt16) -> [UInt8] {
            [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0] + me.bytes + remote.bytes
                + [UInt8(port >> 8), UInt8(port & 0xff), 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]
        }
        func key(_ port: UInt16) -> FlowKey { FlowKey(proto: .tcp, localPort: port, remote: remote, remotePort: 443) }
        let interface = OSAllocatedUnfairLock(initialState: "en0")
        let opens = OSAllocatedUnfairLock(initialState: 0)
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in OnePass([syn(from: opens.withLock { n in n += 1; return 50000 + UInt16(n) })]) },
                              host: Sniffer.Host(primaryInterface: { interface.withLock { $0 } }, hardwareAddress: { _ in nil },
                                                 addresses: { _ in [me] }, resolvers: { [] }, interfaceCheckEvery: 0.05),
                              onEvents: { new in events.withLock { $0 += new } }, onStatus: { _ in })
        defer { sniffer.stop() }
        sniffer.start()
        XCTAssertTrue(eventually { events.withLock { $0 } == [FlowEvent(key: key(50001), kind: .opened)] }, "the first run's flow opened")

        interface.withLock { $0 = "en1" }
        XCTAssertTrue(eventually { events.withLock { $0 }.count >= 3 })
        XCTAssertEqual(events.withLock { $0 }, [FlowEvent(key: key(50001), kind: .opened), FlowEvent(key: key(50001), kind: .unnamed(.captureEnded)),
                                                 FlowEvent(key: key(50002), kind: .opened)],
                       "the default route moved: the old run gave up on its flow before the new run opened one")

        sniffer.stop()
        XCTAssertTrue(eventually { events.withLock { $0 }.count >= 4 })
        XCTAssertEqual(events.withLock { $0 }.last, FlowEvent(key: key(50002), kind: .unnamed(.captureEnded)), "stopped")
    }

    /// A capture that delivers what the test feeds it, and applies no filter.
    private final class Fed: CaptureSource, @unchecked Sendable {
        let dataLinkType: UInt32
        private let packets = OSAllocatedUnfairLock<[(at: Double, bytes: [UInt8])]>(initialState: [])
        init(linkType: UInt32) { dataLinkType = linkType }
        /// `secondsAgo` dates the frames' capture that long before now.
        func feed(_ frames: [[UInt8]], secondsAgo: Double = 0) {
            let at = Date().timeIntervalSince1970 - secondsAgo
            packets.withLock { $0 += frames.map { (at, $0) } }
        }
        func install(_ filter: CaptureFilter) throws {}
        func readPackets(_ handle: (Double, [UInt8]) -> Void) throws {
            for packet in packets.withLock({ p in defer { p = [] }; return p }) { handle(packet.at, packet.bytes) }
            usleep(10_000)
        }
    }

    /// What a sniffer on en0 reports for a DNS reply from `resolver`, a host on the link, to
    /// `mine`, and then this Mac's SYN to the address the reply names. Any other interface of
    /// this Mac holds `elsewhere`, for a sniffer that asked.
    private func eventsAfterAReply(from resolver: IPAddress, to mine: IPAddress, elsewhere: Set<IPAddress>) -> [FlowEvent] {
        let mac = Self.first
        let reply = Self.reply(from: resolver, to: mine)
        let own: Set<IPAddress> = [Self.me, mine]

        let capture = Fed(linkType: PacketCapture.linkEthernet)
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in capture },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in mac }, gatewayHardwareAddresses: { _ in [] },
                                                 addresses: { $0 == "en0" ? own : elsewhere }, resolvers: { [resolver] }),
                              onEvents: { new in events.withLock { $0 += new } }, onStatus: { _ in })
        defer { sniffer.stop() }
        sniffer.start()
        capture.feed([Self.query(from: mine, to: resolver), reply])
        // Opened long enough ago for the DNS fallback to be due at the next pass.
        capture.feed([Self.syn(from: mac, port: 50001)], secondsAgo: FlowNamer.dnsFallbackAfter + 1)
        _ = eventually { events.withLock { $0 }.count >= 2 }
        return events.withLock { $0 }
    }

    /// An Ethernet frame from the interface at `first`, carrying the query from `mine` to
    /// `resolver` that `reply(from:to:)` answers.
    private static func query(from mine: IPAddress, to resolver: IPAddress) -> [UInt8] {
        let question: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1]
        let datagram: [UInt8] = [0xea, 0x60, 0, 53, 0, UInt8(8 + question.count), 0, 0] + question
        let header: [UInt8] = resolver.isV4
            ? [0x08, 0x00, 0x45, 0, 0, UInt8(20 + datagram.count), 0, 0, 0, 0, 64, 17, 0, 0]
            : [0x86, 0xdd, 0x60, 0, 0, 0, 0, UInt8(datagram.count), 17, 64]
        return other + first + header + mine.bytes + resolver.bytes + datagram
    }

    /// An Ethernet frame from another host to the interface at `first`, carrying a DNS reply
    /// from `resolver` to `mine` that names `remote` cdn.example.net.
    private static func reply(from resolver: IPAddress, to mine: IPAddress) -> [UInt8] {
        let answer: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1,
                               0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4] + remote.bytes
        let datagram: [UInt8] = [0, 53, 0xea, 0x60, 0, UInt8(8 + answer.count), 0, 0] + answer
        let header: [UInt8] = resolver.isV4
            ? [0x08, 0x00, 0x45, 0, 0, UInt8(20 + datagram.count), 0, 0, 0, 0, 64, 17, 0, 0]
            : [0x86, 0xdd, 0x60, 0, 0, 0, 0, UInt8(datagram.count), 17, 64]
        return first + other + header + resolver.bytes + mine.bytes + datagram
    }

    /// The interface's addresses and the resolvers are read at each check of the interface.
    /// An address it has gained is this Mac's from then on, and the resolvers of the network
    /// it came with are known once the system has them. An address a reading lacks is kept:
    /// Wi-Fi between networks has none for a moment, and one being renewed has only its
    /// link-local address.
    func testTheNamerFollowsTheInterfacesAddresses() {
        let gained = IPAddress(bytes: [192, 168, 1, 6]), linkLocal = IPAddress(bytes: [0xfe, 0x80] + [UInt8](repeating: 0, count: 12) + [0xab, 0xcd])
        let resolver = IPAddress(bytes: [192, 168, 1, 1]), newResolver = IPAddress(bytes: [192, 168, 1, 2])
        let own = OSAllocatedUnfairLock<Set<IPAddress>>(initialState: [Self.me])
        let resolvers = OSAllocatedUnfairLock<Set<IPAddress>>(initialState: [resolver])
        // Readings of the interface that lacked the address this Mac's SYNs come from, and
        // readings that held the address gained.
        let readingsWithout = OSAllocatedUnfairLock(initialState: 0)
        let readingsWithGained = OSAllocatedUnfairLock(initialState: 0)
        let capture = Fed(linkType: PacketCapture.linkEthernet)
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in capture },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in Self.first }, gatewayHardwareAddresses: { _ in [] },
                                                 addresses: { _ in
                                                     let now = own.withLock { $0 }
                                                     if !now.contains(Self.me) { readingsWithout.withLock { $0 += 1 } }
                                                     if now.contains(gained) { readingsWithGained.withLock { $0 += 1 } }
                                                     return now
                                                 }, resolvers: { resolvers.withLock { $0 } }, interfaceCheckEvery: 0.05),
                              onEvents: { new in events.withLock { $0 += new } }, onStatus: { _ in })
        defer { sniffer.stop() }
        sniffer.start()
        capture.feed([Self.syn(from: Self.first, port: 50000)])
        XCTAssertTrue(eventually { events.withLock { $0 } == [Self.opened(50000)] }, "the capture is reading, with the interface's address")

        for (reading, port, state) in [(Set<IPAddress>(), UInt16(50001), "no address"), ([linkLocal], UInt16(50002), "only its link-local address")] {
            let before = readingsWithout.withLock { $0 }
            own.withLock { $0 = reading }
            XCTAssertTrue(eventually { readingsWithout.withLock { $0 } >= before + 2 }, "the interface was read with \(state)")
            capture.feed([Self.syn(from: Self.first, port: port)])
            XCTAssertTrue(eventually { events.withLock { $0 }.contains(Self.opened(port)) }, "the address read before still counts with \(state)")
        }

        // This Mac's SYNs keep coming from the address the namer knows, so only a check of the
        // interface can teach it the address gained, which the new network's resolver replies
        // to. The system says who that resolver is a moment after the address is there.
        own.withLock { $0 = [Self.me, gained] }
        XCTAssertTrue(eventually { readingsWithGained.withLock { $0 } >= 2 }, "the interface was read with the address gained")
        resolvers.withLock { $0 = [newResolver] }
        func named() -> Bool { events.withLock { $0 }.contains { $0.kind == .named("cdn.example.net", .dns) } }
        var port: UInt16 = 50100
        let deadline = Date().addingTimeInterval(10)
        while !named(), Date() < deadline {
            port += 1
            capture.feed([Self.query(from: gained, to: newResolver), Self.reply(from: newResolver, to: gained)])
            // Opened long enough ago for the DNS fallback to be due at the next pass.
            capture.feed([Self.syn(from: Self.first, port: port)], secondsAgo: FlowNamer.dnsFallbackAfter + 1)
            usleep(50_000)
        }
        XCTAssertTrue(named(), "the new resolver's reply to the address gained was read")
    }

    private static let namedByDNS: [FlowEvent] = {
        let key = FlowKey(proto: .tcp, localPort: 50001, remote: remote, remotePort: 443)
        return [FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("cdn.example.net", .dns))]
    }()

    /// The namer is given the capture interface's addresses and no other interface's, since an
    /// address another one holds can be another host's on this link. Loopback holds fe80::1,
    /// and so do many routers, which answer DNS from it.
    func testARouterAtLoopbacksLinkLocalAddressNamesAFlowByDNS() {
        let router = IPAddress(bytes: [0xfe, 0x80] + [UInt8](repeating: 0, count: 13) + [1])
        let mine = IPAddress(bytes: [0xfe, 0x80] + [UInt8](repeating: 0, count: 12) + [0xab, 0xcd])
        let loopback: Set<IPAddress> = [router, IPAddress(bytes: [127, 0, 0, 1]), IPAddress(bytes: [UInt8](repeating: 0, count: 15) + [1])]
        XCTAssertEqual(eventsAfterAReply(from: router, to: mine, elsewhere: loopback), Self.namedByDNS)
    }

    /// The same for a resolver on a subnet that a bridge of this Mac's numbers too, as the
    /// one internet sharing or a virtual machine's network makes: 192.168.2.1 is the address
    /// internet sharing gives its bridge.
    func testAResolverAtAnAddressAnotherInterfaceHoldsNamesAFlowByDNS() {
        let resolver = IPAddress(bytes: [192, 168, 2, 1])
        XCTAssertEqual(eventsAfterAReply(from: resolver, to: Self.me, elsewhere: [resolver]), Self.namedByDNS)
    }

    /// A tunnel's frames carry no hardware address, so the IP source alone tells direction,
    /// and there only the tunnel's own addresses are this Mac's, as they are to the kernel
    /// filter: a packet under the LAN address did not leave through the tunnel.
    func testOnATunnelOnlyTheTunnelsAddressesAreThisMacs() {
        let tunnel = IPAddress(bytes: [10, 8, 0, 2])
        let hello = SnifferParserTests.clientHello(sni: Array("tunnel.example".utf8))
        let initial = SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello)
        func datagram(from source: IPAddress, port: UInt16) -> [UInt8] {
            let length = 8 + initial.count, total = 20 + length
            return [2, 0, 0, 0, 0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0, 0, 64, 17, 0, 0] + source.bytes + Self.remote.bytes
                + [UInt8(port >> 8), UInt8(port & 0xff), 0x01, 0xbb, UInt8(length >> 8), UInt8(length & 0xff), 0, 0] + initial
        }
        let capture = Fed(linkType: PacketCapture.linkNull)
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in capture },
                              host: Sniffer.Host(primaryInterface: { "utun4" }, hardwareAddress: { _ in nil },
                                                 addresses: { _ in [tunnel] }, resolvers: { [] }),
                              onEvents: { new in events.withLock { $0 += new } }, onStatus: { _ in })
        defer { sniffer.stop() }
        sniffer.start()
        // From port 53 the kernel filter passes the first as a DNS reply.
        capture.feed([datagram(from: Self.me, port: 53), datagram(from: tunnel, port: 50000)])
        XCTAssertTrue(eventually { events.withLock { $0 }.count >= 2 })
        let key = FlowKey(proto: .udp, localPort: 50000, remote: Self.remote, remotePort: 443)
        XCTAssertEqual(events.withLock { $0 }, [FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("tunnel.example", .quic))])
    }

    private static let me = IPAddress(bytes: [192, 168, 1, 5])
    private static let remote = IPAddress(bytes: [203, 0, 113, 7])

    /// An Ethernet frame from `source` carrying this Mac's SYN to `remote`.
    private static func syn(from source: [UInt8], to destination: [UInt8] = [2, 0, 0, 0, 0, 9], port: UInt16) -> [UInt8] {
        destination + source + [0x08, 0x00, 0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0] + me.bytes + remote.bytes
            + [UInt8(port >> 8), UInt8(port & 0xff), 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]
    }

    private static func opened(_ port: UInt16) -> FlowEvent {
        FlowEvent(key: FlowKey(proto: .tcp, localPort: port, remote: remote, remotePort: 443), kind: .opened)
    }

    /// A sniffer on an Ethernet capture the test feeds, with no kernel filter in front, whose
    /// interface is checked only as often as given. Returns the openings it reports.
    private func ethernetSniffer(_ capture: Fed, mac: OSAllocatedUnfairLock<[UInt8]>, interfaceCheckEvery: TimeInterval) -> (Sniffer, OSAllocatedUnfairLock<[FlowEvent]>) {
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in capture },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in mac.withLock { $0 } }, gatewayHardwareAddresses: { _ in [] },
                                                 addresses: { _ in [Self.me] }, resolvers: { [] }, interfaceCheckEvery: interfaceCheckEvery),
                              onEvents: { new in events.withLock { $0 += new.filter { $0.kind == .opened } } }, onStatus: { _ in })
        return (sniffer, events)
    }

    private static let first: [UInt8] = [0x2a, 0, 0, 0, 0, 1], rotated: [UInt8] = [0x2a, 0, 0, 0, 0, 2], other: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]

    /// On Ethernet the namer is told the interface's hardware address, so a frame another host
    /// sent under this Mac's IP address opens no flow, with or without a kernel filter in
    /// front, before the address changes and after.
    func testOnEthernetOnlyFramesFromTheInterfaceOpenFlows() {
        let mac = OSAllocatedUnfairLock(initialState: Self.first)
        let capture = Fed(linkType: PacketCapture.linkEthernet)
        let (sniffer, events) = ethernetSniffer(capture, mac: mac, interfaceCheckEvery: 0.05)
        defer { sniffer.stop() }
        sniffer.start()
        capture.feed([Self.syn(from: Self.other, port: 50001), Self.syn(from: Self.first, port: 50002)])
        XCTAssertTrue(eventually { !events.withLock { $0 }.isEmpty })
        XCTAssertEqual(events.withLock { $0 }, [Self.opened(50002)], "the other host's frame opened nothing")

        // Frames from the new address are fed until the run has noticed it and one opens a flow.
        mac.withLock { $0 = Self.rotated }
        var port: UInt16 = 50100
        let deadline = Date().addingTimeInterval(10)
        while events.withLock({ $0 }).count < 2, Date() < deadline {
            port += 1
            capture.feed([Self.syn(from: Self.rotated, port: port)])
            usleep(50_000)
        }
        // Frames are read in the order fed, so once the second of these has opened its flow the
        // first has been read too.
        capture.feed([Self.syn(from: Self.first, port: 50003), Self.syn(from: Self.rotated, port: 50004)])
        XCTAssertTrue(eventually { events.withLock { $0 }.contains(Self.opened(50004)) }, "the namer follows the interface's new address")
        XCTAssertFalse(events.withLock { $0 }.contains(Self.opened(50003)), "and a frame from the old one opens nothing")
    }

    /// On a network whose gateway answers at a multicast hardware address, every frame this
    /// Mac sends past the link is addressed to one. The gateway's address is read when the
    /// capture opens and at each check of the interface; while it is a group address, frames
    /// to group addresses are read as sent, by the namer from its first packet and by the
    /// kernel filter, and when it is another host's address, or cannot be read, they are not.
    func testWhereTheGatewayAnswersAtAGroupAddressFramesToOneOpenFlows() {
        let cluster: [UInt8] = [0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01], router: [UInt8] = [2, 0, 0, 0, 0, 9]
        let gateways = OSAllocatedUnfairLock<[[UInt8]]>(initialState: [cluster])
        func host() -> Sniffer.Host {
            Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in Self.first }, gatewayHardwareAddresses: { _ in gateways.withLock { $0 } },
                         addresses: { _ in [Self.me] }, resolvers: { [] }, interfaceCheckEvery: 0.05)
        }
        let capture = Fed(linkType: PacketCapture.linkEthernet)
        let events = OSAllocatedUnfairLock<[FlowEvent]>(initialState: [])
        let sniffer = Sniffer(open: { _ in capture }, host: host(),
                              onEvents: { new in events.withLock { $0 += new.filter { $0.kind == .opened } } }, onStatus: { _ in })
        defer { sniffer.stop() }
        sniffer.start()
        capture.feed([Self.syn(from: Self.first, to: cluster, port: 50001)])
        XCTAssertTrue(eventually { events.withLock { $0 } == [Self.opened(50001)] }, "read as sent from the first packet")

        /// Feeds a frame to the group address and then one to a host's, some checks of the
        /// interface after the reading changed: frames are read in order, so once the second
        /// has opened its flow the first has been read.
        func opensAfterTheNextChecks(_ group: UInt16, _ unicast: UInt16) -> [FlowEvent] {
            usleep(300_000)
            capture.feed([Self.syn(from: Self.first, to: cluster, port: group), Self.syn(from: Self.first, to: router, port: unicast)])
            XCTAssertTrue(eventually { events.withLock { $0 }.contains(Self.opened(unicast)) })
            return events.withLock { $0 }.filter { $0 == Self.opened(group) || $0 == Self.opened(unicast) }
        }
        gateways.withLock { $0 = [router] }
        XCTAssertEqual(opensAfterTheNextChecks(50002, 50003), [Self.opened(50003)], "the gateway now answers at a host's address: a frame to a group address is not this Mac's")
        gateways.withLock { $0 = [router, cluster] }
        XCTAssertEqual(opensAfterTheNextChecks(50004, 50005), [Self.opened(50004), Self.opened(50005)], "one of two gateways at a group address is enough")
        gateways.withLock { $0 = [] }
        XCTAssertEqual(opensAfterTheNextChecks(50006, 50007), [Self.opened(50007)], "no gateway address to read: the test stays")

        // The kernel filter is built from the same reading, and rebuilt when it changes.
        gateways.withLock { $0 = [cluster] }
        let filtered = FakeCapture(linkType: PacketCapture.linkEthernet)
        let second = Sniffer(open: { _ in filtered }, host: host(), onEvents: { _ in }, onStatus: { _ in })
        defer { second.stop() }
        second.start()
        XCTAssertTrue(eventually { filtered.installed.count == 1 })
        XCTAssertEqual(filtered.installed.last, CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(Self.first, gatewayAtGroupAddress: true)))
        gateways.withLock { $0 = [] }
        XCTAssertTrue(eventually { filtered.installed.count == 2 }, "rebuilt when the gateway's address can no longer be read")
        XCTAssertEqual(filtered.installed.last, CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(Self.first)))
        XCTAssertNotEqual(filtered.installed.first, filtered.installed.last, "and the two programs differ")
    }

    /// The interface is checked every few seconds, and its hardware address can change in
    /// between. With no kernel filter in front, the first frame sent from the new address has
    /// the address read again and is read as sent.
    func testTheFirstFrameFromANewHardwareAddressOpensItsFlow() {
        let mac = OSAllocatedUnfairLock(initialState: Self.first)
        let capture = Fed(linkType: PacketCapture.linkEthernet)
        let (sniffer, events) = ethernetSniffer(capture, mac: mac, interfaceCheckEvery: 60)
        defer { sniffer.stop() }
        sniffer.start()
        capture.feed([Self.syn(from: Self.first, port: 50002)])
        XCTAssertTrue(eventually { events.withLock { $0 } == [Self.opened(50002)] })

        mac.withLock { $0 = Self.rotated }
        capture.feed([Self.syn(from: Self.rotated, port: 50004)])
        XCTAssertTrue(eventually { events.withLock { $0 }.count >= 2 })
        XCTAssertEqual(events.withLock { $0 }, [Self.opened(50002), Self.opened(50004)])
    }

    /// An opener that does not return until the test lets it, as a broker request that is slow
    /// to answer. Counts how many opens have begun.
    private final class SlowOpen: @unchecked Sendable {
        private let gate = DispatchSemaphore(value: 0)
        private let begun = OSAllocatedUnfairLock(initialState: 0)
        var opens: Int { begun.withLock { $0 } }
        func open() throws -> any CaptureSource {
            let number = begun.withLock { n -> Int in n += 1; return n }
            if number == 1 { _ = gate.wait(timeout: .now() + 20) }
            return FakeCapture(linkType: PacketCapture.linkEthernet)
        }
        func release() { gate.signal() }
    }

    /// A restart while the run is inside open() (the broker request can take its full timeout)
    /// must not block the caller, must not start a second run beside the first, and the old
    /// run must say nothing once it has been stopped.
    func testRestartDuringOpenNeitherBlocksNorOverlaps() {
        let statuses = OSAllocatedUnfairLock<[Sniffer.Status]>(initialState: [])
        let slow = SlowOpen()
        let sniffer = Sniffer(open: { _ in try slow.open() },
                              host: Sniffer.Host(primaryInterface: { "en0" }, hardwareAddress: { _ in [2, 0, 0, 0, 0, 1] }, gatewayHardwareAddresses: { _ in [] }, addresses: { _ in [] }),
                              onEvents: { _ in }, onStatus: { status in statuses.withLock { $0.append(status) } })
        defer { slow.release(); sniffer.stop() }
        sniffer.start()
        XCTAssertTrue(eventually { slow.opens == 1 }, "the first run is inside open")

        let began = Date()
        sniffer.stop()
        XCTAssertLessThan(Date().timeIntervalSince(began), 0.5, "stop returns without waiting for the run: it is the main actor's call")
        sniffer.start()
        usleep(500_000)
        XCTAssertEqual(slow.opens, 1, "the second run waits for the first to end before it opens a device")

        slow.release()
        XCTAssertTrue(eventually { statuses.withLock { $0 }.count >= 2 })
        XCTAssertEqual(statuses.withLock { $0 }, [.stopped, .capturing(interface: "en0")],
                       "the stopped run reports only that it stopped, and before the new run reports")
    }
}
