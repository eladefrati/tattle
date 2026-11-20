import os
import SystemConfiguration
import XCTest
@testable import tattle

final class CaptureFilterTests: XCTestCase {
    private let mac: [UInt8] = [0xa4, 0x83, 0xe7, 0x11, 0x22, 0x33]
    private let otherMac: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    private let myV4: [UInt8] = [192, 168, 1, 5]
    private let peerV4: [UInt8] = [17, 253, 144, 10]
    private let myV6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [1]
    private let peerV6: [UInt8] = [0x26, 0x06, 0x47, 0x00] + [UInt8](repeating: 0, count: 10) + [0x11, 0x11]

    // MARK: Packet builders

    private func tcp(flags: UInt8, payload: Int) -> [UInt8] {
        [0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]
            + [UInt8](repeating: 0x16, count: payload)
    }

    private func udp(sourcePort: UInt16, destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
        [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xff), UInt8(destinationPort >> 8), UInt8(destinationPort & 0xff),
         UInt8((8 + payload.count) >> 8), UInt8((8 + payload.count) & 0xff), 0, 0] + payload
    }

    private func ipv4(from src: [UInt8], to dst: [UInt8], proto: UInt8, _ transport: [UInt8], fragmentOffset: UInt16 = 0) -> [UInt8] {
        let total = 20 + transport.count
        return [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, UInt8(fragmentOffset >> 8), UInt8(fragmentOffset & 0xff),
                64, proto, 0, 0] + src + dst + transport
    }

    private func ipv6(from src: [UInt8], to dst: [UInt8], proto: UInt8, _ transport: [UInt8]) -> [UInt8] {
        [0x60, 0, 0, 0, UInt8(transport.count >> 8), UInt8(transport.count & 0xff), proto, 64] + src + dst + transport
    }

    private func ethernet(from src: [UInt8], to dst: [UInt8]? = nil, _ ip: [UInt8]) -> [UInt8] {
        let type: [UInt8] = ip[0] >> 4 == 6 ? [0x86, 0xdd] : [0x08, 0x00]
        return (dst ?? otherMac) + src + type + ip
    }

    private func nullLink(_ ip: [UInt8]) -> [UInt8] {
        (ip[0] >> 4 == 6 ? [30, 0, 0, 0] : [2, 0, 0, 0]) + ip
    }

    // MARK: Programs

    func testProgramsAreValidForEachLinkType() throws {
        let ethernet = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac)))
        XCTAssertTrue(ethernet.isValid)
        let null = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkNull, direction: .sourceAddresses([myV4, myV6])))
        XCTAssertTrue(null.isValid)
        let raw = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkRaw, direction: .sourceAddresses([])))
        XCTAssertTrue(raw.isValid)
        XCTAssertNil(CaptureFilter.program(linkType: 9, direction: .sourceAddresses([myV4])), "unknown link layout")
        XCTAssertNil(CaptureFilter.program(linkType: PacketCapture.linkNull, direction: .hardwareAddress(mac)), "a tunnel has no hardware address")
        XCTAssertNil(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress([1, 2, 3])))
    }

    func testValidatorRejectsBrokenPrograms() {
        XCTAssertFalse(CaptureFilter(instructions: []).isValid)
        XCTAssertFalse(CaptureFilter(instructions: [.init(code: 0x28, jt: 0, jf: 0, k: 12)]).isValid, "must end in a return")
        XCTAssertFalse(CaptureFilter(instructions: [.init(code: 0x15, jt: 5, jf: 0, k: 0), .init(code: 0x06, jt: 0, jf: 0, k: 0)]).isValid, "jump past the end")
        XCTAssertFalse(CaptureFilter(instructions: [.init(code: 0x02, jt: 0, jf: 0, k: 16), .init(code: 0x06, jt: 0, jf: 0, k: 0)]).isValid, "memory slot out of range")
    }

    /// A client Initial's first bytes, padded to the 1200 a client sends at least.
    private let initial: [UInt8] = [0xc3, 0, 0, 0, 1] + [UInt8](repeating: 0, count: 1195)

    func testEthernetFilterKeepsHandshakesAndDNSAndDropsTheRest() throws {
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac)))
        func run(_ frame: [UInt8]) -> UInt32 { Interpreter.run(filter, on: frame) }
        let snap = CaptureFilter.snapLength

        // Outbound TCP: SYN kept, pure ACK dropped, ACK with payload kept, both families.
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 6, tcp(flags: 0x02, payload: 0)))), snap)
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 6, tcp(flags: 0x10, payload: 0)))), 0)
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 6, tcp(flags: 0x18, payload: 200)))), snap)
        XCTAssertEqual(run(ethernet(from: mac, ipv6(from: myV6, to: peerV6, proto: 6, tcp(flags: 0x02, payload: 0)))), snap)
        XCTAssertEqual(run(ethernet(from: mac, ipv6(from: myV6, to: peerV6, proto: 6, tcp(flags: 0x10, payload: 0)))), 0)
        XCTAssertEqual(run(ethernet(from: mac, ipv6(from: myV6, to: peerV6, proto: 6, tcp(flags: 0x18, payload: 1)))), snap)

        // Inbound TCP, the download case: dropped whatever it carries.
        XCTAssertEqual(run(ethernet(from: otherMac, ipv4(from: peerV4, to: myV4, proto: 6, tcp(flags: 0x18, payload: 1400)))), 0)
        XCTAssertEqual(run(ethernet(from: otherMac, ipv4(from: peerV4, to: myV4, proto: 6, tcp(flags: 0x12, payload: 0)))), 0)
        XCTAssertEqual(run(ethernet(from: otherMac, ipv6(from: peerV6, to: myV6, proto: 6, tcp(flags: 0x18, payload: 1400)))), 0)

        // Outbound UDP: a client Initial kept, short header and other UDP dropped.
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 17, udp(sourcePort: 50000, destinationPort: 443, payload: initial)))), snap)
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 17, udp(sourcePort: 50000, destinationPort: 443, payload: [0x41, 1, 2, 3])))), 0)
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 17, udp(sourcePort: 50000, destinationPort: 53, payload: SnifferParserTests.query)))), snap, "a DNS query, which its reply is matched to")
        XCTAssertEqual(run(ethernet(from: mac, ipv6(from: myV6, to: peerV6, proto: 17, udp(sourcePort: 50000, destinationPort: 443, payload: initial)))), snap)
        // Only a client Initial, long header with the fixed bit, at least 1200 bytes, or a DNS query.
        var rtp = initial
        rtp[0] = 0x80
        for family in [4, 6] {
            func out(_ port: UInt16, _ payload: [UInt8]) -> UInt32 {
                let datagram = udp(sourcePort: 50000, destinationPort: port, payload: payload)
                return run(ethernet(from: mac, family == 4 ? ipv4(from: myV4, to: peerV4, proto: 17, datagram) : ipv6(from: myV6, to: peerV6, proto: 17, datagram)))
            }
            XCTAssertEqual(out(5004, rtp), 0, "RTP, IPv\(family)")
            XCTAssertEqual(out(443, Array(initial.prefix(1199))), 0, "too small for a client Initial, IPv\(family)")
            XCTAssertEqual(out(53, initial), 0, "to port 53 and not a DNS query, IPv\(family)")
            XCTAssertEqual(out(53, SnifferParserTests.query), snap, "a DNS query, IPv\(family)")
            XCTAssertEqual(out(5353, SnifferParserTests.query), 0, "not to port 53, IPv\(family)")
            let inbound = udp(sourcePort: 50000, destinationPort: 53, payload: SnifferParserTests.query)
            XCTAssertEqual(run(ethernet(from: otherMac, family == 4 ? ipv4(from: peerV4, to: myV4, proto: 17, inbound) : ipv6(from: peerV6, to: myV6, proto: 17, inbound))), 0,
                           "another host's query, IPv\(family)")
        }

        // Inbound UDP: only replies from port 53.
        XCTAssertEqual(run(ethernet(from: otherMac, ipv4(from: peerV4, to: myV4, proto: 17, udp(sourcePort: 53, destinationPort: 50000, payload: [0x12, 0x34, 0x81, 0x80])))), snap)
        XCTAssertEqual(run(ethernet(from: otherMac, ipv4(from: peerV4, to: myV4, proto: 17, udp(sourcePort: 443, destinationPort: 50000, payload: [0xc3, 0, 0, 0, 1])))), 0, "a server's QUIC Initial is not needed")
        XCTAssertEqual(run(ethernet(from: otherMac, ipv6(from: peerV6, to: myV6, proto: 17, udp(sourcePort: 53, destinationPort: 50000, payload: [0x12, 0x34, 0x81, 0x80])))), snap)

        // Not IP, or a later fragment: dropped.
        XCTAssertEqual(run(otherMac + mac + [0x08, 0x06] + [UInt8](repeating: 0, count: 28)), 0, "ARP")
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 6, tcp(flags: 0x18, payload: 100), fragmentOffset: 0x0010))), 0)
        XCTAssertEqual(run(ethernet(from: mac, ipv4(from: myV4, to: peerV4, proto: 1, [8, 0, 0, 0, 0, 0, 0, 0]))), 0, "ICMP")
    }

    /// Of what this Mac sends to port 53 the namer reads a standard query with one question
    /// (`DNS.parseQuery`) and nothing else, so that is all the filter copies: whatever else a
    /// program sends there, a tunnel's packets among it, stays in the kernel.
    func testOfWhatGoesToPort53OnlyAStandardQueryWithOneQuestionIsCopied() throws {
        let query = SnifferParserTests.query
        func changed(_ change: (inout [UInt8]) -> Void) -> [UInt8] {
            var bytes = query
            change(&bytes)
            return bytes
        }
        let kept: [(String, [UInt8])] = [
            ("a query", query),
            ("recursion desired and authentic data set", changed { $0[2] = 0x01; $0[3] = 0x20 }),
            ("an OPT record after the question", changed { $0[11] = 1; $0 += [0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0] }),
        ]
        let dropped: [(String, [UInt8])] = [
            ("a reply", changed { $0[2] |= 0x80 }),
            ("another operation", changed { $0[2] = 0x11 }),
            ("two questions", changed { $0[5] = 2 }),
            ("no question", changed { $0[5] = 0 }),
            ("cut before the question count", Array(query.prefix(5))),
            ("a tunnel's full packet", [0x04, 0, 0, 0, 0x9a, 0x3c] + [UInt8](repeating: 0x5a, count: 1394)),
        ]
        /// The same IPv4 packet with four bytes of options, which move everything after them.
        func withOptions(_ ip: [UInt8]) -> [UInt8] {
            var bytes = ip
            bytes[0] = 0x46
            bytes[3] += 4
            bytes.insert(contentsOf: [1, 1, 1, 1], at: 20)
            return bytes
        }
        let mine = CaptureFilter.Direction.sourceAddresses([myV4, myV6])
        let links: [(String, CaptureFilter, ([UInt8]) -> [UInt8])] = [
            ("Ethernet", try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac))), { self.ethernet(from: self.mac, $0) }),
            ("null link", try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkNull, direction: mine)), nullLink),
            ("raw IP", try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkRaw, direction: mine)), { $0 }),
        ]
        for (link, filter, frame) in links {
            for (what, payload) in kept + dropped {
                let datagram = udp(sourcePort: 50000, destinationPort: 53, payload: payload)
                let v4 = ipv4(from: myV4, to: peerV4, proto: 17, datagram)
                let packets = [("IPv4", v4), ("IPv4 with options", withOptions(v4)), ("IPv6", ipv6(from: myV6, to: peerV6, proto: 17, datagram))]
                let wanted = kept.contains { $0.0 == what } ? CaptureFilter.snapLength : 0
                for (family, packet) in packets {
                    XCTAssertEqual(Interpreter.run(filter, on: frame(packet)), wanted, "\(what), \(family) on \(link)")
                }
                if DNS.parseQuery(payload[...]) != nil { XCTAssertEqual(wanted, CaptureFilter.snapLength, "\(what) is read by the namer, so it is copied") }
            }
        }
        for (what, payload) in kept { XCTAssertNotNil(DNS.parseQuery(payload[...]), "\(what) is one the namer reads") }
    }

    /// The filter passes any datagram from port 53 as a DNS reply, whatever its addresses, so
    /// what reads it must not take the sender's word for the direction. A host on the network
    /// that put this Mac's IP address on a frame of its own had a QUIC Initial of its choosing
    /// decrypted and a flow named from it. What this Mac sends and what its resolver answers
    /// are still read.
    func testAFrameFromAnotherHostUnderThisMacsAddressIsNotReadAsSent() throws {
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac)))
        let hello = SnifferParserTests.clientHello(sni: Array("forged.example".utf8))
        let initial = SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello)
        let reply: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1,
                              0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4] + peerV4
        // The query that reply answers: cdn.example.net's A record, under the same id.
        let query: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1]
        let resolverV6: [UInt8] = [0xfd, 0] + [UInt8](repeating: 0, count: 13) + [1]
        for (family, me, peer, resolver) in [(4, myV4, peerV4, [192, 168, 1, 1]), (6, myV6, peerV6, resolverV6)] {
            func ip(from src: [UInt8], to dst: [UInt8], _ datagram: [UInt8]) -> [UInt8] {
                family == 4 ? ipv4(from: src, to: dst, proto: 17, datagram) : ipv6(from: src, to: dst, proto: 17, datagram)
            }
            /// Through the kernel filter, the parser and the namer, as a captured frame goes.
            func read(_ frame: [UInt8], by namer: inout FlowNamer) throws -> [FlowEvent] {
                XCTAssertEqual(Interpreter.run(filter, on: frame), CaptureFilter.snapLength, "IPv\(family): the filter passes it")
                return namer.observe(try XCTUnwrap(Packet.parse(frame, dlt: PacketCapture.linkEthernet)), at: 1_700_000_000)
            }
            // A Mac that resolves through a proxy of its own has a loopback address as resolver.
            // No link carries one, so a frame from it is not the proxy's reply.
            let loopback: [UInt8] = family == 4 ? [127, 0, 0, 1] : [UInt8](repeating: 0, count: 15) + [1]
            var namer = FlowNamer(localAddresses: [IPAddress(bytes: me)],
                                  resolvers: [IPAddress(bytes: resolver), IPAddress(bytes: loopback)], hardwareAddress: mac)

            let forged = ethernet(from: otherMac, to: mac, ip(from: me, to: peer, udp(sourcePort: 53, destinationPort: 443, payload: initial)))
            XCTAssertEqual(try read(forged, by: &namer), [], "IPv\(family): another host's frame is not this Mac's connection")
            XCTAssertEqual(namer.flowCount, 0, "IPv\(family)")

            let forgedReply = ethernet(from: otherMac, to: mac, ip(from: loopback, to: me, udp(sourcePort: 53, destinationPort: 60000, payload: reply)))
            XCTAssertEqual(try read(forgedReply, by: &namer), [], "IPv\(family)")
            XCTAssertEqual(namer.dnsCount, 0, "IPv\(family): nor is it a reply from this Mac's own resolver")

            // A query under this Mac's address from another host does not make a reply expected.
            let forgedQuery = ethernet(from: otherMac, to: mac, ip(from: me, to: resolver, udp(sourcePort: 60000, destinationPort: 53, payload: query)))
            XCTAssertEqual(Interpreter.run(filter, on: forgedQuery), 0, "IPv\(family): the filter drops it")
            XCTAssertEqual(namer.observe(try XCTUnwrap(Packet.parse(forgedQuery, dlt: PacketCapture.linkEthernet)), at: 1_700_000_000), [], "IPv\(family)")
            XCTAssertEqual(namer.queryCount, 0, "IPv\(family): and with no filter the namer does not hold it")

            let answered = ethernet(from: otherMac, to: mac, ip(from: resolver, to: me, udp(sourcePort: 53, destinationPort: 60000, payload: reply)))
            XCTAssertEqual(try read(answered, by: &namer), [], "IPv\(family)")
            XCTAssertEqual(namer.dnsCount, 0, "IPv\(family): a reply this Mac did not ask for")

            let asked = ethernet(from: mac, ip(from: me, to: resolver, udp(sourcePort: 60000, destinationPort: 53, payload: query)))
            XCTAssertEqual(try read(asked, by: &namer), [], "IPv\(family)")
            XCTAssertEqual(namer.queryCount, 1, "IPv\(family): this Mac's query is held")
            XCTAssertEqual(try read(answered, by: &namer), [], "IPv\(family)")
            XCTAssertEqual(namer.dnsCount, 1, "IPv\(family): the resolver's reply to it is remembered")
            XCTAssertEqual(namer.queryCount, 0, "IPv\(family): and the query let go")

            let sent = ethernet(from: mac, ip(from: me, to: peer, udp(sourcePort: 50000, destinationPort: 443, payload: initial)))
            let key = FlowKey(proto: .udp, localPort: 50000, remote: IPAddress(bytes: peer), remotePort: 443)
            XCTAssertEqual(try read(sent, by: &namer), [FlowEvent(key: key, kind: .opened), FlowEvent(key: key, kind: .named("forged.example", .quic))],
                           "IPv\(family): this Mac's own Initial names its flow")
        }
    }

    /// A frame can carry this Mac's hardware address as its source and still be another
    /// host's: any host on the link can write it there. Such a frame reaches this Mac only
    /// when it is addressed to this Mac's own hardware address or to a broadcast or multicast
    /// one, and this Mac addresses no frame to itself and sends to a group address nothing
    /// the namer reads. So a frame addressed that way is not read as sent: it holds no query
    /// for a forged reply to answer, renames no open connection and has no Initial decrypted
    /// (ADR-0006). The same frames to another host's address, as this Mac sends them, are read,
    /// and so are frames to a group address on a network whose gateway answers at one.
    func testAFrameUnderThisMacsHardwareAddressToItselfOrAGroupAddressIsNotReadAsSent() throws {
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac)))
        func record(_ hello: [UInt8]) -> [UInt8] { [0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello }
        func segment(flags: UInt8, seq: UInt32, _ payload: [UInt8] = []) -> [UInt8] {
            [0xd4, 0x31, 0x01, 0xbb, UInt8(seq >> 24), UInt8(seq >> 16 & 0xff), UInt8(seq >> 8 & 0xff), UInt8(seq & 0xff),
             0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0] + payload
        }
        let forgedHello = SnifferParserTests.clientHello(sni: Array("forged.example".utf8))
        let initial = SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(forgedHello.count >> 8), UInt8(forgedHello.count & 0xff)] + forgedHello)
        let reply: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1,
                              0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4] + peerV4
        let query: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0, 1, 0, 1]
        let resolverV6: [UInt8] = [0xfd, 0] + [UInt8](repeating: 0, count: 13) + [1]
        let notSent: [(String, [UInt8])] = [
            ("this Mac's own address", mac),
            ("the broadcast address", [UInt8](repeating: 0xff, count: 6)),
            ("an IPv4 multicast address", [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]),
            ("an IPv6 multicast address", [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]),
        ]
        for (family, me, peer, resolver) in [(4, myV4, peerV4, [192, 168, 1, 1]), (6, myV6, peerV6, resolverV6)] {
            func ip(_ proto: UInt8, to dst: [UInt8], _ transport: [UInt8]) -> [UInt8] {
                family == 4 ? ipv4(from: me, to: dst, proto: proto, transport) : ipv6(from: me, to: dst, proto: proto, transport)
            }
            func observe(_ frame: [UInt8], by namer: inout FlowNamer) throws -> [FlowEvent] {
                namer.observe(try XCTUnwrap(Packet.parse(frame, dlt: PacketCapture.linkEthernet)), at: 1_700_000_000)
            }
            func fresh() -> FlowNamer {
                FlowNamer(localAddresses: [IPAddress(bytes: me)], resolvers: [IPAddress(bytes: resolver)], hardwareAddress: mac)
            }
            /// What a forger would send under this Mac's addresses, to a hardware address.
            func frames(to destination: [UInt8]) -> [(String, [UInt8])] {
                [("a DNS query", ethernet(from: mac, to: destination, ip(17, to: resolver, udp(sourcePort: 60000, destinationPort: 53, payload: query)))),
                 ("a SYN", ethernet(from: mac, to: destination, ip(6, to: peer, segment(flags: 0x02, seq: 1)))),
                 ("a ClientHello", ethernet(from: mac, to: destination, ip(6, to: peer, segment(flags: 0x18, seq: 2, record(forgedHello))))),
                 ("a QUIC Initial", ethernet(from: mac, to: destination, ip(17, to: peer, udp(sourcePort: 50000, destinationPort: 443, payload: initial))))]
            }
            let answer = ethernet(from: otherMac, to: mac, family == 4 ? ipv4(from: resolver, to: me, proto: 17, udp(sourcePort: 53, destinationPort: 60000, payload: reply))
                                                                       : ipv6(from: resolver, to: me, proto: 17, udp(sourcePort: 53, destinationPort: 60000, payload: reply)))
            let tcpKey = FlowKey(proto: .tcp, localPort: 0xd431, remote: IPAddress(bytes: peer), remotePort: 443)
            let udpKey = FlowKey(proto: .udp, localPort: 50000, remote: IPAddress(bytes: peer), remotePort: 443)

            for (what, destination) in notSent {
                // An open connection of this Mac's, already named, on the ports the forger uses.
                var namer = fresh()
                let real = record(SnifferParserTests.clientHello(sni: Array("real.example".utf8)))
                _ = try observe(ethernet(from: mac, ip(6, to: peer, segment(flags: 0x02, seq: 1))), by: &namer)
                XCTAssertEqual(try observe(ethernet(from: mac, ip(6, to: peer, segment(flags: 0x18, seq: 2, real))), by: &namer),
                               [FlowEvent(key: tcpKey, kind: .named("real.example", .sni))])
                for (kind, frame) in frames(to: destination) {
                    XCTAssertEqual(Interpreter.run(filter, on: frame), 0, "IPv\(family): the filter drops \(kind) addressed to \(what)")
                    XCTAssertEqual(try observe(frame, by: &namer), [], "IPv\(family): with no filter the namer does not read \(kind) addressed to \(what)")
                }
                XCTAssertEqual(namer.flowCount, 1, "IPv\(family), \(what): no flow opened, and the open one not started over")
                XCTAssertEqual(namer.queryCount, 0, "IPv\(family), \(what): no query held")
                _ = try observe(answer, by: &namer)
                XCTAssertEqual(namer.dnsCount, 0, "IPv\(family), \(what): so the reply sent after it names nothing")
            }

            // To another host's address, which is where this Mac sends them, all four are read.
            var namer = fresh()
            let sent = frames(to: otherMac)
            for (kind, frame) in sent { XCTAssertEqual(Interpreter.run(filter, on: frame), CaptureFilter.snapLength, "IPv\(family): the filter passes \(kind)") }
            XCTAssertEqual(try observe(sent[0].1, by: &namer), [])
            XCTAssertEqual(namer.queryCount, 1, "IPv\(family)")
            _ = try observe(answer, by: &namer)
            XCTAssertEqual(namer.dnsCount, 1, "IPv\(family)")
            XCTAssertEqual(try observe(sent[1].1, by: &namer), [FlowEvent(key: tcpKey, kind: .opened)], "IPv\(family)")
            XCTAssertEqual(try observe(sent[2].1, by: &namer), [FlowEvent(key: tcpKey, kind: .named("forged.example", .sni))], "IPv\(family)")
            XCTAssertEqual(try observe(sent[3].1, by: &namer), [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .named("forged.example", .quic))], "IPv\(family)")

            // Where the gateway answers at a group address, everything this Mac sends past
            // the link is addressed to one, and is read. A frame to this Mac's own address
            // still is not.
            let cluster: [UInt8] = [0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01]
            let lenient = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .hardwareAddress(mac, gatewayAtGroupAddress: true)))
            var routed = FlowNamer(localAddresses: [IPAddress(bytes: me)], resolvers: [IPAddress(bytes: resolver)], hardwareAddress: mac, gatewayAtGroupAddress: true)
            let viaCluster = frames(to: cluster)
            for (kind, frame) in viaCluster { XCTAssertEqual(Interpreter.run(lenient, on: frame), CaptureFilter.snapLength, "IPv\(family): with a gateway at a group address the filter passes \(kind) addressed to it") }
            XCTAssertEqual(try observe(viaCluster[0].1, by: &routed), [])
            XCTAssertEqual(routed.queryCount, 1, "IPv\(family): the query sent through the gateway is held")
            _ = try observe(answer, by: &routed)
            XCTAssertEqual(routed.dnsCount, 1, "IPv\(family): and its reply remembered")
            XCTAssertEqual(try observe(viaCluster[1].1, by: &routed), [FlowEvent(key: tcpKey, kind: .opened)], "IPv\(family)")
            XCTAssertEqual(try observe(viaCluster[2].1, by: &routed), [FlowEvent(key: tcpKey, kind: .named("forged.example", .sni))], "IPv\(family)")
            XCTAssertEqual(try observe(viaCluster[3].1, by: &routed), [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .named("forged.example", .quic))], "IPv\(family)")
            for (kind, frame) in frames(to: mac) {
                XCTAssertEqual(Interpreter.run(lenient, on: frame), 0, "IPv\(family): the filter still drops \(kind) addressed to this Mac's own address")
                XCTAssertEqual(try observe(frame, by: &routed), [], "IPv\(family): and the namer still does not read \(kind) addressed to it")
            }
            for (kind, frame) in sent { XCTAssertEqual(Interpreter.run(lenient, on: frame), CaptureFilter.snapLength, "IPv\(family): \(kind) to another host's address passes as before") }

            // An address that differs from this Mac's in its last byte alone is another host's.
            var neighbour = mac
            neighbour[5] ^= 0x10
            XCTAssertEqual(Interpreter.run(filter, on: frames(to: neighbour)[1].1), CaptureFilter.snapLength, "IPv\(family): a neighbour's address")
            var other = mac
            other[1] ^= 0x10
            XCTAssertEqual(Interpreter.run(filter, on: frames(to: other)[1].1), CaptureFilter.snapLength, "IPv\(family): an address that differs early")
        }
    }

    /// An Ethernet link whose hardware address cannot be read tells direction from this Mac's
    /// IP addresses, as a tunnel does, and has no hardware address to test a frame's
    /// destination against: whatever a frame is addressed to, it is passed and read.
    func testOnEthernetWithNoHardwareAddressToReadAFramesDestinationIsNotTested() throws {
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkEthernet, direction: .sourceAddresses([myV4, myV6])))
        let destinations: [(String, [UInt8])] = [
            ("another host's address", otherMac),
            ("the frame's own source address", mac),
            ("the broadcast address", [UInt8](repeating: 0xff, count: 6)),
            ("an IPv4 multicast address", [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]),
            ("an IPv6 multicast address", [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]),
        ]
        for (family, me, peer) in [(4, myV4, peerV4), (6, myV6, peerV6)] {
            let syn = tcp(flags: 0x02, payload: 0)
            let packet = family == 4 ? ipv4(from: me, to: peer, proto: 6, syn) : ipv6(from: me, to: peer, proto: 6, syn)
            let key = FlowKey(proto: .tcp, localPort: 0xd431, remote: IPAddress(bytes: peer), remotePort: 443)
            var namer = FlowNamer(localAddresses: [IPAddress(bytes: me)], resolvers: [])
            for (what, destination) in destinations {
                let frame = ethernet(from: mac, to: destination, packet)
                XCTAssertEqual(Interpreter.run(filter, on: frame), CaptureFilter.snapLength, "IPv\(family): the filter passes a SYN to \(what)")
                XCTAssertEqual(namer.observe(try XCTUnwrap(Packet.parse(frame, dlt: PacketCapture.linkEthernet)), at: 1_700_000_000),
                               [FlowEvent(key: key, kind: .opened)], "IPv\(family): and the namer reads a SYN to \(what)")
            }
        }
    }

    func testNullLinkFilterTellsDirectionFromAddresses() throws {
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: PacketCapture.linkNull, direction: .sourceAddresses([myV4, myV6])))
        func run(_ frame: [UInt8]) -> UInt32 { Interpreter.run(filter, on: frame) }
        let snap = CaptureFilter.snapLength

        XCTAssertEqual(run(nullLink(ipv4(from: myV4, to: peerV4, proto: 6, tcp(flags: 0x02, payload: 0)))), snap)
        XCTAssertEqual(run(nullLink(ipv4(from: peerV4, to: myV4, proto: 6, tcp(flags: 0x18, payload: 1400)))), 0, "inbound payload dropped")
        XCTAssertEqual(run(nullLink(ipv4(from: peerV4, to: myV4, proto: 17, udp(sourcePort: 53, destinationPort: 5000, payload: [1, 2, 3, 4])))), snap)
        XCTAssertEqual(run(nullLink(ipv6(from: myV6, to: peerV6, proto: 17, udp(sourcePort: 5000, destinationPort: 443, payload: initial)))), snap)
        XCTAssertEqual(run(nullLink(ipv4(from: myV4, to: peerV4, proto: 17, udp(sourcePort: 5000, destinationPort: 53, payload: SnifferParserTests.query)))), snap, "this Mac's DNS query")
        XCTAssertEqual(run(nullLink(ipv6(from: myV6, to: peerV6, proto: 17, udp(sourcePort: 5000, destinationPort: 53, payload: SnifferParserTests.query)))), snap)
        XCTAssertEqual(run(nullLink(ipv4(from: peerV4, to: myV4, proto: 17, udp(sourcePort: 5000, destinationPort: 53, payload: SnifferParserTests.query)))), 0, "another host's")
        XCTAssertEqual(run(nullLink(ipv6(from: peerV6, to: myV6, proto: 6, tcp(flags: 0x18, payload: 1400)))), 0)
        // Another address of ours that the filter was not told about looks inbound: dropped.
        XCTAssertEqual(run(nullLink(ipv4(from: [10, 0, 0, 9], to: peerV4, proto: 6, tcp(flags: 0x02, payload: 0)))), 0)
    }

    /// A full-tunnel VPN puts the capture on a link without a hardware address, so direction
    /// comes from addresses. Too many of them push the early jumps past BPF's 255-instruction
    /// reach; that must leave the capture unfiltered, not stop the app.
    func testTooManyAddressesGiveNoFilterInsteadOfStoppingTheApp() {
        let many = (0..<40).map { [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [UInt8($0)] }
        XCTAssertNil(CaptureFilter.program(linkType: PacketCapture.linkNull, direction: .sourceAddresses(many)))
    }

    /// The direction test gets only the capture interface's own addresses, which keeps the
    /// program short: loopback's never include another interface's.
    func testInterfaceAddressesAreThatInterfacesOnly() {
        let loopback = localAddresses(of: "lo0")
        XCTAssertTrue(loopback.contains(IPAddress(bytes: [127, 0, 0, 1])))
        XCTAssertTrue(loopback.allSatisfy { $0.bytes.count == 4 ? $0.bytes[0] == 127 : $0.isLocalScope })
    }

    /// An IPv6-only network has a default route but no IPv4 one; capture must still start.
    func testPrimaryInterfaceComesFromIPv4ThenIPv6() {
        func store(_ v4: String?, _ v6: String?) -> (String) -> [String: Any]? {
            { key in
                switch key {
                case "State:/Network/Global/IPv4": v4.map { ["PrimaryInterface": $0] }
                case "State:/Network/Global/IPv6": v6.map { ["PrimaryInterface": $0] }
                default: nil
                }
            }
        }
        XCTAssertEqual(PacketCapture.primaryInterface(store: store("en0", "en0")), "en0")
        XCTAssertEqual(PacketCapture.primaryInterface(store: store(nil, "en1")), "en1", "IPv6-only")
        XCTAssertEqual(PacketCapture.primaryInterface(store: store("en0", "utun3")), "en0", "IPv4 first, as before")
        XCTAssertNil(PacketCapture.primaryInterface(store: store(nil, nil)))
    }

    /// The gateways whose hardware addresses are read are the routers the configuration store
    /// names for the interface, each family's only when its default route is on it, and only
    /// those the neighbour table has resolved.
    func testTheGatewaysAreTheRoutersOfTheFamiliesRoutedOverTheInterface() {
        let unicast: [UInt8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x09], group: [UInt8] = [0x01, 0x00, 0x5e, 0x7f, 0x00, 0x01]
        func store(_ v4: [String: Any]?, _ v6: [String: Any]?) -> (String) -> [String: Any]? {
            { key in
                switch key {
                case "State:/Network/Global/IPv4": v4
                case "State:/Network/Global/IPv6": v6
                default: nil
                }
            }
        }
        let asked = OSAllocatedUnfairLock<[String]>(initialState: [])
        func gateways(_ v4: [String: Any]?, _ v6: [String: Any]?, resolved: [String: [UInt8]] = ["192.168.1.1": unicast, "fe80::1": group]) -> [[UInt8]] {
            PacketCapture.gatewayHardwareAddresses(of: "en0", store: store(v4, v6)) { address, interface in
                asked.withLock { $0.append("\(address.text) on \(interface)") }
                return resolved[address.text]
            }
        }
        let v4: [String: Any] = ["PrimaryInterface": "en0", "Router": "192.168.1.1"]
        XCTAssertEqual(gateways(v4, ["PrimaryInterface": "en0", "Router": "fe80::1%en0"]), [unicast, group], "both families, the zone dropped from a link-local router")
        XCTAssertEqual(asked.withLock { $0 }, ["192.168.1.1 on en0", "fe80::1 on en0"])
        XCTAssertEqual(gateways(v4, ["PrimaryInterface": "utun3", "Router": "fe80::1"]), [unicast], "IPv6 is routed over another interface")
        XCTAssertEqual(gateways(["PrimaryInterface": "en1", "Router": "192.168.1.1"], nil), [], "the default route is on another interface")
        XCTAssertEqual(gateways(v4, nil, resolved: [:]), [], "the router's entry is not resolved")
        XCTAssertEqual(gateways(["PrimaryInterface": "en0"], nil), [], "a route with no router, as on a point-to-point link")
        XCTAssertEqual(gateways(nil, nil), [])
    }

    /// The neighbour table is read with the layout `arp` reads it with: on this machine, the
    /// IPv4 gateway's hardware address is the one `arp -n` prints.
    func testTheGatewaysHardwareAddressIsTheOneArpReports() throws {
        let global = SCDynamicStoreCopyValue(nil, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        let interface = try XCTUnwrap(global?["PrimaryInterface"] as? String, "no IPv4 default route")
        guard let router = global?["Router"] as? String else { throw XCTSkip("the default route has no router") }
        let arp = Process(), output = Pipe()
        arp.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        arp.arguments = ["-n", router]
        arp.standardOutput = output
        arp.standardError = Pipe()
        try arp.run()
        let printed = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        arp.waitUntilExit()
        // "? (192.168.1.1) at 2:0:0:0:0:9 on en0 ifscope [ethernet]", without leading zeros.
        let words = printed.split(separator: " ")
        guard let at = words.firstIndex(of: "at"), at + 1 < words.count else { throw XCTSkip("arp printed no entry for \(router)") }
        let reported = words[at + 1].split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard reported.count == 6 else { throw XCTSkip("the gateway's entry is not resolved: \(words[at + 1])") }
        XCTAssertEqual(PacketCapture.gatewayHardwareAddresses(of: interface).first, reported)
    }

    func testKernelAcceptsTheProgram() throws {
        try XCTSkipUnless(access("/dev/bpf0", R_OK) == 0, "needs readable /dev/bpf*")
        let interface = try XCTUnwrap(PacketCapture.primaryInterface())
        let capture = try PacketCapture.open(interface: interface)
        let direction: CaptureFilter.Direction
        if let mac = PacketCapture.hardwareAddress(of: interface), capture.dataLinkType == PacketCapture.linkEthernet {
            direction = .hardwareAddress(mac)
        } else {
            // The interface's own, sorted, as the sniffer builds it.
            direction = .sourceAddresses(localAddresses(of: interface).map(\.bytes).sorted { $0.lexicographicallyPrecedes($1) })
        }
        let filter = try XCTUnwrap(CaptureFilter.program(linkType: capture.dataLinkType, direction: direction))
        XCTAssertNoThrow(try capture.install(filter))
        XCTAssertThrowsError(try capture.install(CaptureFilter(instructions: [.init(code: 0x15, jt: 9, jf: 9, k: 0), .init(code: 0x06, jt: 0, jf: 0, k: 0)])))
    }

    /// Runs a program over a packet the way the kernel does, for the opcodes the
    /// builder emits. Returns the accepted length.
    private enum Interpreter {
        static func run(_ filter: CaptureFilter, on packet: [UInt8]) -> UInt32 {
            var a: UInt32 = 0, x: UInt32 = 0
            var memory = [UInt32](repeating: 0, count: 16)
            var pc = 0
            func load(_ offset: UInt32, _ size: Int) -> UInt32? {
                let start = Int(offset)
                guard start >= 0, start + size <= packet.count else { return nil }
                return packet[start..<(start + size)].reduce(0) { $0 << 8 | UInt32($1) }
            }
            while pc < filter.instructions.count {
                let i = filter.instructions[pc]
                pc += 1
                let cls = i.code & 0x07
                switch cls {
                case 0x00, 0x01:  // LD, LDX
                    let size = i.code & 0x18 == 0x10 ? 1 : i.code & 0x18 == 0x08 ? 2 : 4
                    let value: UInt32?
                    switch i.code & 0xe0 {
                    case 0x20: value = load(i.k, size)
                    case 0x40: value = load(x &+ i.k, size)
                    case 0x60: value = memory[Int(i.k)]
                    case 0xa0: value = load(i.k, 1).map { ($0 & 0x0f) * 4 }
                    case 0x00: value = i.k
                    default: return 0
                    }
                    guard let value else { return 0 }
                    if cls == 0x00 { a = value } else { x = value }
                case 0x02: memory[Int(i.k)] = a
                case 0x03: memory[Int(i.k)] = x
                case 0x04:
                    let operand = i.code & 0x08 != 0 ? x : i.k
                    switch i.code & 0xf0 {
                    case 0x10: a = a &- operand
                    case 0x50: a &= operand
                    case 0x60: a <<= operand
                    case 0x70: a >>= operand
                    default: return 0
                    }
                case 0x05:
                    let operand = i.code & 0x08 != 0 ? x : i.k
                    let taken: Bool
                    switch i.code & 0xf0 {
                    case 0x00: pc += Int(i.k); continue
                    case 0x10: taken = a == operand
                    case 0x20: taken = a > operand
                    case 0x40: taken = a & operand != 0
                    default: return 0
                    }
                    pc += Int(taken ? i.jt : i.jf)
                case 0x06: return i.code & 0x10 != 0 ? a : i.k
                case 0x07: if i.code & 0x80 == 0 { x = a } else { a = x }
                default: return 0
                }
            }
            return 0
        }
    }
}
