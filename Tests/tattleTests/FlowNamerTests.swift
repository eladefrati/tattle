import XCTest
@testable import tattle

final class FlowNamerTests: XCTestCase {
    private let me = IPAddress(bytes: [192, 168, 1, 5])
    private let peer = IPAddress(bytes: [17, 253, 144, 10])
    private let resolver = IPAddress(bytes: [192, 168, 1, 1])
    private let t0 = 1_700_000_000.0

    private func namer() -> FlowNamer { FlowNamer(localAddresses: [me], resolvers: [resolver]) }

    private func tcp(from src: IPAddress? = nil, to dst: IPAddress? = nil, port: UInt16 = 443, flags: UInt8, seq: UInt32, _ payload: [UInt8] = []) -> Packet {
        Packet(src: src ?? me, dst: dst ?? peer, srcPort: 50000, dstPort: port, proto: .tcp, tcpFlags: flags, tcpSeq: seq, payload: payload[...])
    }

    private func udp(from src: IPAddress? = nil, to dst: IPAddress? = nil, srcPort: UInt16 = 50000, dstPort: UInt16 = 443, _ payload: [UInt8]) -> Packet {
        Packet(src: src ?? me, dst: dst ?? peer, srcPort: srcPort, dstPort: dstPort, proto: .udp, tcpFlags: 0, tcpSeq: 0, payload: payload[...])
    }

    private var tcpKey: FlowKey { FlowKey(proto: .tcp, localPort: 50000, remote: peer, remotePort: 443) }
    private var udpKey: FlowKey { FlowKey(proto: .udp, localPort: 50000, remote: peer, remotePort: 443) }

    private var clientHelloRecord: [UInt8] {
        let hello = SnifferParserTests.rfcClientHello
        return [0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello
    }

    private var dnsReply: Packet {
        var bytes: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        bytes += [3, 0x63, 0x64, 0x6e, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6e, 0x65, 0x74, 0, 0x00, 0x01, 0x00, 0x01]
        bytes += [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04] + peer.bytes
        return udp(from: resolver, to: me, srcPort: 53, dstPort: 60000, bytes)
    }

    func testTCPHandshakeOverTwoSegmentsNamesTheFlow() {
        var n = namer()
        XCTAssertEqual(n.observe(tcp(flags: 0x02, seq: 1000), at: t0), [FlowEvent(key: tcpKey, kind: .opened)])
        let record = clientHelloRecord
        let first = Array(record.prefix(40)), second = Array(record.dropFirst(40))
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001, first), at: t0 + 0.01), [])
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001, first), at: t0 + 0.02), [], "a retransmit is dropped")
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001 + UInt32(first.count), second), at: t0 + 0.03),
                       [FlowEvent(key: tcpKey, kind: .named("example.com", .sni))])
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 5000, [1, 2, 3]), at: t0 + 1), [], "a named flow emits nothing more")
        XCTAssertEqual(n.expire(now: t0 + 10), [], "no DNS fallback once the wire named it")
    }

    func testGapEndsBufferingAndSegmentsWithoutASYNAreIgnored() {
        var n = namer()
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 7, clientHelloRecord), at: t0), [], "no SYN seen: not a flow Tattle watches")
        _ = n.observe(tcp(flags: 0x02, seq: 1000), at: t0)
        let record = clientHelloRecord
        _ = n.observe(tcp(flags: 0x18, seq: 1001, Array(record.prefix(50))), at: t0)
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001 + 60, Array(record.dropFirst(60))), at: t0),
                       [FlowEvent(key: tcpKey, kind: .unnamed(.gap))], "a gap: parsing a shifted stream would be wrong")
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001 + 50, Array(record.dropFirst(50))), at: t0), [], "buffering ended, even for the missing piece")
    }

    /// A handshake segment cut at the snap length before the server name cannot be
    /// completed: it says so at once instead of waiting out the timeout, and a later
    /// in-order segment is placed by the segment's length on the wire, not by what was
    /// captured. One cut after the name is named: the rest of the hello is not needed.
    func testASegmentCutByTheSnapLengthEndsBuffering() {
        var n = namer()
        _ = n.observe(tcp(flags: 0x02, seq: 1000), at: t0)
        var cut = tcp(flags: 0x18, seq: 1001, Array(clientHelloRecord.prefix(60)))
        cut.uncaptured = clientHelloRecord.count - 60
        XCTAssertEqual(n.observe(cut, at: t0 + 0.01), [FlowEvent(key: tcpKey, kind: .unnamed(.gap))])
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001 + UInt32(clientHelloRecord.count), [1, 2, 3]), at: t0 + 0.02), [], "no second gap")
        XCTAssertEqual(n.expire(now: t0 + FlowNamer.finalizeAfter), [], "already answered")

        var whole = namer()
        _ = whole.observe(tcp(flags: 0x02, seq: 1000), at: t0)
        var tail = tcp(flags: 0x18, seq: 1001, clientHelloRecord + [0x17, 3, 3, 0, 10])
        tail.uncaptured = 2000
        XCTAssertEqual(whole.observe(tail, at: t0 + 0.01), [FlowEvent(key: tcpKey, kind: .named("example.com", .sni))], "the hello itself was captured whole")

        // A hello of 2,500 bytes sent as one segment, of which the capture keeps what fits
        // in its snap length beside 66 bytes of headers.
        let captured = Int(CaptureFilter.snapLength) - 66
        for (before, expected) in [(1200, FlowEvent.Kind.named("example.com", .sni)), (2300, .unnamed(.gap))] {
            let hello = SnifferParserTests.clientHello(sni: Array("example.com".utf8), before: before, after: 2400 - before)
            let record = [0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello
            var large = namer()
            _ = large.observe(tcp(flags: 0x02, seq: 1000), at: t0)
            var segment = tcp(flags: 0x18, seq: 1001, Array(record.prefix(captured)))
            segment.uncaptured = record.count - captured
            XCTAssertEqual(large.observe(segment, at: t0 + 0.01), [FlowEvent(key: tcpKey, kind: expected)], "the name \(before) bytes into the extensions")
        }
    }

    /// A hello larger than one segment is named from the segment that holds the name, so a
    /// later segment that is lost or out of order costs nothing.
    func testAHelloOverTwoSegmentsIsNamedFromTheOneThatHoldsTheName() {
        let hello = SnifferParserTests.clientHello(sni: Array("example.com".utf8), before: 100, after: 1800)
        let record = [0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello
        var n = namer()
        _ = n.observe(tcp(flags: 0x02, seq: 1000), at: t0)
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001, Array(record.prefix(1460))), at: t0 + 0.01),
                       [FlowEvent(key: tcpKey, kind: .named("example.com", .sni))])
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001 + 1460 + 500, [1, 2, 3]), at: t0 + 0.02), [], "the rest never came in order")

        // The same over QUIC, where such a hello spans two Initials.
        var q = namer()
        let piece = Array(hello.prefix(1000))
        let frame: [UInt8] = [0x06, 0x00, 0x40 | UInt8(piece.count >> 8), UInt8(piece.count & 0xff)] + piece
        XCTAssertEqual(q.observe(udp(SnifferParserTests.sealInitial(frame)), at: t0).last?.kind, .named("example.com", .quic))
    }

    func testNotAHandshakeAndTimeoutAreReported() {
        var n = namer()
        _ = n.observe(tcp(port: 22, flags: 0x02, seq: 1), at: t0)
        let ssh = FlowKey(proto: .tcp, localPort: 50000, remote: peer, remotePort: 22)
        XCTAssertEqual(n.observe(tcp(port: 22, flags: 0x18, seq: 2, Array("SSH-2.0-OpenSSH\r\n".utf8)), at: t0), [FlowEvent(key: ssh, kind: .unnamed(.notHandshake))])
        XCTAssertEqual(n.observe(tcp(port: 22, flags: 0x18, seq: 19, [1, 2, 3]), at: t0 + 1), [], "reported once")

        _ = n.observe(tcp(flags: 0x02, seq: 1), at: t0)
        XCTAssertEqual(n.expire(now: t0 + FlowNamer.finalizeAfter), [FlowEvent(key: tcpKey, kind: .unnamed(.timeout))], "no payload ever came")
        XCTAssertEqual(n.expire(now: t0 + FlowNamer.finalizeAfter + 1), [], "once")
    }

    func testHTTPHostNamesAPlaintextFlow() {
        var n = namer()
        _ = n.observe(tcp(port: 80, flags: 0x02, seq: 1), at: t0)
        let key = FlowKey(proto: .tcp, localPort: 50000, remote: peer, remotePort: 80)
        XCTAssertEqual(n.observe(tcp(port: 80, flags: 0x18, seq: 2, Array("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n".utf8)), at: t0),
                       [FlowEvent(key: key, kind: .named("example.org", .http))])
    }

    private func tlsOutcome(_ sni: [UInt8]) -> FlowEvent.Kind? {
        var n = namer()
        _ = n.observe(tcp(flags: 0x02, seq: 1), at: t0)
        let hello = SnifferParserTests.clientHello(sni: sni)
        return n.observe(tcp(flags: 0x18, seq: 2, [0x16, 0x03, 0x01, UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello), at: t0).first?.kind
    }

    private func httpOutcome(_ host: [UInt8]) -> FlowEvent.Kind? {
        var n = namer()
        _ = n.observe(tcp(port: 80, flags: 0x02, seq: 1), at: t0)
        return n.observe(tcp(port: 80, flags: 0x18, seq: 2, Array("GET / HTTP/1.1\r\nHost: ".utf8) + host + Array("\r\n\r\n".utf8)), at: t0).first?.kind
    }

    private func quicOutcome(_ sni: [UInt8]) -> FlowEvent.Kind? {
        var n = namer()
        let hello = SnifferParserTests.clientHello(sni: sni)
        let frame: [UInt8] = [0x06, 0x00, 0x40 | UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello
        return n.observe(udp(SnifferParserTests.sealInitial(frame)), at: t0).last?.kind
    }

    /// A name off the wire is a host name or nothing: the sender picks every byte of it.
    func testNamesThatFailValidationLeaveTheFlowUnnamed() {
        for (shape, name) in SnifferParserTests.rejectedNames {
            XCTAssertEqual(tlsOutcome(name), .unnamed(.noServerName), "SNI with \(shape)")
            XCTAssertEqual(quicOutcome(name), .unnamed(.noServerName), "QUIC SNI with \(shape)")
            // A Host header is one line: a CR or LF in it ends the header instead.
            guard !name.contains(0x0d), !name.contains(0x0a), shape != "a port outside a Host header" else { continue }
            XCTAssertEqual(httpOutcome(name), .unnamed(.noServerName), "Host with \(shape)")
        }
        XCTAssertEqual(httpOutcome(Array("example.org:x".utf8)), .unnamed(.noServerName), "a port that is not a number")
        XCTAssertEqual(tlsOutcome(Array("Example.COM.".utf8)), .named("example.com", .sni))
        XCTAssertEqual(quicOutcome(Array("Example.COM.".utf8)), .named("example.com", .quic))
        XCTAssertEqual(httpOutcome(Array("Example.ORG:8080".utf8)), .named("example.org", .http), "the port is not part of the name")
    }

    func testQUICInitialNamesTheFlow() {
        var n = namer()
        XCTAssertEqual(n.observe(udp(SnifferParserTests.rfcInitial), at: t0),
                       [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .named("example.com", .quic))])
        XCTAssertEqual(n.observe(udp(SnifferParserTests.rfcInitial), at: t0 + 0.1), [], "same connection, already named")
        XCTAssertEqual(n.flowCount, 1)
    }

    /// Any local process can send a sealed Initial whose CRYPTO frame is empty: the keys come
    /// from the packet. It must not hang the capture thread.
    func testASealedInitialWithAnEmptyCryptoFrameReturns() {
        let datagram = SnifferParserTests.sealInitial([0x06, 0x00, 0x00])
        let packet = udp(datagram)
        let start = t0
        let me = self.me
        XCTAssertTrue(SnifferParserTests.returns {
            var n = FlowNamer(localAddresses: [me], resolvers: [])
            _ = n.observe(packet, at: start)
            _ = n.observe(packet, at: start + 0.1)
        }, "observe returned")
    }

    /// A ClientHello that claims to be larger than the TCP buffer cap, sent one Initial at a
    /// time, stops being buffered at the cap, as over TCP.
    func testAQUICHandshakeLargerThanTheCapIsGivenUp() {
        var n = namer()
        let piece = 1000
        var hello: [UInt8] = [1, 0x01, 0x00, 0x00]  // a ClientHello of 64 KB
        hello += [UInt8](repeating: 0x41, count: piece - hello.count)
        var offset = 0
        var events: [FlowEvent] = []
        while offset <= FlowNamer.bufferLimit + piece, !events.contains(where: { $0.kind != .opened }) {
            let data = offset == 0 ? hello : [UInt8](repeating: 0x41, count: piece)
            let frame: [UInt8] = [0x06, 0x80 | UInt8(offset >> 24), UInt8((offset >> 16) & 0xff), UInt8((offset >> 8) & 0xff), UInt8(offset & 0xff),
                                  0x40 | UInt8(piece >> 8), UInt8(piece & 0xff)] + data
            events += n.observe(udp(SnifferParserTests.sealInitial(frame)), at: t0 + Double(offset) / 100_000)
            offset += piece
        }
        XCTAssertEqual(events.last, FlowEvent(key: udpKey, kind: .unnamed(.noServerName)))
        XCTAssertLessThanOrEqual(offset, FlowNamer.bufferLimit + piece, "given up at the cap")
    }

    private func sealedHello(_ sni: String, dcid: [UInt8]) -> [UInt8] {
        let hello = SnifferParserTests.clientHello(sni: Array(sni.utf8))
        return SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(hello.count >> 8), UInt8(hello.count & 0xff)] + hello, dcid: dcid)
    }

    /// A client that reuses a local port for a new QUIC connection sends a first Initial with a
    /// new destination connection id: like a SYN over TCP, it starts a new flow. Later Initials
    /// of the same connection carry the id the server chose, which the keys derived from it do
    /// not open, so they do not.
    func testANewInitialOnAFinishedQUICFlowStartsANewFlow() {
        var n = namer()
        _ = n.observe(udp(SnifferParserTests.rfcInitial), at: t0)
        let next = sealedHello("example.org", dcid: [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(n.observe(udp(next), at: t0 + 30),
                       [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .named("example.org", .quic))], "after a named flow")
        XCTAssertEqual(n.observe(udp(next), at: t0 + 30.1), [], "the same Initial again")
        var serverChosen = next
        serverChosen[6] ^= 0xff
        XCTAssertEqual(n.observe(udp(serverChosen), at: t0 + 30.2), [], "an Initial its own id does not open")
        XCTAssertEqual(n.flowCount, 1)

        var timedOut = namer()
        _ = timedOut.observe(udp(serverChosen), at: t0)
        _ = timedOut.expire(now: t0 + FlowNamer.finalizeAfter)
        XCTAssertEqual(timedOut.observe(udp(next), at: t0 + 30),
                       [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .named("example.org", .quic))], "after a flow given up on")
    }

    /// A Retry moves the client to an id the server chose before the handshake is over, and a
    /// ClientHello split over two Initials can finish under it. Only a finished flow restarts
    /// on a new id, so this one is named from both halves.
    func testANewIdOnAPendingQUICFlowDoesNotRestartIt() {
        var n = namer()
        let hello = SnifferParserTests.clientHello(sni: Array("example.org".utf8))
        let half = hello.count / 2
        let rest = hello.count - half
        let first = SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(half >> 8), UInt8(half & 0xff)] + hello[..<half],
                                                   dcid: [1, 2, 3, 4, 5, 6, 7, 8])
        let second = SnifferParserTests.sealInitial([0x06, 0x40 | UInt8(half >> 8), UInt8(half & 0xff), 0x40 | UInt8(rest >> 8), UInt8(rest & 0xff)] + hello[half...],
                                                    dcid: [9, 10, 11, 12, 13, 14, 15, 16])
        XCTAssertEqual(n.observe(udp(first), at: t0), [FlowEvent(key: udpKey, kind: .opened)], "half a ClientHello")
        XCTAssertEqual(n.observe(udp(second), at: t0 + 0.1), [FlowEvent(key: udpKey, kind: .named("example.org", .quic))],
                       "the rest, under the id from the Retry")
        XCTAssertEqual(n.flowCount, 1)
    }

    func testBytesAfterAnInitialDoNotEndTheFlowAsAnotherVersion() {
        var n = namer()
        let hello = SnifferParserTests.clientHello(sni: Array("example.org".utf8))
        let half = hello.count / 2
        let rest = hello.count - half
        let first = SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(half >> 8), UInt8(half & 0xff)] + hello[..<half])
        let second = SnifferParserTests.sealInitial([0x06, 0x40 | UInt8(half >> 8), UInt8(half & 0xff), 0x40 | UInt8(rest >> 8), UInt8(rest & 0xff)] + hello[half...])
        XCTAssertEqual(n.observe(udp(first + [0xc0, 0, 0, 0, 2, 0, 0]), at: t0), [FlowEvent(key: udpKey, kind: .opened)])
        XCTAssertEqual(n.observe(udp(second), at: t0 + 0.1), [FlowEvent(key: udpKey, kind: .named("example.org", .quic))])
    }

    func testAQUICStreamThatIsNoClientHelloEndsAtOnceAsOverTCP() {
        var n = namer()
        let serverHello: [UInt8] = [2, 0, 0, 4, 1, 2, 3, 4]
        let initial = SnifferParserTests.sealInitial([0x06, 0x00, UInt8(serverHello.count)] + serverHello)
        XCTAssertEqual(n.observe(udp(initial), at: t0),
                       [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .unnamed(.notHandshake))])
        XCTAssertEqual(n.expire(now: t0 + FlowNamer.finalizeAfter), [], "nothing left to give up on")
    }

    func testShortHeaderDoesNotStartAFlow() {
        var n = namer()
        XCTAssertEqual(n.observe(udp([0x41, 1, 2, 3]), at: t0), [], "a connection open before capture started")
        XCTAssertEqual(n.flowCount, 0)
    }

    func testALongHeaderOfAnotherVersionOpensAFlowItCannotRead() {
        var n = namer()
        var otherVersion = SnifferParserTests.rfcInitial
        otherVersion[4] = 2
        XCTAssertEqual(n.observe(udp(otherVersion), at: t0),
                       [FlowEvent(key: udpKey, kind: .opened), FlowEvent(key: udpKey, kind: .unnamed(.quic(.unsupportedVersion)))], "opened, but unreadable")
    }

    /// Only what can be a client's first QUIC packet starts a flow: long header with the fixed
    /// bit (0xC0), in a datagram of at least 1200 bytes (RFC 9000 14.1), not to DNS. RTP's
    /// first byte (0x80) and a DNS query whose id has the high bit set would otherwise show as
    /// "a QUIC version Tattle cannot read".
    func testOnlyAClientInitialStartsAUDPFlow() {
        var n = namer()
        var rtp = [UInt8](repeating: 0, count: 1300)
        rtp[0] = 0x80
        XCTAssertEqual(n.observe(udp(dstPort: 5004, rtp), at: t0), [], "RTP version 2")
        XCTAssertEqual(n.observe(udp([0xc3, 0, 0, 0, 1] + [UInt8](repeating: 0, count: 95)), at: t0), [], "too small for a client Initial")
        XCTAssertEqual(n.observe(udp(dstPort: 53, SnifferParserTests.rfcInitial), at: t0), [], "a DNS query, whatever its first byte")
        for (first, type) in [(UInt8(0xd0), "0-RTT"), (0xe0, "Handshake")] {
            XCTAssertEqual(n.observe(udp([first, 0, 0, 0, 1] + [UInt8](repeating: 0, count: 1295)), at: t0), [], "a version 1 \(type) packet")
        }
        XCTAssertEqual(n.flowCount, 0)
    }

    func testDNSFallbackAfterThreeSecondsOnlyWhenNothingElseNamed() {
        var n = namer()
        XCTAssertEqual(n.observe(dnsReply, at: t0), [], "a reply updates the map and says nothing")
        XCTAssertEqual(n.dnsCount, 1)
        _ = n.observe(tcp(flags: 0x02, seq: 1), at: t0 + 1)
        XCTAssertEqual(n.expire(now: t0 + 3), [], "the wire gets three seconds first")
        XCTAssertEqual(n.expire(now: t0 + 4), [FlowEvent(key: tcpKey, kind: .named("cdn.example.net", .dns))])
        XCTAssertEqual(n.expire(now: t0 + 5), [], "once")
    }

    /// The DNS fallback is a stand-in, not an answer: a handshake that comes after it (late,
    /// as after a wake) names the flow from the wire, and the give-up timeout does not
    /// replace the DNS name with "no complete handshake".
    func testAWireNameAfterTheDNSFallbackReplacesIt() {
        var n = namer()
        _ = n.observe(dnsReply, at: t0)
        _ = n.observe(tcp(flags: 0x02, seq: 1000), at: t0 + 1)
        XCTAssertEqual(n.expire(now: t0 + 4.5), [FlowEvent(key: tcpKey, kind: .named("cdn.example.net", .dns))])
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001, clientHelloRecord), at: t0 + 6),
                       [FlowEvent(key: tcpKey, kind: .named("example.com", .sni))])
        XCTAssertEqual(n.expire(now: t0 + 1 + FlowNamer.finalizeAfter), [])

        var silent = namer()
        _ = silent.observe(dnsReply, at: t0)
        _ = silent.observe(tcp(flags: 0x02, seq: 1000), at: t0 + 1)
        _ = silent.expire(now: t0 + 4.5)
        XCTAssertEqual(silent.expire(now: t0 + 1 + FlowNamer.finalizeAfter), [], "the DNS name stands")

        var garbage = namer()
        _ = garbage.observe(dnsReply, at: t0)
        _ = garbage.observe(tcp(flags: 0x02, seq: 1000), at: t0 + 1)
        _ = garbage.expire(now: t0 + 4.5)
        XCTAssertEqual(garbage.observe(tcp(flags: 0x18, seq: 1001, [0x53, 0x53, 0x48]), at: t0 + 6), [], "a failure on the wire does not replace the DNS name")
    }

    /// A DNS reply without compression: `answers` are (owner, type, rdata), type 1 (A) or 5 (CNAME).
    static func dnsMessage(question: String, answers: [(String, UInt16, [UInt8])]) -> [UInt8] {
        func name(_ text: String) -> [UInt8] {
            text.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
        }
        var bytes: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, UInt8(answers.count >> 8), UInt8(answers.count & 0xff), 0, 0, 0, 0]
        bytes += name(question) + [0x00, 0x01, 0x00, 0x01]
        for (owner, type, rdata) in answers {
            bytes += name(owner) + [UInt8(type >> 8), UInt8(type & 0xff), 0x00, 0x01, 0, 0, 0, 0x3c, UInt8(rdata.count >> 8), UInt8(rdata.count & 0xff)] + rdata
        }
        return bytes
    }

    private func cname(_ owner: String, _ target: String) -> (String, UInt16, [UInt8]) {
        (owner, 5, target.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0])
    }

    private func named(after reply: Packet, _ n: inout FlowNamer) -> FlowEvent.Kind? {
        _ = n.observe(reply, at: t0)
        _ = n.observe(tcp(port: 22, flags: 0x02, seq: 1), at: t0)
        return n.expire(now: t0 + FlowNamer.dnsFallbackAfter).first?.kind
    }

    /// Only the resolvers this Mac asks may name addresses: a broadcast from any host on the
    /// network named an arbitrary address www.apple.com.
    func testADNSReplyFromAHostThatIsNotAResolverIsIgnored() {
        var n = namer()
        let lanHost = IPAddress(bytes: [192, 168, 1, 20])
        let forged = udp(from: lanHost, to: me, srcPort: 53, dstPort: 60000, Self.dnsMessage(question: "www.apple.com", answers: [("www.apple.com", 1, peer.bytes)]))
        XCTAssertNil(named(after: forged, &n), "from a host that is not a resolver")
        XCTAssertEqual(n.dnsCount, 0)

        var moved = namer()
        moved.updateResolvers([lanHost])
        XCTAssertEqual(named(after: forged, &moved), .named("www.apple.com", .dns), "the resolver set follows the network")
    }

    func testADNSReplyNotAddressedToThisMacIsIgnored() {
        let answer = Self.dnsMessage(question: "www.apple.com", answers: [("www.apple.com", 1, peer.bytes)])
        for destination in [IPAddress(bytes: [192, 168, 1, 255]), IPAddress(bytes: [255, 255, 255, 255]), IPAddress(bytes: [224, 0, 0, 251]), IPAddress(bytes: [192, 168, 1, 6])] {
            var n = namer()
            XCTAssertNil(named(after: udp(from: resolver, to: destination, srcPort: 53, dstPort: 60000, answer), &n), "to \(destination.text)")
            XCTAssertEqual(n.dnsCount, 0)
        }
    }

    /// A site's own authoritative answer could add other services' addresses under its
    /// question name; an address counts only when its record is for the question name or a
    /// CNAME target reached from it.
    func testOnlyRecordsForTheQuestionNameOrItsCNAMEChainCount() {
        var n = namer()
        let site = IPAddress(bytes: [203, 0, 113, 7])
        let reply = Self.dnsMessage(question: "www.site.example", answers: [
            cname("www.site.example", "edge.site.example"),
            ("edge.site.example", 1, site.bytes),
            ("ssh.other.example", 1, peer.bytes),
            cname("unrelated.example", "www.other.example"),
            ("www.other.example", 1, peer.bytes),
        ])
        XCTAssertNil(named(after: udp(from: resolver, to: me, srcPort: 53, dstPort: 60000, reply), &n), "the peer's records are not for the question")
        XCTAssertEqual(n.dnsCount, 1, "the address the chain reached is kept")

        var chain = namer()
        let real = Self.dnsMessage(question: "WWW.Example.com", answers: [
            cname("www.example.com", "a.cdn.example"),
            cname("A.CDN.example", "b.cdn.example"),
            ("b.cdn.example", 1, peer.bytes),
        ])
        XCTAssertEqual(named(after: udp(from: resolver, to: me, srcPort: 53, dstPort: 60000, real), &chain), .named("www.example.com", .dns),
                       "a resolver's reply with a CNAME chain still names, case aside")
    }

    /// Forged replies grew the map without bound (990k entries from 16 MB). Past the cap the
    /// oldest answer goes, and an answer seen again counts as new.
    func testTheDNSMapKeepsTheNewestAnswersUpToItsCapacity() {
        var n = namer()
        func address(_ i: Int) -> IPAddress { IPAddress(bytes: [23, 0, UInt8(i >> 8), UInt8(i & 0xff)]) }
        func reply(_ i: Int) -> Packet {
            udp(from: resolver, to: me, srcPort: 53, dstPort: 60000,
                Self.dnsMessage(question: "h\(i).example", answers: [("h\(i).example", 1, address(i).bytes)]))
        }
        let total = FlowNamer.dnsCapacity + 10
        for i in 0..<total {
            _ = n.observe(reply(i), at: t0 + Double(i) / 10_000)
            if i == FlowNamer.dnsCapacity / 2 { _ = n.observe(reply(0), at: t0 + Double(i) / 10_000) }
        }
        XCTAssertEqual(n.dnsCount, FlowNamer.dnsCapacity)
        for (i, port) in [(0, UInt16(1)), (1, 2), (total - 1, 3)] {
            _ = n.observe(Packet(src: me, dst: address(i), srcPort: port, dstPort: 443, proto: .tcp, tcpFlags: 0x02, tcpSeq: 1, payload: []), at: t0 + 1)
        }
        let names = Dictionary(uniqueKeysWithValues: n.expire(now: t0 + 1 + FlowNamer.dnsFallbackAfter).map { ($0.key.localPort, $0.kind) })
        XCTAssertEqual(names[1], .named("h0.example", .dns), "seen again halfway, so not among the oldest")
        XCTAssertNil(names[2], "among the oldest, evicted")
        XCTAssertEqual(names[3], .named("h\(total - 1).example", .dns), "the newest is kept")
    }

    /// Any local process can open flows faster than they go idle, and every SYN to a new port
    /// grew the table. Past the cap the flow that started first goes: by then it has almost
    /// always finished. A restarted flow counts as new.
    func testTheFlowTableKeepsTheNewestFlowsUpToItsCapacity() {
        var n = namer()
        func packet(_ i: Int, flags: UInt8, seq: UInt32, _ payload: [UInt8] = []) -> Packet {
            Packet(src: me, dst: peer, srcPort: UInt16(1000 + i), dstPort: 443, proto: .tcp, tcpFlags: flags, tcpSeq: seq, payload: payload[...])
        }
        let total = FlowNamer.flowCapacity + 10
        for i in 0..<total {
            _ = n.observe(packet(i, flags: 0x02, seq: 1), at: t0 + Double(i) / 10_000)
            if i == FlowNamer.flowCapacity / 2 { _ = n.observe(packet(0, flags: 0x02, seq: 1), at: t0 + Double(i) / 10_000) }
        }
        XCTAssertEqual(n.flowCount, FlowNamer.flowCapacity)
        let named = FlowEvent.Kind.named("example.com", .sni)
        XCTAssertEqual(n.observe(packet(0, flags: 0x18, seq: 2, clientHelloRecord), at: t0 + 1).first?.kind, named, "restarted halfway, so not among the oldest")
        XCTAssertEqual(n.observe(packet(1, flags: 0x18, seq: 2, clientHelloRecord), at: t0 + 1), [], "among the oldest, evicted")
        XCTAssertEqual(n.observe(packet(total - 1, flags: 0x18, seq: 2, clientHelloRecord), at: t0 + 1).first?.kind, named, "the newest is kept")

        var restarted = namer()
        for i in 0..<(3 * FlowNamer.flowCapacity) { _ = restarted.observe(packet(0, flags: 0x02, seq: 1), at: t0 + Double(i) / 10_000) }
        XCTAssertEqual(restarted.flowCount, 1)
    }

    func testAFlowEvictedBeforeItWasNamedIsGivenUpOn() {
        var n = namer()
        let unknown = IPAddress(bytes: [203, 0, 113, 7])
        func packet(_ port: UInt16, to dst: IPAddress, flags: UInt8 = 0x02, seq: UInt32 = 1, _ payload: [UInt8] = []) -> Packet {
            Packet(src: me, dst: dst, srcPort: port, dstPort: 443, proto: .tcp, tcpFlags: flags, tcpSeq: seq, payload: payload[...])
        }
        _ = n.observe(dnsReply, at: t0)
        _ = n.observe(packet(1000, to: peer), at: t0)
        _ = n.observe(packet(1001, to: unknown), at: t0)
        _ = n.observe(packet(1002, to: unknown), at: t0)
        _ = n.observe(packet(1002, to: unknown, flags: 0x18, seq: 2, Array("SSH-2.0-OpenSSH\r\n".utf8)), at: t0)
        for i in 0..<(FlowNamer.flowCapacity - 3) { _ = n.observe(packet(UInt16(2000 + i), to: unknown), at: t0 + 0.5) }

        var events: [FlowEvent] = []
        for i in 0..<3 { events += n.observe(packet(UInt16(9000 + i), to: unknown), at: t0 + 1) }
        XCTAssertEqual(events.filter { $0.kind != .opened }, [
            FlowEvent(key: FlowKey(proto: .tcp, localPort: 1000, remote: peer, remotePort: 443), kind: .named("cdn.example.net", .dns)),
            FlowEvent(key: FlowKey(proto: .tcp, localPort: 1001, remote: unknown, remotePort: 443), kind: .unnamed(.evicted)),
        ], "the DNS map's name, else a reason; nothing for the finished one")
        XCTAssertEqual(events.filter { $0.kind == .opened }.count, 3)
        XCTAssertEqual(n.flowCount, FlowNamer.flowCapacity)
    }

    /// The capture ending takes the namer and its flows with it: a stop, a restart, the default
    /// route moving, a failed read. A flow still waiting for its handshake gets what a timeout
    /// gives, or it would keep neither a name nor a reason.
    func testFlowsPendingWhenTheCaptureEndsAreGivenUpOn() {
        var n = namer()
        let unknown = IPAddress(bytes: [203, 0, 113, 7])
        func packet(_ port: UInt16, to dst: IPAddress, flags: UInt8 = 0x02, seq: UInt32 = 1, _ payload: [UInt8] = []) -> Packet {
            Packet(src: me, dst: dst, srcPort: port, dstPort: 443, proto: .tcp, tcpFlags: flags, tcpSeq: seq, payload: payload[...])
        }
        let hello = SnifferParserTests.clientHello(sni: Array("example.org".utf8))
        let half = hello.count / 2
        _ = n.observe(dnsReply, at: t0)
        _ = n.observe(packet(1000, to: peer), at: t0)
        _ = n.observe(packet(1001, to: unknown), at: t0)
        _ = n.observe(packet(1001, to: unknown, flags: 0x18, seq: 2, Array(clientHelloRecord.prefix(50))), at: t0)
        _ = n.observe(packet(1002, to: unknown), at: t0)
        _ = n.observe(packet(1002, to: unknown, flags: 0x18, seq: 2, Array("SSH-2.0-OpenSSH\r\n".utf8)), at: t0)
        XCTAssertEqual(n.observe(udp(to: unknown, SnifferParserTests.sealInitial([0x06, 0x00, 0x40 | UInt8(half >> 8), UInt8(half & 0xff)] + hello[..<half])), at: t0),
                       [FlowEvent(key: FlowKey(proto: .udp, localPort: 50000, remote: unknown, remotePort: 443), kind: .opened)], "half a ClientHello")

        XCTAssertEqual(n.endCapture().sorted { $0.key.localPort < $1.key.localPort }, [
            FlowEvent(key: FlowKey(proto: .tcp, localPort: 1000, remote: peer, remotePort: 443), kind: .named("cdn.example.net", .dns)),
            FlowEvent(key: FlowKey(proto: .tcp, localPort: 1001, remote: unknown, remotePort: 443), kind: .unnamed(.captureEnded)),
            FlowEvent(key: FlowKey(proto: .udp, localPort: 50000, remote: unknown, remotePort: 443), kind: .unnamed(.captureEnded)),
        ], "the DNS map's name, else a reason; nothing for the finished one")
    }

    func testOneAnswerRepeatedStaysOneEntryAndIsStillForgotten() {
        var n = namer()
        for i in 0..<(3 * FlowNamer.dnsCapacity) { _ = n.observe(dnsReply, at: t0 + Double(i) / 10_000) }
        XCTAssertEqual(n.dnsCount, 1)
        _ = n.expire(now: t0 + 2 + FlowNamer.dnsRemembered)
        XCTAssertEqual(n.dnsCount, 0)
    }

    func testDNSMapIsOnlyConsultedOnceAndForgotten() {
        var n = namer()
        _ = n.observe(tcp(flags: 0x02, seq: 1), at: t0)
        XCTAssertEqual(n.expire(now: t0 + 4), [], "nothing in the map")
        _ = n.observe(dnsReply, at: t0 + 5)
        XCTAssertEqual(n.expire(now: t0 + 6), [], "a reply arriving after the fallback ran does not rename")
        _ = n.expire(now: t0 + 5 + FlowNamer.dnsRemembered)
        XCTAssertEqual(n.dnsCount, 0)
    }

    func testIdleFlowsAreForgottenAndOldOnesGivenUpOn() {
        var n = namer()
        _ = n.observe(tcp(flags: 0x02, seq: 1000), at: t0)
        _ = n.expire(now: t0 + FlowNamer.finalizeAfter)
        XCTAssertEqual(n.observe(tcp(flags: 0x18, seq: 1001, clientHelloRecord), at: t0 + FlowNamer.finalizeAfter), [], "given up: the handshake came too late")
        XCTAssertEqual(n.flowCount, 1)
        _ = n.expire(now: t0 + FlowNamer.finalizeAfter + FlowNamer.idleAfter)
        XCTAssertEqual(n.flowCount, 0)
        XCTAssertEqual(n.observe(tcp(flags: 0x02, seq: 1), at: t0 + 200), [FlowEvent(key: tcpKey, kind: .opened)], "the same addresses again are a new connection")
    }

    func testDirectionAndScope() {
        var n = namer()
        XCTAssertEqual(n.observe(tcp(from: peer, to: me, flags: 0x02, seq: 1), at: t0), [], "inbound SYN: not ours")
        XCTAssertEqual(n.observe(tcp(to: IPAddress(bytes: [192, 168, 1, 20]), flags: 0x02, seq: 1), at: t0), [], "this network needs no public name")
        let newAddress = IPAddress(bytes: [10, 0, 0, 9])
        XCTAssertEqual(n.observe(tcp(from: newAddress, flags: 0x02, seq: 1), at: t0), [], "not known as ours yet")
        XCTAssertTrue(n.endpointsUnknown(tcp(from: newAddress, flags: 0x02, seq: 1)), "to the internet from an address not known as ours: the set is stale")
        XCTAssertTrue(n.endpointsUnknown(tcp(from: IPAddress(bytes: [203, 0, 113, 9]), flags: 0x02, seq: 1)))
        XCTAssertFalse(n.endpointsUnknown(tcp(from: me, flags: 0x02, seq: 1)), "ours")
        XCTAssertFalse(n.endpointsUnknown(tcp(from: peer, to: me, flags: 0x12, seq: 1)), "inbound to us")
        XCTAssertFalse(n.endpointsUnknown(tcp(from: newAddress, to: IPAddress(bytes: [192, 168, 1, 20]), flags: 0x02, seq: 1)), "this network: no public destination to judge by")
        XCTAssertFalse(n.endpointsUnknown(dnsReply))
        n.updateLocalAddresses([newAddress])
        XCTAssertEqual(n.observe(tcp(from: newAddress, flags: 0x02, seq: 1), at: t0).count, 1)
        n.updateLocalAddresses([])
        XCTAssertEqual(n.observe(tcp(from: newAddress, flags: 0x02, seq: 2), at: t0 + 200).count, 1, "an empty reading keeps the old set")
    }

    func testFlowKeyTextMatchesConnectionShape() {
        XCTAssertEqual(tcpKey.text, "tcp/50000>17.253.144.10:443")
        XCTAssertEqual(FlowKey(proto: .udp, localPort: 1, remote: IPAddress(bytes: [0x26, 0x06, 0x47, 0] + [UInt8](repeating: 0, count: 10) + [0x11, 0x11]), remotePort: 443).text,
                       "udp/1>2606:4700::1111:443")
    }
}
