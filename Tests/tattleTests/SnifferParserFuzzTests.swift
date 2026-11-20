import Foundation
import XCTest
@testable import tattle

/// Every byte the sniffer parses is chosen by whoever sent the packet, and a parser that
/// traps takes the app down with it. The other parser tests are examples; this one runs
/// every prefix and many random mutations of each fixture through every parser, and through
/// a namer for the frames, and asserts only that each returns. The mutations come from a
/// fixed seed, so a failure is the same failure on the next run; `TATTLE_FUZZ_SEED` runs
/// another seed.
final class SnifferParserFuzzTests: XCTestCase {
    /// SplitMix64: a few lines, and the same sequence on every machine.
    struct Generator: RandomNumberGenerator {
        var state: UInt64

        mutating func next() -> UInt64 {
            state &+= 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }
    }

    static let defaultSeed: UInt64 = 0x7a77_1e5e_ed00_0001
    static let mutationsPerFixture = 2000

    private static let me: [UInt8] = [192, 168, 1, 5]
    private static let resolver: [UInt8] = [192, 168, 1, 1]
    private static let remote: [UInt8] = [93, 184, 216, 34]
    private static let me6: [UInt8] = [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [5]
    private static let remote6: [UInt8] = [0x26, 0x06, 0x28, 0x00] + [UInt8](repeating: 0, count: 11) + [0x46]
    private static let hardware: [UInt8] = [0x02, 0, 0, 0, 0, 0x05]

    private static func tcp(from sport: UInt16, to dport: UInt16, seq: UInt32, flags: UInt8, _ payload: [UInt8]) -> [UInt8] {
        [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff),
         UInt8(seq >> 24), UInt8(seq >> 16 & 0xff), UInt8(seq >> 8 & 0xff), UInt8(seq & 0xff),
         0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0] + payload
    }

    private static func udp(from sport: UInt16, to dport: UInt16, _ payload: [UInt8]) -> [UInt8] {
        let length = 8 + payload.count
        return [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff),
                UInt8(length >> 8), UInt8(length & 0xff), 0, 0] + payload
    }

    private static func ipv4(from src: [UInt8], to dst: [UInt8], proto: UInt8, _ transport: [UInt8]) -> [UInt8] {
        let total = 20 + transport.count
        return [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0, 0, 64, proto, 0, 0] + src + dst + transport
    }

    private static func ipv6(from src: [UInt8], to dst: [UInt8], proto: UInt8, _ transport: [UInt8]) -> [UInt8] {
        [0x60, 0, 0, 0, UInt8(transport.count >> 8), UInt8(transport.count & 0xff), proto, 64] + src + dst + transport
    }

    private static func ethernet(_ ip: [UInt8], from source: [UInt8] = hardware) -> [UInt8] {
        [0x02, 0, 0, 0, 0, 0x01] + source + (ip[0] >> 4 == 6 ? [0x86, 0xdd] : [0x08, 0x00]) + ip
    }

    private static func record(_ handshake: [UInt8]) -> [UInt8] {
        [0x16, 0x03, 0x01, UInt8(handshake.count >> 8), UInt8(handshake.count & 0xff)] + handshake
    }

    /// What the parsers read in the app, by what carries it: handshake messages, records,
    /// datagrams, DNS messages, a request, and whole frames of each link type.
    static let fixtures: [(name: String, bytes: [UInt8])] = {
        let hello = SnifferParserTests.rfcClientHello
        let http = Array("GET /x HTTP/1.1\r\nHost: example.org:8080\r\nAccept: */*\r\n\r\n".utf8)
        let reply = FlowNamerTests.dnsMessage(question: "www.example.com", answers: [
            ("www.example.com", 5, [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0]),
            ("example.com", 1, remote),
            ("example.com", 28, remote6),
        ])
        return [
            ("ClientHello", hello),
            ("ClientHello in a record", record(hello)),
            ("ClientHello in two records", record(Array(hello[..<50])) + record(Array(hello[50...]))),
            ("QUIC Initial", SnifferParserTests.rfcInitial),
            ("CRYPTO frame", SnifferParserTests.rfcCryptoFrame),
            ("DNS query", SnifferParserTests.query),
            ("DNS reply", reply),
            ("HTTP request", http),
            ("Ethernet SYN", ethernet(ipv4(from: me, to: remote, proto: 6, tcp(from: 50000, to: 443, seq: 1, flags: 0x02, [])))),
            ("Ethernet ClientHello", ethernet(ipv4(from: me, to: remote, proto: 6, tcp(from: 50000, to: 443, seq: 2, flags: 0x18, record(hello))))),
            ("Ethernet QUIC Initial", ethernet(ipv4(from: me, to: remote, proto: 17, udp(from: 50001, to: 443, SnifferParserTests.rfcInitial)))),
            ("Ethernet DNS query", ethernet(ipv4(from: me, to: resolver, proto: 17, udp(from: 50002, to: 53, [0x12, 0x34] + SnifferParserTests.query.dropFirst(2))))),
            ("Ethernet DNS reply", ethernet(ipv4(from: resolver, to: me, proto: 17, udp(from: 53, to: 50002, reply)), from: [0x02, 0, 0, 0, 0, 0x01])),
            ("null link IPv6 HTTP request", [30, 0, 0, 0] + ipv6(from: me6, to: remote6, proto: 6, tcp(from: 50003, to: 80, seq: 2, flags: 0x18, http))),
            ("raw IPv6 QUIC Initial", ipv6(from: me6, to: remote6, proto: 17, udp(from: 50004, to: 443, SnifferParserTests.rfcInitial))),
        ]
    }()

    /// Runs one input through every parser. Frames that parse go on to a namer that takes the
    /// fixtures' addresses for this Mac's, so the flows they open are followed.
    static func parse(_ bytes: [UInt8], namer: inout FlowNamer, at time: Double) {
        _ = TLS.clientHello(bytes)
        _ = TLS.clientHelloFromRecords(bytes)
        _ = HTTP.request(bytes[...])
        _ = DNS.parseReply(bytes[...])
        _ = DNS.parseQuery(bytes[...])
        _ = DNS.transactionID(bytes[...])
        _ = HostName(bytes)
        _ = HostName(bytes, allowingPort: true)
        _ = QUIC.mayBeClientInitial(bytes)
        var assembly = QUICAssembly()
        for start in [0, bytes.count / 2] {
            if case .success(let initial) = QUIC.parseInitial(bytes, at: start) { assembly.add(initial.chunks) }
        }
        _ = TLS.clientHello(assembly.stream)
        for link in [PacketCapture.linkEthernet, PacketCapture.linkNull, PacketCapture.linkRaw] {
            guard let packet = Packet.parse(bytes, dlt: link) else { continue }
            _ = namer.endpointsUnknown(packet)
            _ = namer.hardwareSourceUnknown(packet)
            _ = namer.observe(packet, at: time)
        }
    }

    /// One to three changes of the kind a hostile or broken sender makes: a bit, a byte, a
    /// length field at its extremes, bytes cut, added or repeated.
    static func mutate(_ original: [UInt8], using generator: inout Generator) -> [UInt8] {
        var bytes = original
        for _ in 0..<Int.random(in: 1...3, using: &generator) {
            guard !bytes.isEmpty else { return bytes }
            let at = Int.random(in: 0..<bytes.count, using: &generator)
            switch Int.random(in: 0..<9, using: &generator) {
            case 0: bytes[at] ^= 1 << UInt8.random(in: 0..<8, using: &generator)
            case 1: bytes[at] = UInt8.random(in: 0...255, using: &generator)
            case 2: bytes[at] = [0x00, 0x7f, 0x80, 0xff, 0xc0, 0x3f].randomElement(using: &generator)!
            case 3:
                let field: [UInt8] = [[0xff, 0xff], [0x00, 0x00], [0x7f, 0xff], [0x00, 0x01], [0xc0, 0x0c]].randomElement(using: &generator)!
                bytes.replaceSubrange(at..<min(at + 2, bytes.count), with: field)
            case 4: bytes.removeSubrange(at...)
            case 5: bytes.removeSubrange(at..<min(bytes.count, at + Int.random(in: 1...40, using: &generator)))
            case 6: bytes.insert(contentsOf: (0..<Int.random(in: 1...40, using: &generator)).map { _ in UInt8.random(in: 0...255, using: &generator) }, at: at)
            case 7:
                let run = bytes[at..<min(bytes.count, at + Int.random(in: 1...64, using: &generator))]
                bytes.insert(contentsOf: run, at: at)
            default:
                let other = Int.random(in: 0..<bytes.count, using: &generator)
                bytes.swapAt(at, other)
            }
        }
        return bytes
    }

    func testEveryPrefixAndManyMutationsOfEachFixtureReturnFromEveryParser() {
        let seed = ProcessInfo.processInfo.environment["TATTLE_FUZZ_SEED"].flatMap { UInt64($0) } ?? Self.defaultSeed
        for (index, fixture) in Self.fixtures.enumerated() {
            let finished = SnifferParserTests.returns(within: 60) {
                var generator = Generator(state: seed &+ UInt64(index))
                var namer = FlowNamer(localAddresses: [IPAddress(bytes: Self.me), IPAddress(bytes: Self.me6)],
                                      resolvers: [IPAddress(bytes: Self.resolver)], hardwareAddress: Self.hardware)
                var time = 1_700_000_000.0
                for length in 0...fixture.bytes.count {
                    Self.parse(Array(fixture.bytes[..<length]), namer: &namer, at: time)
                }
                for round in 0..<Self.mutationsPerFixture {
                    time += 0.01
                    Self.parse(Self.mutate(fixture.bytes, using: &generator), namer: &namer, at: time)
                    if round % 100 == 0 { _ = namer.expire(now: time) }
                }
                _ = namer.endCapture()
            }
            XCTAssertTrue(finished, "a parser did not return on a prefix or a mutation of the \(fixture.name) fixture, seed \(seed)")
        }
    }

    /// An Initial's frames are read only after it decrypts, which no mutation of a sealed
    /// packet does: these are sealed after the change, as a sender would. Fewer than the
    /// rest, since each costs a key derivation.
    func testPrefixesAndMutationsOfAnInitialsFramesReturn() {
        let seed = ProcessInfo.processInfo.environment["TATTLE_FUZZ_SEED"].flatMap { UInt64($0) } ?? Self.defaultSeed
        let frames = SnifferParserTests.rfcCryptoFrame
        let finished = SnifferParserTests.returns(within: 60) {
            var generator = Generator(state: seed)
            var namer = FlowNamer(localAddresses: [IPAddress(bytes: Self.me)], resolvers: [IPAddress(bytes: Self.resolver)])
            let inputs = (0...frames.count).map { Array(frames[..<$0]) }
                + (0..<400).map { _ in Self.mutate(frames, using: &generator) }
            for (index, input) in inputs.enumerated() where input.count < 1100 {
                let sealed = SnifferParserTests.sealInitial(input)
                Self.parse(sealed, namer: &namer, at: 1_700_000_000 + Double(index))
                let datagram = Self.udp(from: UInt16(50000 + index % 1000), to: 443, sealed)
                Self.parse(Self.ipv4(from: Self.me, to: Self.remote, proto: 17, datagram), namer: &namer, at: 1_700_000_000 + Double(index))
            }
        }
        XCTAssertTrue(finished, "a parser did not return on a sealed prefix or mutation of the CRYPTO frame, seed \(seed)")
    }
}
