import CommonCrypto
import CryptoKit
import XCTest
@testable import tattle

/// The parsers moved from the spike (ADR-0001), checked against published fixtures:
/// RFC 9001 Appendix A.2's client Initial, whose ClientHello names example.com.
final class SnifferParserTests: XCTestCase {
    /// The protected Initial packet from RFC 9001 A.2, 1200 bytes.
    static let rfcInitial: [UInt8] = hex([
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c",
        "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
        "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89",
        "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
        "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
        "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
        "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7",
        "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
        "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7",
        "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
        "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf",
        "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
        "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2",
        "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
        "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
        "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
        "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07",
        "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
        "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d",
        "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
        "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723",
        "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
        "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd",
        "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
        "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
    ].joined())

    /// The CRYPTO frame it carries: frame header, then a 241-byte ClientHello.
    static let rfcCryptoFrame: [UInt8] = hex([
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113",
        "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005",
        "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1",
        "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100",
        "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806",
        "048000ffff",
    ].joined())

    static var rfcClientHello: [UInt8] { Array(rfcCryptoFrame.dropFirst(4)) }

    /// The smallest ClientHello that carries `sni` as its server name.
    static func clientHello(sni: [UInt8]) -> [UInt8] {
        let entry: [UInt8] = [0, UInt8(sni.count >> 8), UInt8(sni.count & 0xff)] + sni
        let list: [UInt8] = [UInt8(entry.count >> 8), UInt8(entry.count & 0xff)] + entry
        let ext: [UInt8] = [0, 0, UInt8(list.count >> 8), UInt8(list.count & 0xff)] + list
        let body: [UInt8] = [3, 3] + [UInt8](repeating: 0xab, count: 32) + [0, 0, 2, 0x13, 0x01, 1, 0]
            + [UInt8(ext.count >> 8), UInt8(ext.count & 0xff)] + ext
        return [1, 0, UInt8(body.count >> 8), UInt8(body.count & 0xff)] + body
    }

    /// Names a wire parser must refuse: each would reach row titles, history, rule keys and
    /// the LLM prompt as given.
    static let rejectedNames: [(String, [UInt8])] = [
        ("a newline", Array("example.com\r\nX-Injected: 1".utf8)),
        ("a NUL", Array("example.com".utf8) + [0] + Array("evil".utf8)),
        ("a bidi override", Array("\u{202E}moc.elpmaxe".utf8)),
        ("the empty string", []),
        ("only a dot", Array(".".utf8)),
        ("an empty label", Array("example..com".utf8)),
        ("a leading hyphen", Array("-example.com".utf8)),
        ("a trailing hyphen", Array("example-.com".utf8)),
        ("a space", Array("example .com".utf8)),
        ("a 64-byte label", Array((String(repeating: "a", count: 64) + ".com").utf8)),
        ("more than 253 bytes", Array(Array(repeating: String(repeating: "a", count: 63), count: 4).joined(separator: ".").utf8)),
        ("a port outside a Host header", Array("example.com:443".utf8)),
        ("an IPv4 address", Array("17.253.144.10".utf8)),
        ("a number", Array("297865738".utf8)),
        ("a last label that is a number", Array("example.10".utf8)),
        ("a hexadecimal last label", Array("17.253.144.0x0a".utf8)),
    ]

    static func hex(_ text: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            out.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    /// Seals `frames` into a client Initial as any sender can (RFC 9001 section 5), padded
    /// with PADDING frames to the 1200 bytes a client must send.
    static func sealInitial(_ frames: [UInt8], dcid: [UInt8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]) -> [UInt8] {
        func expand(_ secret: some ContiguousBytes, _ label: String, _ length: Int) -> SymmetricKey {
            let full = Array("tls13 \(label)".utf8)
            let info = [UInt8(length >> 8), UInt8(length & 0xff), UInt8(full.count)] + full + [0]
            return SymmetricKey(data: HKDF<SHA256>.expand(pseudoRandomKey: SymmetricKey(data: secret), info: info, outputByteCount: length))
        }
        let salt: [UInt8] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                             0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a]
        let initial = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: dcid), salt: salt)
        let client = expand(initial, "client in", 32)
        let key = expand(client, "quic key", 16)
        let iv = expand(client, "quic iv", 12).withUnsafeBytes { Array($0) }
        let hp = expand(client, "quic hp", 16).withUnsafeBytes { Array($0) }

        var header: [UInt8] = [0xc0, 0, 0, 0, 1, UInt8(dcid.count)] + dcid + [0, 0]
        let fixed = header.count + 2 + 1 + 16  // length field, one-byte packet number, tag
        let plaintext = frames + [UInt8](repeating: 0, count: max(0, QUIC.minimumInitialDatagram - fixed - frames.count))
        let length = 1 + plaintext.count + 16
        header += [0x40 | UInt8(length >> 8), UInt8(length & 0xff)]
        let pnOffset = header.count
        header.append(0)  // packet number 0, so the nonce is the iv
        let box = try! AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: iv), authenticating: header)
        var packet = header + Array(box.ciphertext) + Array(box.tag)

        let sample = Array(packet[(pnOffset + 4)..<(pnOffset + 20)])
        var mask = [UInt8](repeating: 0, count: 16)
        var moved = 0
        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                hp, hp.count, nil, sample, 16, &mask, 16, &moved)
        packet[0] ^= mask[0] & 0x0f
        packet[pnOffset] ^= mask[1]
        return packet
    }

    /// Runs `body` on another thread and says whether it returned within `seconds`: a parser
    /// that loops forever must fail the test, not hang the suite.
    static func returns(within seconds: TimeInterval = 5, _ body: @escaping @Sendable () -> Void) -> Bool {
        let done = DispatchSemaphore(value: 0)
        Thread { body(); done.signal() }.start()
        return done.wait(timeout: .now() + seconds) == .success
    }

    // MARK: QUIC

    func testASealedInitialOpensToTheFramesItWasGiven() throws {
        guard case .success(let initial) = QUIC.parseInitial(Self.sealInitial(Self.rfcCryptoFrame), at: 0) else {
            return XCTFail("a sealed Initial must decrypt")
        }
        XCTAssertEqual(initial.chunks.map(\.data), [Self.rfcClientHello])
    }

    /// A CRYPTO frame of length zero (`06 00 00`) is valid on the wire. The old reassembly
    /// never advanced past it and spun the capture thread forever.
    func testAnEmptyCryptoChunkDoesNotStallTheAssembly() {
        XCTAssertTrue(Self.returns {
            var assembly = QUICAssembly()
            assembly.add([QUIC.Chunk(offset: 0, data: [])])
            assembly.add([QUIC.Chunk(offset: 0, data: [1, 2, 3])])
            XCTAssertEqual(assembly.stream, [1, 2, 3], "the empty chunk is ignored, the real one kept")
        }, "the assembly returned")
    }

    /// Every chunk is checked against those held ahead of the stream, so thousands of one-byte
    /// chunks would make each later frame cost thousands of comparisons on the capture thread.
    func testQUICAssemblyHoldsAtMost32ChunksAheadOfTheStream() {
        var held = QUICAssembly()
        held.add((1...32).map { QUIC.Chunk(offset: UInt64($0), data: [1]) })
        XCTAssertFalse(held.overLimit, "32 ahead are allowed")
        var flooded = QUICAssembly()
        flooded.add((1...33).map { QUIC.Chunk(offset: UInt64($0), data: [1]) })
        XCTAssertTrue(flooded.overLimit, "the 33rd ends the assembly")
        flooded.add([QUIC.Chunk(offset: 0, data: [0])])
        XCTAssertEqual(flooded.stream, [], "and it stays ended")
    }

    func testQUICAssemblyRejectsOverlapsAndBytesPastTheCap() {
        var assembly = QUICAssembly()
        assembly.add([QUIC.Chunk(offset: 0, data: [0, 1, 2, 3])])
        assembly.add([QUIC.Chunk(offset: 2, data: [9, 9, 9, 9])])
        XCTAssertEqual(assembly.stream, [0, 1, 2, 3], "an overlap is dropped, not spliced in")
        XCTAssertFalse(assembly.overLimit)
        assembly.add([QUIC.Chunk(offset: UInt64(FlowNamer.bufferLimit) - 1, data: [7, 7])])
        XCTAssertTrue(assembly.overLimit, "a byte past the cap ends the assembly")
        XCTAssertEqual(assembly.stream, [], "and frees what it held")
    }

    func testRFC9001ClientInitialDecryptsToClientHello() throws {
        XCTAssertTrue(QUIC.mayBeClientInitial(Self.rfcInitial))
        guard case .success(let initial) = QUIC.parseInitial(Self.rfcInitial, at: 0) else {
            return XCTFail("the published Initial did not decrypt")
        }
        XCTAssertEqual(initial.nextOffset, 1200, "one packet fills the datagram")
        XCTAssertEqual(initial.chunks.count, 1)
        XCTAssertEqual(initial.chunks[0].offset, 0)
        XCTAssertEqual(initial.chunks[0].data, Self.rfcClientHello)

        var assembly = QUICAssembly()
        assembly.add(initial.chunks)
        guard case .hello(let sni) = TLS.clientHello(assembly.stream) else { return XCTFail("not a ClientHello") }
        XCTAssertEqual(sni, "example.com")
    }

    func testQUICFailures() {
        var wrongVersion = Self.rfcInitial
        wrongVersion[4] = 2
        guard case .failure(.unsupportedVersion) = QUIC.parseInitial(wrongVersion, at: 0) else { return XCTFail() }

        var corrupted = Self.rfcInitial
        corrupted[600] ^= 0xff
        guard case .failure(.decryptFailed) = QUIC.parseInitial(corrupted, at: 0) else { return XCTFail("a flipped byte must fail authentication") }

        let truncated = Array(Self.rfcInitial.prefix(100))
        guard case .failure(.malformed) = QUIC.parseInitial(truncated, at: 0) else { return XCTFail() }

        var shortHeader = Self.rfcInitial
        shortHeader[0] = 0x40
        XCTAssertFalse(QUIC.mayBeClientInitial(shortHeader))
        guard case .failure(.notInitial) = QUIC.parseInitial(shortHeader, at: 0) else { return XCTFail() }
    }

    func testQUICAssemblyOrdersChunksAndIgnoresDuplicates() {
        var assembly = QUICAssembly()
        assembly.add([QUIC.Chunk(offset: 3, data: [3, 4, 5])])
        XCTAssertEqual(assembly.stream, [], "nothing contiguous from zero yet")
        assembly.add([QUIC.Chunk(offset: 0, data: [0, 1, 2]), QUIC.Chunk(offset: 0, data: [9, 9, 9])])
        XCTAssertEqual(assembly.stream, [0, 1, 2, 3, 4, 5])
    }

    // MARK: TLS over TCP

    private func record(_ handshake: ArraySlice<UInt8>) -> [UInt8] {
        [0x16, 0x03, 0x01, UInt8(handshake.count >> 8), UInt8(handshake.count & 0xff)] + handshake
    }

    func testClientHelloSplitAcrossTwoSegments() {
        let stream = record(Self.rfcClientHello[...])
        let first = Array(stream.prefix(100))
        let second = Array(stream.dropFirst(100))

        guard case .needMore = TLS.clientHelloFromRecords(first) else { return XCTFail("a partial record needs more") }
        guard case .hello(let sni) = TLS.clientHelloFromRecords(first + second) else { return XCTFail() }
        XCTAssertEqual(sni, "example.com")
    }

    func testClientHelloSplitAcrossTwoRecords() {
        // Some clients fragment the handshake message over several records.
        let hello = Self.rfcClientHello
        let stream = record(hello[..<50]) + record(hello[50...])
        guard case .hello(let sni) = TLS.clientHelloFromRecords(stream) else { return XCTFail() }
        XCTAssertEqual(sni, "example.com")
    }

    /// The name is read from inside the extensions block, whatever length the extension claims.
    func testAServerNamePastTheExtensionsBlockIsNotRead() {
        let name = Array("evil.example".utf8)
        let entry: [UInt8] = [0, 0, UInt8(name.count)] + name
        let list: [UInt8] = [0, UInt8(entry.count)] + entry
        let ext: [UInt8] = [0, 0, 0, UInt8(list.count)] + list
        func hello(extensionsLength: Int) -> [UInt8] {
            let body: [UInt8] = [3, 3] + [UInt8](repeating: 0xab, count: 32) + [0, 0, 2, 0x13, 0x01, 1, 0] + [0, UInt8(extensionsLength)] + ext
            return [1, 0, 0, UInt8(body.count)] + body
        }
        guard case .hello(let whole) = TLS.clientHello(hello(extensionsLength: ext.count)),
              case .hello(let cut) = TLS.clientHello(hello(extensionsLength: 4)) else { return XCTFail("both are ClientHellos") }
        XCTAssertEqual(whole, "evil.example")
        XCTAssertNil(cut, "the block ends after the extension's header")
    }

    func testNotTLS() {
        guard case .notClientHello = TLS.clientHelloFromRecords(Array("GET / HTTP/1.1\r\n".utf8)) else { return XCTFail() }
        guard case .needMore = TLS.clientHelloFromRecords([]) else { return XCTFail() }
        // A ServerHello-shaped handshake message is not a ClientHello.
        guard case .notClientHello = TLS.clientHello([2, 0, 0, 0]) else { return XCTFail() }
    }

    func testServerNamesAreValidatedAndNormalized() {
        for (shape, name) in Self.rejectedNames {
            guard case .hello(let sni) = TLS.clientHello(Self.clientHello(sni: name)) else { return XCTFail(shape) }
            XCTAssertNil(sni, "an SNI with \(shape) is no name")
        }
        guard case .hello(let sni) = TLS.clientHello(Self.clientHello(sni: Array("Example.COM.".utf8))) else { return XCTFail() }
        XCTAssertEqual(sni, "example.com", "lowercased, trailing dot dropped")
        let longest = Array(repeating: String(repeating: "a", count: 63), count: 3).joined(separator: ".") + "." + String(repeating: "b", count: 61)
        guard case .hello(let edge) = TLS.clientHello(Self.clientHello(sni: Array(longest.utf8))) else { return XCTFail() }
        XCTAssertEqual(edge, longest, "63-byte labels and 253 bytes in all are allowed")
        guard case .hello(let underscore) = TLS.clientHello(Self.clientHello(sni: Array("_dmarc.x-1.example".utf8))) else { return XCTFail() }
        XCTAssertEqual(underscore, "_dmarc.x-1.example")
        // Only the last label decides whether a name reads as an address.
        for name in ["10.example", "4.3.2.1.in-addr.arpa", "example.1a", "example.0xg", "x0x10"] {
            XCTAssertEqual(HostName(Array(name.utf8))?.text, name, "\(name) is a host name")
        }
    }

    func testHTTPHost() {
        XCTAssertEqual(HTTP.request(Array("GET /x HTTP/1.1\r\nHost: example.org\r\nAccept: */*\r\n\r\n".utf8)[...])?.host, "example.org")
        XCTAssertEqual(HTTP.request(Array("POST / HTTP/1.1\r\nhost:  api.example.org:8080 \r\n\r\n".utf8)[...])?.host, "api.example.org", "the port is not part of the name")
        let late = HTTP.request(Array("GET / HTTP/1.1\r\n\r\nHost: late.example\r\n".utf8)[...])
        XCTAssertNotNil(late, "a request")
        XCTAssertNil(late?.host, "headers end at the blank line")
        XCTAssertNil(HTTP.request(Array("SSH-2.0-OpenSSH\r\n".utf8)[...]))
        let address = HTTP.request(Array("GET / HTTP/1.1\r\nHost: 17.253.144.10:8080\r\n\r\n".utf8)[...])
        XCTAssertNotNil(address, "a request")
        XCTAssertNil(address?.host, "an address is not a name, with a port or without")
    }

    // MARK: DNS

    /// A reply for www.example.com: a CNAME to example.com, then its A record, with the
    /// answer names as RFC 1035 pointers back into the question.
    private static let compressedReply: [UInt8] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        3, 0x77, 0x77, 0x77, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x63, 0x6f, 0x6d, 0,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x02, 0xc0, 0x10,
        0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34,
    ]

    func testDNSReplyWithCompression() {
        let reply = DNS.parseReply(Self.compressedReply[...])
        XCTAssertEqual(reply?.name, "www.example.com", "the name the application asked for")
        XCTAssertEqual(reply?.addresses.map(\.text), ["93.184.216.34"])
    }

    func testDNSReplyWithAAAA() {
        var bytes = Self.compressedReply
        bytes[7] = 1  // one answer
        bytes.removeSubrange(33..<47)  // drop the CNAME
        bytes[34] = 0x0c  // so the record is the question name's, not the dropped alias's
        bytes[bytes.count - 13] = 28  // type AAAA
        bytes[bytes.count - 5] = 16
        bytes.removeLast(4)
        bytes += [0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]
        XCTAssertEqual(DNS.parseReply(bytes[...])?.addresses.map(\.text), ["2606:2800:220:1:248:1893:25c8:1946"])
    }

    /// DNS labels are length-prefixed, so one can hold a dot or any byte at all.
    func testDNSNamesAreValidatedAndNormalized() {
        var dotted = Self.compressedReply
        dotted[14] = 0x2e  // "www" becomes "w.w" inside one label
        XCTAssertNil(DNS.parseReply(dotted[...]), "a label containing a dot")
        var newline = Self.compressedReply
        newline[15] = 0x0a
        XCTAssertNil(DNS.parseReply(newline[...]), "a label containing a newline")
        var upper = Self.compressedReply
        upper[13] = 0x57  // "Www"
        XCTAssertEqual(DNS.parseReply(upper[...])?.name, "www.example.com")
    }

    func testDNSKeepsOnlyAddressesOwnedByTheQuestionsChain() {
        var appended = Self.compressedReply
        appended[7] = 3
        appended += [1, 0x78, 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 17, 253, 144, 10]  // "x" A 17.253.144.10
        XCTAssertEqual(DNS.parseReply(appended[...])?.addresses.map(\.text), ["93.184.216.34"], "x is not www.example.com or its CNAME target")
    }

    /// A CNAME's target is read inside its RDATA: with RDLENGTH 0 the next record's owner, "x",
    /// was read as the alias, and x's address joined the question's.
    func testDNSReadsACNAMETargetOnlyInsideItsRecord() {
        var reply = Array(Self.compressedReply.prefix(33))
        reply[7] = 2
        reply += [0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00]  // CNAME, RDLENGTH 0
        reply += [1, 0x78, 0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 17, 253, 144, 10]  // "x" A 17.253.144.10
        let parsed = DNS.parseReply(reply[...])
        XCTAssertEqual(parsed?.name, "www.example.com")
        XCTAssertEqual(parsed?.addresses, [])
    }

    /// A CNAME whose name runs past its RDATA drops only that alias: the question and its own
    /// records still parse, as they did before the alias was bounded.
    func testDNSDropsOnlyACNAMEThatRunsPastItsRecord() {
        var reply = Array(Self.compressedReply.prefix(33))
        reply[7] = 2
        reply += [0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00]  // CNAME, RDLENGTH 0
        reply += [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34]  // its own A
        let parsed = DNS.parseReply(reply[...])
        XCTAssertEqual(parsed?.name, "www.example.com")
        XCTAssertEqual(parsed?.addresses.map(\.text), ["93.184.216.34"])
    }

    func testDNSIgnoresQueriesAndPointerLoops() {
        var query = Self.compressedReply
        query[2] = 0x01  // QR bit clear
        XCTAssertNil(DNS.parseReply(query[...]))

        var loop = Self.compressedReply
        loop[12] = 0xc0
        loop[13] = 0x0c  // the question name points at itself
        XCTAssertNil(DNS.parseReply(loop[...]))
    }

    private enum Record {
        case address(String, [UInt8])
        case alias(String, String)
    }

    /// A reply compressed as servers compress them (RFC 1035 4.1.4): a name whose suffix is
    /// already in the message ends in a pointer to it.
    private static func dnsReply(questions: [String], answers: [Record]) -> [UInt8] {
        var bytes: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, UInt8(questions.count), UInt8(answers.count >> 8), UInt8(answers.count & 0xff), 0, 0, 0, 0]
        var offsets: [String: Int] = [:]
        func name(_ text: String) {
            let labels = text.split(separator: ".")
            for i in labels.indices {
                let suffix = labels[i...].joined(separator: ".")
                if let at = offsets[suffix] {
                    bytes += [0xc0 | UInt8(at >> 8), UInt8(at & 0xff)]
                    return
                }
                offsets[suffix] = bytes.count
                bytes += [UInt8(labels[i].utf8.count)] + Array(labels[i].utf8)
            }
            bytes.append(0)
        }
        for question in questions {
            name(question)
            bytes += [0, 1, 0, 1]
        }
        for record in answers {
            switch record {
            case let .address(owner, address):
                name(owner)
                bytes += [0, address.count == 4 ? 1 : 28, 0, 1, 0, 0, 0x0e, 0x10, 0, UInt8(address.count)] + address
            case let .alias(owner, target):
                name(owner)
                bytes += [0, 5, 0, 1, 0, 0, 0x0e, 0x10, 0, 0]
                let start = bytes.count
                name(target)
                bytes[start - 2] = UInt8((bytes.count - start) >> 8)
                bytes[start - 1] = UInt8((bytes.count - start) & 0xff)
            }
        }
        return bytes
    }

    func testDNSRefusesAReplyWithMoreThanOneQuestion() {
        let answer = Record.address("www.example.com", [192, 0, 2, 1])
        let one = Self.dnsReply(questions: ["www.example.com"], answers: [answer])
        XCTAssertEqual(DNS.parseReply(one[...])?.addresses.map(\.text), ["192.0.2.1"])
        let two = Self.dnsReply(questions: ["www.example.com", "example.com"], answers: [answer])
        XCTAssertNil(DNS.parseReply(two[...]))
    }

    /// RFC 1035 caps a name at 255 bytes on the wire, its length bytes and the root's zero
    /// included: 253 as text, HostName's limit. A walk past it stops there, which leaves the
    /// reader inside the name, so the whole reply is refused.
    func testDNSRefusesANameLongerThan255Bytes() {
        let a63 = String(repeating: "a", count: 63)
        let longest = [a63, a63, a63, String(repeating: "b", count: 61)].joined(separator: ".")
        let tooLong = [a63, a63, a63, String(repeating: "b", count: 62)].joined(separator: ".")
        let atLimit = Self.dnsReply(questions: [longest], answers: [.address(longest, [192, 0, 2, 1])])
        XCTAssertEqual(DNS.parseReply(atLimit[...])?.addresses.map(\.text), ["192.0.2.1"], "255 bytes")
        let past = Self.dnsReply(questions: ["www.example.com"], answers: [
            .address("www.example.com", [192, 0, 2, 1]), .address(tooLong, [192, 0, 2, 2]),
        ])
        XCTAssertNil(DNS.parseReply(past[...]), "256 bytes")
    }

    /// One question for "a", then `count` records whose owners, or whose CNAME targets, point
    /// at one run of 127 one-letter labels: 255 bytes, the most a name may be.
    private static func fanOut(_ count: Int, aliases: Bool) -> [UInt8] {
        let run = 12 + 7 + count * (aliases ? 14 : 12)
        let pointer: [UInt8] = [0xc0 | UInt8(run >> 8), UInt8(run & 0xff)]
        var bytes: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, UInt8(count >> 8), UInt8(count & 0xff), 0, 0, 0, 0, 1, 0x61, 0, 0, 1, 0, 1]
        for _ in 0..<count {
            bytes += aliases
                ? [0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0x0e, 0x10, 0, 2] + pointer  // a CNAME <run>
                : pointer + [0, 16, 0, 1, 0, 0, 0x0e, 0x10, 0, 0]  // <run> TXT, empty
        }
        return bytes + (0..<127).flatMap { _ in [UInt8(1), 0x61] } + [0]
    }

    /// Compression lets every name point into one run of labels, so names that are each
    /// valid can still make one reply walk thousands of labels. These fill 1,472 bytes, the
    /// most a 1,500-byte packet carries: 99 owners or 85 CNAME targets of 127 labels each.
    func testDNSRefusesAReplyThatWalksTooManyLabels() {
        let owners = Self.fanOut(99, aliases: false)
        XCTAssertLessThanOrEqual(owners.count, 1472)
        XCTAssertNil(DNS.parseReply(owners[...]), "owners")
        let targets = Self.fanOut(85, aliases: true)
        XCTAssertLessThanOrEqual(targets.count, 1472)
        XCTAssertNil(DNS.parseReply(targets[...]), "CNAME targets")
    }

    /// Replies as large as real ones still parse whole: a CNAME chain through a CDN, and as
    /// many A or AAAA records for a six-label name as the capture holds (its 2,048-byte snap
    /// length leaves 2,006 bytes for the reply).
    func testDNSReadsFullRepliesWithCompressedNames() {
        let chain = Self.dnsReply(questions: ["www.shop.example"], answers: [
            .alias("www.shop.example", "www.shop.example.edgekey.net"),
            .alias("www.shop.example.edgekey.net", "www.shop.example.edgekey.net.globalredir.akadns.net"),
            .alias("www.shop.example.edgekey.net.globalredir.akadns.net", "e6858.dsce9.akamaiedge.net"),
            .address("e6858.dsce9.akamaiedge.net", [192, 0, 2, 10]),
            .address("e6858.dsce9.akamaiedge.net", [192, 0, 2, 11]),
        ])
        XCTAssertEqual(DNS.parseReply(chain[...])?.addresses.map(\.text), ["192.0.2.10", "192.0.2.11"])

        let pool = "pool-7.lb.us-east-1.edge.example.net"
        let a = Self.dnsReply(questions: [pool], answers: (0..<122).map { .address(pool, [198, 51, 100, UInt8($0)]) })
        XCTAssertEqual(a.count, 2006)
        XCTAssertEqual(DNS.parseReply(a[...])?.addresses.count, 122)
        let aaaa = Self.dnsReply(questions: [pool], answers: (0..<69).map {
            .address(pool, [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [UInt8($0)])
        })
        XCTAssertLessThanOrEqual(aaaa.count, 2006)
        XCTAssertEqual(DNS.parseReply(aaaa[...])?.addresses.count, 69)
    }

    // MARK: Packets

    func testParsesIPv4UDPOverEthernet() {
        let payload: [UInt8] = [0xc0, 1, 2, 3]
        let udp: [UInt8] = [0xd4, 0x31, 0x01, 0xbb, 0x00, UInt8(8 + payload.count), 0, 0] + payload
        let total = 20 + udp.count
        let ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0x40, 0, 64, 17, 0, 0,
                           192, 168, 1, 5, 17, 253, 144, 10] + udp
        let frame = [UInt8](repeating: 0xaa, count: 12) + [0x08, 0x00] + ip
        let packet = Packet.parse(frame, dlt: PacketCapture.linkEthernet)
        XCTAssertEqual(packet?.proto, .udp)
        XCTAssertEqual(packet?.src.text, "192.168.1.5")
        XCTAssertEqual(packet?.dst.text, "17.253.144.10")
        XCTAssertEqual(packet?.srcPort, 54321)
        XCTAssertEqual(packet?.dstPort, 443)
        XCTAssertEqual(packet.map { Array($0.payload) }, payload)
        XCTAssertNil(Packet.parse(frame, dlt: 99), "unknown link type")
    }

    /// A capture cut at the snap length keeps the header's lengths: the payload is what was
    /// captured, and the rest is counted, so a stream position stays right.
    func testCountsPayloadCutOffByTheSnapLength() {
        let tcp: [UInt8] = [0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]
        let captured = [UInt8](repeating: 0x16, count: 100)
        let total = 20 + tcp.count + 3000
        let ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0x40, 0, 64, 6, 0, 0,
                           192, 168, 1, 5, 17, 253, 144, 10] + tcp + captured
        let packet = Packet.parse([UInt8](repeating: 0xaa, count: 12) + [0x08, 0x00] + ip, dlt: PacketCapture.linkEthernet)
        XCTAssertEqual(packet?.payload.count, 100)
        XCTAssertEqual(packet?.uncaptured, 2900)

        var v6: [UInt8] = [0x60, 0, 0, 0, UInt8((tcp.count + 3000) >> 8), UInt8((tcp.count + 3000) & 0xff), 6, 64]
        v6 += [UInt8](repeating: 0x20, count: 32)
        XCTAssertEqual(Packet.parse([30, 0, 0, 0] + v6 + tcp + captured, dlt: PacketCapture.linkNull)?.uncaptured, 2900)
    }

    func testRefusesAHeaderLengthShorterThanTheHeader() {
        func frame(headerWords: UInt8, dataOffsetWords: UInt8) -> [UInt8] {
            let tcp: [UInt8] = [0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, dataOffsetWords << 4, 0x18, 0xff, 0xff, 0, 0, 0, 0, 0x16, 0x03]
            let total = 20 + tcp.count
            let ip: [UInt8] = [0x40 | headerWords, 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, 0x40, 0, 64, 6, 0, 0,
                               192, 168, 1, 5, 17, 253, 144, 10] + tcp
            return [UInt8](repeating: 0xaa, count: 12) + [0x08, 0x00] + ip
        }
        XCTAssertEqual(Packet.parse(frame(headerWords: 5, dataOffsetWords: 5), dlt: PacketCapture.linkEthernet)?.payload.count, 2)
        XCTAssertNil(Packet.parse(frame(headerWords: 2, dataOffsetWords: 5), dlt: PacketCapture.linkEthernet), "an IPv4 header of 8 bytes")
        XCTAssertNil(Packet.parse(frame(headerWords: 5, dataOffsetWords: 2), dlt: PacketCapture.linkEthernet), "a TCP header of 8 bytes")
    }

    func testParsesIPv6TCPOverNullLink() {
        let tcp: [UInt8] = [0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]
        var ip: [UInt8] = [0x60, 0, 0, 0, 0, UInt8(tcp.count), 6, 64]
        ip += [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [1]
        ip += [0x26, 0x06, 0x47, 0x00] + [UInt8](repeating: 0, count: 10) + [0x11, 0x11]
        let frame: [UInt8] = [30, 0, 0, 0] + ip + tcp
        let packet = Packet.parse(frame, dlt: PacketCapture.linkNull)
        XCTAssertEqual(packet?.proto, .tcp)
        XCTAssertEqual(packet?.src.text, "2001:db8::1")
        XCTAssertEqual(packet?.dst.text, "2606:4700::1111")
        XCTAssertEqual(packet?.tcpFlags, 0x02)
        XCTAssertEqual(packet?.tcpSeq, 1)
        XCTAssertEqual(packet?.payload.count, 0)
    }

    func testAddressFromText() {
        XCTAssertEqual(IPAddress(text: "192.168.1.1")?.bytes, [192, 168, 1, 1])
        XCTAssertEqual(IPAddress(text: "fe80::1%en0")?.text, "fe80::1", "a resolver's zone is dropped")
        XCTAssertNil(IPAddress(text: "resolver.example"))
    }

    func testLocalScope() {
        XCTAssertTrue(IPAddress(bytes: [10, 0, 0, 1]).isLocalScope)
        XCTAssertTrue(IPAddress(bytes: [224, 0, 0, 251]).isLocalScope)
        XCTAssertFalse(IPAddress(bytes: [17, 253, 144, 10]).isLocalScope)
        XCTAssertFalse(IPAddress(bytes: [100, 64, 0, 1]).isLocalScope, "a Tailscale peer can still be named")
        XCTAssertTrue(IPAddress(bytes: [0xfe, 0x80] + [UInt8](repeating: 0, count: 13) + [1]).isLocalScope)
        XCTAssertTrue(IPAddress(bytes: [UInt8](repeating: 0, count: 15) + [1]).isLocalScope)
        XCTAssertFalse(IPAddress(bytes: [0x26, 0x06] + [UInt8](repeating: 0, count: 14)).isLocalScope)
    }
}
