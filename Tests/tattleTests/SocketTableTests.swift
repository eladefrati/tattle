import XCTest
@testable import tattle

final class SocketTableTests: XCTestCase {
    /// The kind is unsigned: one of 2^31 or more is a kind the parser does not know, not a trap.
    func testARecordKindPastInt32IsSkipped() {
        var bytes = [UInt8](repeating: 0, count: 24 + 64)
        func put(_ value: UInt32, at offset: Int) {
            withUnsafeBytes(of: value.littleEndian) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
        }
        put(24, at: 0)  // tattle_xinpgen.xig_len
        put(64, at: 24)  // tattle_xgen_n.xgn_len
        put(0x8000_0000, at: 28)  // tattle_xgen_n.xgn_kind
        let entries = bytes.withUnsafeBytes { SocketTable.parse($0, proto: .tcp) }
        XCTAssertTrue(entries.isEmpty)
    }

    /// macOS 27 answers an ordinary process with the count and no records.
    func testATableWithACountAndNoRecordsIsWithheld() {
        func table(count: UInt32, records: Int) -> [UInt8] {
            var bytes = [UInt8](repeating: 0, count: 24 + records + 24)
            func put(_ value: UInt32, at offset: Int) {
                withUnsafeBytes(of: value.littleEndian) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
            }
            put(24, at: 0)  // tattle_xinpgen.xig_len
            put(count, at: 4)  // tattle_xinpgen.xig_count
            put(24, at: 24 + records)  // the trailing tattle_xinpgen
            put(count, at: 24 + records + 4)
            return bytes
        }
        XCTAssertTrue(table(count: 270, records: 0).withUnsafeBytes { SocketTable.isWithheld($0) })
        XCTAssertFalse(table(count: 0, records: 0).withUnsafeBytes { SocketTable.isWithheld($0) }, "no sockets is not withheld")
        XCTAssertFalse(table(count: 1, records: 64).withUnsafeBytes { SocketTable.isWithheld($0) })
        XCTAssertFalse([UInt8]().withUnsafeBytes { SocketTable.isWithheld($0) })
    }

    /// A parent and the child it forked both hold the socket; the table names one process.
    func testASocketSeveralProcessesHoldIsOneEntryUnderTheOldest() {
        func held(socket: UInt64, pid: Int32, started: UInt64, port: UInt16) -> ProcessSockets.Held {
            ProcessSockets.Held(socket: socket, started: started, entry: SocketEntry(
                proto: .tcp, isIPv6: false, localAddress: "0.0.0.0", localPort: port, remoteAddress: "0.0.0.0", remotePort: 0,
                tcpState: SocketEntry.tcpListen, pid: pid, effectivePid: pid, uid: 501))
        }
        let entries = ProcessSockets.merge([
            held(socket: 1, pid: 300, started: 20, port: 8080),
            held(socket: 1, pid: 200, started: 10, port: 8080),
            held(socket: 1, pid: 200, started: 10, port: 8080),  // the same socket on a second descriptor
            held(socket: 2, pid: 300, started: 20, port: 9090),
        ])
        XCTAssertEqual(entries.map(\.pid), [200, 300])
        XCTAssertEqual(entries.map(\.localPort), [8080, 9090])
    }

    func testProcessesGiveTheirOwnSockets() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, length) }
        }, 0)
        XCTAssertEqual(Darwin.listen(fd, 1), 0)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }, 0)
        let port = UInt16(bigEndian: address.sin_port)
        let entry = try XCTUnwrap(ProcessSockets.read().first { $0.proto == .tcp && $0.localPort == port })
        XCTAssertEqual(entry.pid, getpid())
        XCTAssertEqual(entry.uid, getuid())
        XCTAssertEqual(entry.localAddress, "127.0.0.1")
        XCTAssertTrue(entry.isListening)
        XCTAssertFalse(entry.isIPv6)
    }

    func testTablesParseAndMatchLsof() throws {
        let entries = try SocketTable.read()
        XCTAssertFalse(entries.isEmpty)
        let listeners = entries.filter(\.isListening)
        XCTAssertFalse(listeners.filter { $0.proto == .tcp }.isEmpty, "something always listens on TCP")
        XCTAssertFalse(listeners.filter { $0.proto == .udp }.isEmpty, "mDNS always listens on UDP")
        XCTAssertTrue(entries.allSatisfy { $0.pid >= 0 })
        for entry in listeners where entry.proto == .tcp {
            XCTAssertEqual(entry.remotePort, 0, "a TCP listener has no peer")
        }

        // Cross-check with lsof for this user's processes: every TCP listener lsof sees
        // must be in the table with the same pid.
        let lsof = try run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpn"])
        var pid: Int32 = 0
        var expected: [(pid: Int32, port: UInt16)] = []
        for line in lsof.split(separator: "\n") {
            if line.hasPrefix("p") { pid = Int32(line.dropFirst()) ?? 0 }
            if line.hasPrefix("n"), let port = line.split(separator: ":").last.flatMap({ UInt16($0) }) {
                expected.append((pid, port))
            }
        }
        guard !expected.isEmpty else { throw XCTSkip("lsof sees no TCP listener of this user") }
        for (pid, port) in expected {
            XCTAssertTrue(listeners.contains { $0.proto == .tcp && $0.localPort == port && $0.pid == pid },
                          "lsof sees pid \(pid) listening on \(port)")
        }
    }

    /// The kernel marks a dual-stack listener with both families.
    func testTheTableTellsWhichFamiliesAListenerTakes() throws {
        func listener(family: Int32, v6Only: Bool?) throws -> (fd: Int32, port: UInt16) {
            let fd = socket(family, SOCK_STREAM, 0)
            XCTAssertGreaterThanOrEqual(fd, 0)
            if let v6Only {
                var value: Int32 = v6Only ? 1 : 0
                XCTAssertEqual(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, socklen_t(MemoryLayout<Int32>.size)), 0)
            }
            var storage = sockaddr_storage()
            storage.ss_family = sa_family_t(family)
            storage.ss_len = UInt8(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            var length = socklen_t(storage.ss_len)
            let bound = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, length) }
            }
            XCTAssertEqual(bound, 0, String(cString: strerror(errno)))
            XCTAssertEqual(Darwin.listen(fd, 1), 0)
            let named = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
            }
            XCTAssertEqual(named, 0)
            let port = family == AF_INET
                ? withUnsafePointer(to: &storage) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_port } }
                : withUnsafePointer(to: &storage) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_port } }
            return (fd, UInt16(bigEndian: port))
        }
        let v4 = try listener(family: AF_INET, v6Only: nil)
        let v6 = try listener(family: AF_INET6, v6Only: true)
        let dual = try listener(family: AF_INET6, v6Only: false)
        defer { [v4, v6, dual].forEach { close($0.fd) } }
        let table = try SocketTable.read().filter { $0.proto == .tcp && $0.isListening }
        func entry(_ port: UInt16) throws -> SocketEntry { try XCTUnwrap(table.first { $0.localPort == port }) }
        XCTAssertEqual(try [entry(v4.port).acceptsIPv4, entry(v4.port).acceptsIPv6], [true, false])
        XCTAssertEqual(try [entry(v6.port).acceptsIPv4, entry(v6.port).acceptsIPv6], [false, true])
        XCTAssertEqual(try [entry(dual.port).acceptsIPv4, entry(dual.port).acceptsIPv6], [true, true])
    }

    private func run(_ path: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        // A file, not a pipe: the wait below is bounded, and output larger than a pipe's
        // buffer would hold the process until it is read.
        let output = FileManager.default.temporaryDirectory.appending(path: "socket-table-\(getpid())-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: output.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: output) }
        process.standardOutput = try FileHandle(forWritingTo: output)
        process.standardError = FileHandle.nullDevice
        try process.run()
        waitForExit(process)
        return String(decoding: try Data(contentsOf: output), as: UTF8.self)
    }
}
