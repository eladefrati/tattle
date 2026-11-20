import XCTest
@testable import tattle

final class PortsSnapshotTests: XCTestCase {
    private func entry(_ proto: SocketEntry.Proto, _ local: String, _ port: UInt16, pid: Int32, v6: Bool = false,
                       state: Int32? = nil, remotePort: UInt16 = 0, uid: UInt32 = 501) -> SocketEntry {
        SocketEntry(proto: proto, isIPv6: v6, localAddress: local, localPort: port, remoteAddress: v6 ? "::" : "0.0.0.0",
                    remotePort: remotePort, tcpState: proto == .tcp ? (state ?? SocketEntry.tcpListen) : nil,
                    pid: pid, effectivePid: 0, uid: uid)
    }

    /// A process as the table lists it: named without its signature.
    private func process(_ pid: Int32, _ path: String, arguments: [String]? = nil, uid: UInt32 = 501) -> ProcessEntry {
        ProcessEntry(pid: pid, parentPid: 1, uid: uid, name: URL(fileURLWithPath: path).lastPathComponent, path: path, arguments: arguments, started: .distantPast)
    }

    private let services = ServiceNames.parse("""
        # comment
        ssh              22/udp     # SSH Remote Login Protocol
        ssh              22/tcp     # SSH Remote Login Protocol
        commplex-main  5000/tcp
        afs3-fileserver 7000/tcp   bbs
        """)

    func testGroupsMergesFamiliesAndIgnoresConnections() {
        let entries = [
            entry(.tcp, "0.0.0.0", 5000, pid: 634),
            entry(.tcp, "::", 5000, pid: 634, v6: true),
            entry(.tcp, "127.0.0.1", 8021, pid: 99, uid: 0),
            entry(.tcp, "192.168.1.5", 22, pid: 7, uid: 0),
            entry(.tcp, "192.168.1.5", 61000, pid: 1, state: SocketEntry.tcpEstablished, remotePort: 443),
            entry(.udp, "0.0.0.0", 5353, pid: 300),
            entry(.udp, "0.0.0.0", 60000, pid: 300),
            entry(.udp, "0.0.0.0", 0, pid: 300),
        ]
        let snapshot = PortsSnapshot.build(entries: entries, services: services, processes: { pid in
            pid == 634 ? self.process(634, "/System/ControlCenter") : nil
        }, signature: { _ in CodeSignature(signer: .apple) })

        XCTAssertEqual(snapshot.items.count, 5)
        let network = snapshot.items(in: .network)
        XCTAssertEqual(network.map(\.port), [22, 5000, 5353])
        XCTAssertEqual(network[1].families, "IPv4 and IPv6")
        XCTAssertEqual(network[1].processName, "ControlCenter")
        XCTAssertEqual(network[1].signature?.signer, .apple)
        XCTAssertEqual(network[1].serviceName, "commplex-main")
        XCTAssertEqual(network[1].explainKey, "ControlCenter:tcp/5000")
        XCTAssertEqual(network[0].binding, .address("192.168.1.5"))
        XCTAssertEqual(network[0].processName, "pid 7", "unknown process keeps the pid")
        XCTAssertNil(network[0].signature)
        XCTAssertEqual(network[0].facts.first { $0.name == "Runs as" }?.value, "root")

        XCTAssertEqual(snapshot.items(in: .local).map(\.port), [8021])
        XCTAssertEqual(snapshot.items(in: .local)[0].binding, .loopback)
        XCTAssertEqual(snapshot.items(in: .ephemeral).map(\.port), [60000])
    }

    func testAListenerOnMappedLoopbackIsNotReachableFromTheNetwork() {
        XCTAssertTrue(entry(.tcp, "::ffff:127.0.0.1", 8021, pid: 1, v6: true).isLoopback)
        XCTAssertFalse(entry(.tcp, "::ffff:192.168.1.5", 8021, pid: 1, v6: true).isLoopback)
    }

    func testPortFactsKeepTheLoginAndCertificateNameOutOfTheirPromptValues() throws {
        let snapshot = PortsSnapshot.build(
            entries: [entry(.tcp, "0.0.0.0", 5000, pid: 634, uid: getuid())], services: services,
            processes: { _ in self.process(634, "/x/Mine", uid: getuid()) },
            signature: { _ in CodeSignature(signer: .development, teamIdentifier: "ABCDE12345") })
        assertPromptValues(try XCTUnwrap(snapshot.items.first).facts, runsAs: true)
    }

    /// A socket bound to this Mac's own public address would send that address: the panel
    /// shows it, the model is told only that it is public.
    func testABoundPublicAddressStaysOutOfThePrompt() throws {
        func boundTo(_ address: String, v6: Bool) throws -> Fact? {
            let snapshot = PortsSnapshot.build(
                entries: [entry(.tcp, address, 5000, pid: 634, v6: v6)], services: services,
                processes: { _ in self.process(634, "/x/Mine") }, signature: { _ in nil })
            return try XCTUnwrap(snapshot.items.first).facts.first { $0.name == "Bound to" }
        }
        let global = try XCTUnwrap(try boundTo("2a03:2880:f12f::1", v6: true))
        XCTAssertEqual(global.value, "2a03:2880:f12f::1 (IPv6)")
        XCTAssertEqual(global.promptValue, "<public-ip> (IPv6)")
        let v4 = try XCTUnwrap(try boundTo("17.253.144.10", v6: false))
        XCTAssertEqual(v4.promptValue, "<public-ip> (IPv4)")
        XCTAssertNil(try boundTo("192.168.1.5", v6: false)?.promptValue, "the redaction already replaces a private address")
        XCTAssertNil(try boundTo("0.0.0.0", v6: false)?.promptValue)
    }

    /// A listener that set itself a title: the panel shows it whole, and the key and the
    /// `Process` fact a prompt carries name the program.
    func testATitledListenerGoesOutAndIsKeptAsItsProgram() throws {
        let title = "postgres: appuser payroll_prod db01.corp.example.com(54321) idle"
        let snapshot = PortsSnapshot.build(
            entries: [entry(.tcp, "127.0.0.1", 5432, pid: 700)], services: .empty,
            processes: { _ in self.process(700, "/opt/pg/bin/postgres", arguments: [title, ""]) }, signature: { _ in nil })
        let item = try XCTUnwrap(snapshot.items.first)
        XCTAssertEqual(item.processName, title, "the row keeps the title")
        XCTAssertEqual(item.explainKey, "postgres:tcp/5432")
        XCTAssertEqual(item.facts.first { $0.name == "Process" }?.value, "\(title) (pid 700)")
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .port, key: item.explainKey, facts: item.facts), redactor: .addressesOnly)
        for word in ["appuser", "payroll_prod", "db01", "idle"] { XCTAssertFalse(sent.contains(word), sent) }
        XCTAssertTrue(sent.contains(#"{"name":"Process","value":"postgres (pid 700)"}"#), sent)
    }

    /// A listener's path is known whole, so it is sent without the folders under the home.
    func testAListenersPathGoesOutWithoutItsFolders() throws {
        let snapshot = PortsSnapshot.build(
            entries: [entry(.tcp, "127.0.0.1", 8080, pid: 700)], services: .empty,
            processes: { _ in self.process(700, "/Users/username/Clients/Acme Corp/bin/server") }, signature: { _ in nil })
        let item = try XCTUnwrap(snapshot.items.first)
        XCTAssertEqual(item.facts.first { $0.name == "Path" }?.value, "/Users/username/Clients/Acme Corp/bin/server", "the panel shows it whole")
        let redactor = Redactor(home: "/Users/username", username: "username", machineNames: [])
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .port, key: item.explainKey, facts: item.facts), redactor: redactor)
        XCTAssertFalse(sent.contains("Acme"), sent)
        XCTAssertTrue(sent.contains(#"{"name":"Path","value":"<home>/<folders>/server"}"#), sent)
    }

    /// A script listening on a port reads as the script, as it does in Processes and Network,
    /// and not as its interpreter, which is Apple's.
    func testAListenerIsReadAsTheCodeItRuns() throws {
        let python = "/usr/bin/python3", apple = CodeSignature(signer: .apple, identifier: "com.apple.python3")
        let processes: [Int32: ProcessEntry] = [
            40: process(40, python, arguments: [python, "/x/server.py"]),
            41: process(41, python, arguments: [python, "-c", "serve()"]),
            42: process(42, python, uid: 0),
            43: process(43, "/x/server", arguments: ["/x/server"]),
        ]
        let snapshot = PortsSnapshot.build(
            entries: [entry(.tcp, "127.0.0.1", 8000, pid: 40), entry(.tcp, "127.0.0.1", 8001, pid: 41),
                      entry(.tcp, "127.0.0.1", 8002, pid: 42, uid: 0), entry(.tcp, "127.0.0.1", 8003, pid: 43)],
            services: .empty, processes: { processes[$0] },
            signature: { $0 == python ? apple : CodeSignature(signer: .unsigned) })
        func item(_ port: UInt16) throws -> PortItem { try XCTUnwrap(snapshot.items.first { $0.port == port }) }

        let script = try item(8000)
        XCTAssertEqual(script.processName, "server.py")
        XCTAssertEqual(script.explainKey, "server.py:tcp/8000")
        XCTAssertEqual(script.whyHere(gone: false), "server.py listens on it, for programs on this Mac only.")
        XCTAssertEqual(script.whyHere(gone: true), "server.py listened on it, for programs on this Mac only.")
        XCTAssertEqual(script.signature?.signer, .script)
        XCTAssertEqual(script.interpreterSignature, apple)
        XCTAssertEqual(script.identity, .script(at: "/x/server.py"), "an answer for it is kept, against the script's file")
        XCTAssertFalse(script.isApplesProgram)
        let facts = Dictionary(script.facts.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Runs with"], "python3 (/usr/bin/python3)")
        XCTAssertEqual(facts["Signed by"], "script, not signed")
        XCTAssertEqual(facts["Interpreter signed by"], "Apple")
        XCTAssertNil(facts["Path"])

        XCTAssertEqual(try item(8001).signature?.signer, .unnamed, "inline code")
        XCTAssertNil(try item(8001).identity)
        XCTAssertEqual(try item(8002).signature?.signer, .unnamed, "another account's arguments cannot be read")
        XCTAssertNil(try item(8002).identity)

        let program = try item(8003)
        XCTAssertEqual(program.signature?.signer, .unsigned)
        XCTAssertNil(program.interpreterSignature)
        XCTAssertEqual(program.identity?.text, "unsigned:/x/server")
        XCTAssertEqual(program.facts.first { $0.name == "Path" }?.value, "/x/server")
    }

    /// A socket's uid is whoever created it: launchd creates a socket-activated agent's as
    /// root, and a server can bind as root and drop privileges.
    func testAListenerRunsAsItsProcessNotItsSocket() throws {
        let snapshot = PortsSnapshot.build(
            entries: [entry(.tcp, "0.0.0.0", 8000, pid: 40, uid: 0), entry(.tcp, "0.0.0.0", 8001, pid: 41, uid: 0)],
            services: .empty, processes: { $0 == 40 ? self.process(40, "/x/server", uid: 501) : nil }, signature: { _ in nil })
        XCTAssertEqual(snapshot.items.first { $0.port == 8000 }?.uid, 501)
        XCTAssertEqual(snapshot.items.first { $0.port == 8001 }?.uid, 0, "with no process to ask, the socket's")
    }

    func testServiceNames() {
        XCTAssertEqual(services.name(port: 22, proto: .tcp), "ssh")
        XCTAssertEqual(services.name(port: 7000, proto: .tcp), "afs3-fileserver")
        XCTAssertNil(services.name(port: 7000, proto: .udp))
        XCTAssertEqual(ServiceNames.load().name(port: 443, proto: .tcp), "https")
    }

    func testBuiltinPortRulesResolve() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        let repoSeeds = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Resources/knowledge")
        SeedLoader(rules: rules).load(from: repoSeeds)
        XCTAssertEqual(try rules.lookup(kind: .port, key: "ControlCenter:tcp/5000")?.category, "sharing")
        XCTAssertEqual(try rules.lookup(kind: .port, key: "Comet Helper:udp/5353")?.category, "system")
        XCTAssertEqual(try rules.lookup(kind: .port, key: "mDNSResponder:udp/5353")?.purpose.prefix(8), "The macO")
        XCTAssertNil(try rules.lookup(kind: .port, key: "node:tcp/11001"))
    }

    func testThisMachine() throws {
        let byPid = Dictionary(try ProcessTable.list(signature: { _ in nil }).map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let snapshot = PortsSnapshot.build(entries: try SocketTable.read(), services: ServiceNames.load(),
                                           processes: { byPid[$0] }, signature: { _ in nil })
        XCTAssertFalse(snapshot.items.isEmpty)
        XCTAssertEqual(Set(snapshot.items.map(\.id)).count, snapshot.items.count)
    }
}
