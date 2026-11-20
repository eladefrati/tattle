import XCTest
@testable import tattle

final class ProcessTableTests: XCTestCase {
    func testKernelListHasEveryoneWithNamesAndParents() throws {
        let entries = try ProcessTable.list(signature: { _ in nil })
        let byPid = Dictionary(entries.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(byPid.count, entries.count, "one entry per pid")
        XCTAssertGreaterThan(entries.count, 100)

        let kernel = try XCTUnwrap(byPid[0])
        XCTAssertEqual(kernel.name, "kernel_task", "pid 0 has no path, so the command name is used")
        XCTAssertNil(kernel.path)
        let launchd = try XCTUnwrap(byPid[1])
        XCTAssertEqual(launchd.path, "/sbin/launchd")
        XCTAssertEqual(launchd.parentPid, 0)
        XCTAssertEqual(launchd.uid, 0)

        let me = try XCTUnwrap(byPid[getpid()])
        XCTAssertEqual(me.uid, getuid())
        XCTAssertEqual(me.parentPid, getppid())
        XCTAssertNotNil(me.path)
        XCTAssertLessThan(me.started, Date())
        XCTAssertGreaterThan(me.started, Date().addingTimeInterval(-24 * 60 * 60))
        XCTAssertTrue(entries.contains { $0.uid != getuid() }, "root processes are listed too")
    }

    func testScriptsAreNamedAfterTheScript() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let script = dir.appending(path: "tattle-probe-script.sh")
        try Data("#!/bin/sh\nsleep 30\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
        let process = Process()
        process.executableURL = script
        process.arguments = ["--flag", "/etc"]
        try process.run()
        defer { process.terminate() }

        let entries = try ProcessTable.list(signature: { _ in nil })
        let entry = try XCTUnwrap(entries.first { $0.pid == process.processIdentifier })
        XCTAssertEqual(entry.name, "tattle-probe-script.sh")
        XCTAssertEqual(entry.interpreter, "sh")
        XCTAssertEqual(entry.path, "/bin/sh")
        XCTAssertEqual(entry.arguments?.dropFirst().first, script.path, "the kernel passes the script as the first argument")
        XCTAssertEqual(entry.arguments?.last, "/etc")

        let me = try XCTUnwrap(entries.first { $0.pid == getpid() })
        XCTAssertNil(me.interpreter)
        XCTAssertEqual(me.arguments?.isEmpty, false)
        XCTAssertEqual(me.workingDirectory, FileManager.default.currentDirectoryPath)
        let launchd = try XCTUnwrap(entries.first { $0.pid == 1 })
        XCTAssertNil(launchd.arguments, "other users' command lines are not readable")
        XCTAssertNil(launchd.workingDirectory)
        XCTAssertEqual(launchd.name, "launchd")
    }

    func testNaming() {
        XCTAssertEqual(ProcessEntry.name(path: "/usr/bin/python3", arguments: ["python3", "-u", "/bin/ls"], command: "python3").name, "ls")
        XCTAssertEqual(ProcessEntry.name(path: "/opt/homebrew/bin/python3.14", arguments: ["python3.14", "/bin/ls"], command: "python3.14").interpreter, "python3.14")
        XCTAssertEqual(ProcessEntry.name(path: "/usr/bin/python3", arguments: ["python3", "-m", "http.server"], command: "python3").name, "python3")
        let shell = ProcessEntry.name(path: "/bin/zsh", arguments: ["-zsh"], command: "zsh")
        XCTAssertEqual(shell.name, "zsh", "a login shell with no script is itself")
        XCTAssertNil(shell.interpreter)
        XCTAssertEqual(ProcessEntry.name(path: "/Users/user/.local/share/claude/versions/2.1.304", arguments: ["claude", "--model", "x"], command: "2.1.304").name, "claude",
                       "the name it was started under beats a version-numbered file name")
        XCTAssertEqual(ProcessEntry.name(path: "/Users/user/.local/share/claude/versions/2.1.304", arguments: ["ugrep", "-G"], command: "2.1.304").name, "ugrep")
        XCTAssertEqual(ProcessEntry.name(path: nil, arguments: ["claude"], command: "2.1.206").name, "claude", "a deleted executable too")
        XCTAssertEqual(ProcessEntry.name(path: "/opt/node/bin/node", arguments: ["npm exec chrome-devtools-mcp@1.11.0", ""], command: "node").name,
                       "npm exec chrome-devtools-mcp@1.11.0", "a title node set for itself")
        XCTAssertEqual(ProcessEntry.name(path: "/usr/libexec/trustd", arguments: nil, command: "trustd").name, "trustd")
        XCTAssertEqual(ProcessEntry.name(path: "/Users/user/Library/Application Support/iTerm2/iTermServer-3.6.11",
                                         arguments: ["/Users/user/Library/Application Support/iTerm2/iTermServer-3.6.11"], command: "iTermServer-3.6.").name,
                       "iTermServer-3.6.11", "a path with a space is still a path")
        XCTAssertEqual(ProcessEntry.name(path: nil, arguments: nil, command: "kernel_task").name, "kernel_task")

        XCTAssertEqual(ProcessEntry.scriptName("/Users/user/.npm/_npx/0a/node_modules/chrome-devtools-mcp/build/src/main.js"), "chrome-devtools-mcp")
        XCTAssertEqual(ProcessEntry.scriptName("/x/node_modules/@playwright/mcp/cli.js"), "@playwright/mcp")
        XCTAssertEqual(ProcessEntry.scriptName("/x/node_modules/.bin/tsc"), "tsc")
        XCTAssertEqual(ProcessEntry.name(path: "/opt/node/bin/node", arguments: ["npm exec @playwright/mcp@latest", ""], command: "node").name,
                       "npm exec @playwright/mcp@latest", "a title is not a path")
        XCTAssertEqual(ProcessEntry.scriptName("/Users/user/dev/app/server.js"), "server.js")
    }

    /// The name a process started under is read as text: a URL would resolve these against the
    /// app's own working directory and home folder and name the process after those. A home
    /// folder, or a relative path ending in "." or "..", says nothing about the program, so the
    /// file names it. An absolute path names the process as it always has.
    func testTheNameAProcessStartedUnderIsNotAPathToResolve() {
        func started(_ first: String) -> String {
            ProcessEntry.name(path: "/x/tool", arguments: [first], command: "tool").name
        }
        for folder in ["", ".", "..", "~", "~/", "~user", "~user/", "~user//", "./", ".//", "../", "a/.", "a/..", "a/./", "a/../", "-."] {
            XCTAssertEqual(started(folder), "tool", "[\(folder)]")
        }
        for absolute in ["/x/~", "/x/~/", "/x/~foo", "/x/.", "/x/./", "/x/.."] {
            XCTAssertEqual(started(absolute), URL(fileURLWithPath: absolute).lastPathComponent, "[\(absolute)]")
        }
        XCTAssertEqual(started("~/bin/agent"), "agent", "a file under a folder is still named")
        XCTAssertEqual(started("./agent"), "agent")
        XCTAssertEqual(started("~ maintenance"), "~ maintenance", "a title is kept as written")
    }

    /// A title a process sets for itself can hold a login, a database and a host. The row keeps
    /// it whole; `program` is what a prompt and a kept answer's key carry in its place.
    func testATitleIsCutToItsProgram() {
        func named(_ title: String, path: String? = "/opt/pg/bin/postgres", command: String = "postgres") -> (name: String, program: String?) {
            let named = ProcessEntry.name(path: path, arguments: [title, ""], command: command)
            return (named.name, named.program)
        }
        let backend = named("postgres: appuser payroll_prod db01.corp.example.com(54321) idle")
        XCTAssertEqual(backend.name, "postgres: appuser payroll_prod db01.corp.example.com(54321) idle", "the row keeps the title")
        XCTAssertEqual(backend.program, "postgres")
        XCTAssertEqual(named("npm exec @scope/pkg", path: "/opt/node/bin/node", command: "node").program, "npm", "the title's first word, not the file")
        XCTAssertEqual(named("sshd-session: username@ttys003", path: "/usr/libexec/sshd-session").program, "sshd-session")
        XCTAssertEqual(named("-worker: tenant acme", path: "/x/worker").program, "worker")
        let helper = "/Applications/Acme.app/Contents/MacOS/Acme Helper"
        XCTAssertEqual(named("Acme Helper --tenant example", path: helper).program, "Acme Helper", "a program whose name holds spaces")
        XCTAssertEqual(named("Acme Helper: tenant example", path: helper).program, "Acme Helper")
        XCTAssertNil(named("Acme Helper", path: helper).program, "its own name is no title")
        XCTAssertEqual(named(": appuser payroll_prod").program, "postgres", "nothing before the colon: the file")
        XCTAssertEqual(named(": appuser payroll_prod", path: nil, command: "postgres").program, "postgres", "or the kernel's name")

        // A title is told from a name or a path by a space and no leading slash, so these go
        // out as they are named.
        let slashed = named("/opt/bin/worker: tenant acme", path: "/opt/bin/worker", command: "worker")
        XCTAssertEqual(slashed.name, "worker: tenant acme")
        XCTAssertNil(slashed.program)
        let oneWord = named("worker:tenant-acme", path: "/opt/bin/worker", command: "worker")
        XCTAssertEqual(oneWord.name, "worker:tenant-acme")
        XCTAssertNil(oneWord.program)

        XCTAssertNil(ProcessEntry.name(path: "/bin/zsh", arguments: ["-zsh"], command: "zsh").program, "a name is not a title")
        XCTAssertNil(ProcessEntry.name(path: "/x/My Tool", arguments: ["/x/My Tool"], command: "My Tool").program, "nor is a path with a space")
        XCTAssertNil(ProcessEntry.name(path: "/usr/bin/python3", arguments: ["python3", "/x/my script.py"], command: "python3").program, "nor a script's file name")
        XCTAssertNil(ProcessEntry.name(path: "/usr/libexec/trustd", arguments: nil, command: "trustd").program)
    }

    func testALineReadsAsTheListHasIt() throws {
        let records = try XCTUnwrap(ProcessTable.records())
        let lines = records.lines([getpid(), 0])
        let listed = Dictionary(try ProcessTable.list(signature: { _ in nil }).map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        XCTAssertNotNil(lines.entries[getppid()], "the parent is read with the process")
        XCTAssertTrue(lines.entries.values.contains { $0.parentPid == 1 }, "and every ancestor up to the one launchd started")
        XCTAssertNotNil(lines.entries[0])
        for (pid, entry) in lines.entries {
            XCTAssertEqual(entry, listed[pid], "pid \(pid)")
        }
        XCTAssertEqual(records.lines([Int32.max]), ProcessLines(), "no such process")
    }

    private let lineTable: [Int32: ProcessEntry] = {
        func entry(_ pid: Int32, _ parent: Int32) -> ProcessEntry {
            ProcessEntry(pid: pid, parentPid: parent, uid: 501, name: "p\(pid)", path: "/x/p\(pid)", started: .distantPast)
        }
        return [30: entry(30, 20), 20: entry(20, 1), 40: entry(40, 1), 50: entry(50, 1), 60: entry(60, 1)]
    }()

    func testOwnersAreReadBeforeTheirLines() {
        var table: [Int32: ProcessEntry] = [:]
        for owner: Int32 in [10, 20] {
            for step: Int32 in 0..<6 {
                let pid = owner + step
                table[pid] = ProcessEntry(pid: pid, parentPid: step == 5 ? 1 : pid + 1, uid: 501, name: "p\(pid)", path: "/x/p\(pid)", started: .distantPast)
            }
        }
        var order: [Int32] = []
        _ = ProcessTable.lines(of: [10, 20], in: table, parent: \.parentPid, entry: { found in
            order.append(found.pid)
            return found
        }, responsible: { _ in nil })
        XCTAssertEqual(order.count, 12)
        XCTAssertEqual(Set(order.prefix(2)), [10, 20], "\(order)")
    }

    func testALineFollowsParentsAndTheResponsibleProcess() {
        var reads: [Int32] = []
        let lines = ProcessTable.lines(of: [30, 40, 20, 70], in: lineTable, parent: \.parentPid, entry: { found in
            reads.append(found.pid)
            return found
        }, responsible: { $0 == 40 ? 50 : nil })
        XCTAssertEqual(Set(lines.entries.keys), [20, 30, 40, 50], "not the bystander, nor a pid with no record")
        XCTAssertEqual(lines.responsible, [40: 50])
        XCTAssertEqual(reads.sorted(), [20, 30, 40, 50], "each process once")
    }

    func testAZombieReadsAsExited() throws {
        var pid: pid_t = 0
        var argv: [UnsafeMutablePointer<CChar>?] = [strdup("/usr/bin/true"), nil]
        defer { argv.forEach { free($0) } }
        XCTAssertEqual(posix_spawn(&pid, "/usr/bin/true", nil, nil, &argv, environ), 0)
        defer { waitpid(pid, nil, 0) }
        let deadline = Date().addingTimeInterval(5)
        while ProcessTable.commandName(pid) != nil, Date() < deadline { usleep(10_000) }
        XCTAssertEqual(kill(pid, 0), 0, "still in the table")
        XCTAssertNil(ProcessTable.commandName(pid))
        XCTAssertEqual(ProcessTable.records()?.lines([pid]), ProcessLines())
        XCTAssertFalse(try ProcessTable.list(signature: { _ in nil }).contains { $0.pid == pid })
    }

    func testTheKernelNamesAProcessAfterItsFile() throws {
        let path = try XCTUnwrap(ProcessTable.pidPath(getpid()))
        XCTAssertEqual(ProcessTable.commandName(getpid()), ProcessTable.commandName(ofExecutable: path))
        XCTAssertEqual(ProcessTable.commandName(ofExecutable: "/x/a-very-long-executable-name"), "a-very-long-exec")
        XCTAssertNil(ProcessTable.commandName(Int32.max), "no such process")
    }

    func testParseArguments() {
        var bytes: [UInt8] = [3, 0, 0, 0]
        bytes += Array("/usr/bin/node".utf8) + [0, 0, 0]
        for string in ["node", "/tmp/server.js", "--port", "HOME=/Users/user"] {
            bytes += Array(string.utf8) + [0]
        }
        XCTAssertEqual(ProcessTable.parseArguments(bytes[...]), ["node", "/tmp/server.js", "--port"])
        XCTAssertNil(ProcessTable.parseArguments([1, 0][...]))

        // A path whose NUL ends on the pointer boundary has no padding, and an empty argv[0]
        // follows it straight away.
        var unpadded: [UInt8] = [2, 0, 0, 0]
        unpadded += Array("/bin/ls".utf8) + [0]
        unpadded += [0]
        unpadded += Array("x".utf8) + [0]
        unpadded += Array("HOME=/x".utf8) + [0]
        XCTAssertEqual(ProcessTable.parseArguments(unpadded[...]), ["", "x"])

        // An argument where the padding should be means another layout: the NULs are skipped.
        var unaligned: [UInt8] = [1, 0, 0, 0]
        unaligned += Array("/bin/l".utf8) + [0]
        unaligned += Array("ls".utf8) + [0]
        unaligned += Array("HOME=/x".utf8) + [0]
        XCTAssertEqual(ProcessTable.parseArguments(unaligned[...]), ["ls"])
    }

    /// A process started with an empty argv[0], as `exec -a ""` starts one: the kernel pads the
    /// executable's path with NULs, and the empty argument is one more NUL.
    func testAnEmptyFirstArgumentIsReadAsOne() throws {
        for (path, argv) in [("/bin/cat", [""]), ("/bin/sleep", ["", "30"]), ("/bin/sleep", ["sleep", "30"])] {
            // cat waits on a pipe nobody writes to.
            var input: [Int32] = [0, 0]
            XCTAssertEqual(pipe(&input), 0)
            var actions: posix_spawn_file_actions_t?
            posix_spawn_file_actions_init(&actions)
            posix_spawn_file_actions_adddup2(&actions, input[0], 0)
            let arguments = argv.map { strdup($0) } + [nil]
            let environment = [strdup("TATTLE_FIRST=not-an-argument"), nil]
            var pid: pid_t = 0
            let spawned = posix_spawn(&pid, path, &actions, nil, arguments, environment)
            defer {
                if spawned == 0 {
                    kill(pid, SIGKILL)
                    waitpid(pid, nil, 0)
                }
                input.forEach { close($0) }
                posix_spawn_file_actions_destroy(&actions)
                (arguments + environment).forEach { free($0) }
            }
            XCTAssertEqual(spawned, 0)
            XCTAssertEqual(ProcessTable.arguments(pid: pid), argv, "\(path) \(argv)")
            XCTAssertEqual(ProcessTable.records()?.lines([pid]).entries[pid]?.name, (path as NSString).lastPathComponent, "\(path) \(argv)")
        }
    }

    func testOwnUsageMatchesGetrusage() {
        var spin = 0.0
        for i in 0..<5_000_000 { spin += (Double(i) * 1.0001).squareRoot() }
        XCTAssertGreaterThan(spin, 0)
        var rusage = Darwin.rusage()
        getrusage(RUSAGE_SELF, &rusage)
        let expected = Double(rusage.ru_utime.tv_sec) + Double(rusage.ru_utime.tv_usec) / 1e6
            + Double(rusage.ru_stime.tv_sec) + Double(rusage.ru_stime.tv_usec) / 1e6

        let usage = ProcessTable.ownUsage(pid: getpid())!
        XCTAssertTrue(usage.memoryIsFootprint)
        XCTAssertGreaterThan(usage.memoryBytes, 1 << 20)
        // The rusage times are Mach units, converted with the timebase; getrusage is the
        // same clock in microseconds.
        XCTAssertEqual(usage.cpuSeconds, expected, accuracy: 0.05)
        XCTAssertNil(ProcessTable.ownUsage(pid: 1), "root processes are refused")
    }

    func testFallbackParsesPsTimes() {
        let parsed = ProcessUsageFallback.parse("""
              1  32736 622:57.17
            313 103024   0:05.31
            999  1024 1-02:03:04.50
            bad line here
            """)
        XCTAssertEqual(parsed[1], ProcessUsage(memoryBytes: 32736 * 1024, cpuSeconds: 622 * 60 + 57.17, memoryIsFootprint: false))
        XCTAssertEqual(parsed[313]?.cpuSeconds, 5.31)
        XCTAssertEqual(parsed[999]?.cpuSeconds, 26 * 3600 + 3 * 60 + 4.5)
        XCTAssertEqual(parsed.count, 3)
        XCTAssertNil(ProcessUsageFallback.seconds(fromTime: "12"))
        XCTAssertNil(ProcessUsageFallback.seconds(fromTime: "a:b"))
    }

    func testReadFillsUsageForOthersThroughFallback() throws {
        var asked: [Int32] = []
        let entries = try ProcessTable.read(fallback: { pids in
            asked = pids
            return Dictionary(pids.map { ($0, ProcessUsage(memoryBytes: 7, cpuSeconds: 1, memoryIsFootprint: false)) }, uniquingKeysWith: { a, _ in a })
        }, signature: { _ in nil })
        XCTAssertTrue(asked.contains(1), "launchd is root, so ps must supply it")
        XCTAssertFalse(asked.contains(getpid()), "own processes come from libproc")
        XCTAssertEqual(entries.first { $0.pid == 1 }?.usage?.memoryBytes, 7)
        XCTAssertTrue(entries.first { $0.pid == getpid() }?.usage?.memoryIsFootprint == true)
    }

    func testRealFallbackCoversRootProcesses() throws {
        let entries = try ProcessTable.read(signature: { _ in nil })
        let root = entries.filter { $0.uid == 0 && $0.pid > 0 }
        let covered = root.filter { $0.usage != nil }
        // A handful can exit between the kernel list and ps.
        XCTAssertGreaterThan(Double(covered.count), Double(root.count) * 0.95, "\(covered.count) of \(root.count)")
        XCTAssertEqual(entries.first { $0.pid == 1 }?.usage?.memoryIsFootprint, false)
        XCTAssertGreaterThan(entries.first { $0.pid == 1 }?.usage?.memoryBytes ?? 0, 0)
    }
}
