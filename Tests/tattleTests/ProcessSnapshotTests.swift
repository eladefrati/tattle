import XCTest
@testable import tattle

final class ProcessSnapshotTests: XCTestCase {
    private let epoch = Date(timeIntervalSince1970: 1_700_000_000)

    private func entry(_ pid: Int32, _ ppid: Int32, _ path: String?, uid: UInt32 = 501, memory: UInt64 = 0, cpu: Double = 0,
                       started: Date? = nil, name: String? = nil, interpreter: String? = nil, cwd: String? = nil) -> ProcessEntry {
        ProcessEntry(pid: pid, parentPid: ppid, uid: uid,
                     name: name ?? path.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "pid \(pid)",
                     path: path, interpreter: interpreter, workingDirectory: cwd, started: started ?? epoch,
                     usage: ProcessUsage(memoryBytes: memory, cpuSeconds: cpu, memoryIsFootprint: uid == 501))
    }

    /// Apple signs everything on the system volume and in /bin, /usr; the rest is Developer ID.
    private func sign(_ path: String) -> CodeSignature? {
        for prefix in ["/System/", "/Library/Apple/", "/usr/libexec/", "/usr/bin/", "/bin/", "/sbin/"] where path.hasPrefix(prefix) {
            return CodeSignature(signer: .apple)
        }
        let vendor = path.split(separator: "/").first { $0.hasSuffix(".app") }.map { String($0.dropLast(4)) }
            ?? URL(fileURLWithPath: path).lastPathComponent
        return CodeSignature(signer: .developerID(name: vendor), teamIdentifier: "T-\(vendor)")
    }

    private var machine: [ProcessEntry] {
        [
            entry(0, 0, nil, uid: 0, name: "kernel_task"),
            entry(1, 0, "/sbin/launchd", uid: 0, memory: 30),
            entry(50, 1, "/usr/libexec/trustd", uid: 0, memory: 20),
            entry(60, 1, "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", memory: 90),
            entry(61, 1, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", memory: 200),
            entry(70, 1, "/System/Applications/Mail.app/Contents/MacOS/Mail", memory: 300),
            entry(100, 1, "/Applications/Slack.app/Contents/MacOS/Slack", memory: 100, cpu: 10),
            entry(101, 100, "/Applications/Slack.app/Contents/Frameworks/Slack Helper (GPU).app/Contents/MacOS/Slack Helper (GPU)", memory: 400, cpu: 5),
            entry(200, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2", memory: 150, cwd: "/"),
            entry(201, 200, "/bin/zsh", memory: 5, cwd: NSHomeDirectory()),
            entry(202, 201, "/usr/local/bin/claude", memory: 250, cwd: NSHomeDirectory() + "/dev/tattle"),
            entry(203, 201, nil, memory: 20, name: "claude", cwd: NSHomeDirectory()),
            entry(300, 1, "/usr/local/bin/ollama", memory: 50),
            entry(301, 300, "/usr/local/bin/ollama", memory: 1000, name: "ollama runner"),
            entry(400, 1, "/bin/sh", uid: 0, memory: 1),
            entry(401, 400, "/opt/homebrew/bin/node", uid: 0, memory: 80),
            entry(500, 1, "/private/var/folders/x/T/X/ai.comet.code_sign_clone/code_sign_clone.1U/Comet.app.bundle/Contents/MacOS/Comet", memory: 600),
            entry(501, 500, "/Applications/Comet.app/Contents/Frameworks/Comet Framework.framework/Helpers/Comet Helper (GPU).app/Contents/MacOS/Comet Helper (GPU)", memory: 70),
            entry(510, 1, "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect", uid: 0, memory: 8),
            entry(600, 1, "/bin/sh", memory: 3, name: "backup.sh", interpreter: "sh"),
        ]
    }

    /// What Launch Services knows: the browser's main process came from /Applications,
    /// and it registered a node script as an "app" whose bundle is the node binary.
    private func running(_ pid: Int32) -> String? {
        switch pid {
        case 100: "/Applications/Slack.app"
        case 500: "/Applications/Comet.app"
        case 202: "/usr/local/bin/claude"
        default: nil
        }
    }

    private func signedByAcme(_ path: String) -> CodeSignature? { CodeSignature(signer: .developerID(name: "Acme"), teamIdentifier: "ACME") }

    func testWhyHereSaysWhatStartedIt() throws {
        let calendar = "/System/Applications/Calendar.app"
        let entries = [
            entry(0, 0, nil, uid: 0, name: "kernel_task"), entry(1, 0, "/sbin/launchd", uid: 0), entry(201, 1, "/bin/zsh"),
            entry(9000, 201, "/usr/local/bin/tool"), entry(50, 9000, "/usr/local/bin/worker"),
            entry(752, 1, calendar + "/Contents/PlugIns/CalendarWidgetExtension.appex/Contents/MacOS/CalendarWidgetExtension"),
            entry(9100, 1, calendar + "/Contents/MacOS/Calendar"),
        ]
        func snapshot(open: Bool) -> ProcessSnapshot {
            ProcessSnapshot.build(entries: open ? entries : entries.filter { $0.pid != 9100 }, previous: nil, signature: sign,
                                  runningApp: { open && $0 == 9100 ? calendar : nil }, responsible: { _ in nil }, takenAt: epoch)
        }
        let open = snapshot(open: true)
        func item(_ pid: Int32) throws -> ProcessItem { try XCTUnwrap(open.items.first { $0.pid == pid }) }
        XCTAssertEqual(try item(0).whyHere(gone: false), "The Mac starts it at boot.")
        XCTAssertEqual(try item(9000).whyHere(gone: false), "zsh started it.")
        // launchd takes in every process whose parent quit, so it is named as the parent only.
        XCTAssertEqual(try item(201).whyHere(gone: false), "Its parent is launchd.")
        XCTAssertEqual(try item(752).whyHere(gone: false), "Its parent is launchd, and it is part of Calendar.")
        XCTAssertEqual(try item(752).whyHere(gone: true), "Its parent was launchd, and it was part of Calendar.")
        XCTAssertEqual(open.group(id: "pid:9000")?.whyHere(gone: false), "zsh started it; 2 processes in all.")
        XCTAssertEqual(open.group(id: calendar)?.whyHere(gone: false), "Calendar is open; 2 processes in all.")
        XCTAssertEqual(open.group(id: calendar)?.whyHere(gone: true), "Calendar was open; 2 processes in all.")
        XCTAssertEqual(snapshot(open: false).group(id: calendar)?.whyHere(gone: false), "Calendar is not open, but 1 of its processes is running.")
    }

    /// A widget launchd started at login has a lower pid than the app opened later, and is
    /// not what "Quit Calendar" means. With the app closed there is nothing of that name to quit.
    func testAnAppsLeaderIsTheProcessLaunchServicesOpenedItFrom() throws {
        let calendar = "/System/Applications/Calendar.app"
        let widget = entry(752, 1, calendar + "/Contents/PlugIns/CalendarWidgetExtension.appex/Contents/MacOS/CalendarWidgetExtension")
        let service = entry(1564, 1, calendar + "/Contents/XPCServices/Reminder.xpc/Contents/MacOS/Reminder")
        let app = entry(9000, 1, calendar + "/Contents/MacOS/Calendar")
        let open = ProcessSnapshot.build(entries: [widget, service, app], previous: nil, signature: signedByAcme,
                                         runningApp: { $0 == 9000 ? calendar : $0 == 752 ? widget.path : nil }, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertEqual(open.group(id: calendar)?.leader?.pid, 9000)
        let closed = ProcessSnapshot.build(entries: [widget, service], previous: nil, signature: signedByAcme,
                                           runningApp: { _ in nil }, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertNotNil(closed.group(id: calendar))
        XCTAssertNil(closed.group(id: calendar)?.leader, "its helpers run, the app does not")
    }

    /// Pids wrap, so of two copies of one app the older can have the higher pid.
    func testOfTwoCopiesOfAnAppTheLeaderIsTheOlder() {
        let path = "/Applications/Two.app"
        let snapshot = ProcessSnapshot.build(
            entries: [entry(50, 1, path + "/Contents/MacOS/Two", started: epoch + 60), entry(9000, 1, path + "/Contents/MacOS/Two", started: epoch)],
            previous: nil, signature: signedByAcme, runningApp: { _ in path }, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertEqual(snapshot.group(id: path)?.leader?.pid, 9000)
    }

    /// An app with no window never registers with Launch Services; its main executable is
    /// still the app. Of several at that path, the oldest; a helper elsewhere in the bundle is not it.
    func testAnAppsLeaderIsItsMainExecutableWhenLaunchServicesDoesNotKnowIt() {
        let app = "/Applications/Core.app", main = app + "/Contents/MacOS/Core"
        let entries = [
            entry(50, 1, app + "/Contents/MacOS/helper"),
            entry(9000, 1, main),
            entry(60, 9000, main, started: epoch + 5),
        ]
        func leader(_ entries: [ProcessEntry]) -> Int32? {
            ProcessSnapshot.build(entries: entries, previous: nil, signature: signedByAcme, runningApp: { _ in nil },
                                  mainExecutable: { $0.path == app ? main : nil }, responsible: { _ in nil }, takenAt: epoch)
                .group(id: app)?.leader?.pid
        }
        XCTAssertEqual(leader(entries), 9000)
        XCTAssertNil(leader([entries[0]]), "only a helper runs")
    }

    /// The app's binary run with no window, by a command-line tool say, is often the older of
    /// the two, and is not what "Quit" means while the app itself is open.
    func testAnAppsLeaderIsTheOneLaunchServicesKnowsOverAnOlderRunOfItsExecutable() {
        let app = "/Applications/Core.app", main = app + "/Contents/MacOS/Core"
        let snapshot = ProcessSnapshot.build(
            entries: [entry(50, 1, main, started: epoch), entry(9000, 1, main, started: epoch + 60)],
            previous: nil, signature: signedByAcme, runningApp: { $0 == 9000 ? app : nil },
            mainExecutable: { $0.path == app ? main : nil }, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertEqual(snapshot.group(id: app)?.leader?.pid, 9000)
    }

    /// A program started from a shell has a parent, and a worker with a lower pid after a wrap.
    func testAProgramsLeaderIsTheTopOfItsTree() {
        let snapshot = ProcessSnapshot.build(
            entries: [entry(1, 0, "/sbin/launchd", uid: 0), entry(201, 1, "/bin/zsh"),
                      entry(9000, 201, "/usr/local/bin/tool"), entry(50, 9000, "/usr/local/bin/worker")],
            previous: nil, signature: sign, runningApp: { _ in nil }, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertEqual(snapshot.group(id: "pid:9000")?.members.map(\.pid).sorted(), [50, 9000])
        XCTAssertEqual(snapshot.group(id: "pid:9000")?.leader?.pid, 9000)
    }

    /// A system app's own path names a bundle, so it does not take its parent's app; started by
    /// a publisher's app, it still belongs with that app, not in a row of its own named for it.
    func testASystemAppStartedByAnAppSitsInThatAppsRow() {
        let entries = machine + [entry(102, 100, "/System/Library/CoreServices/Foo.app/Contents/MacOS/Foo", memory: 1)]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: sign, runningApp: running, responsible: { _ in nil }, takenAt: epoch)
        XCTAssertNil(snapshot.group(id: "pid:100"), "no second row named Slack")
        XCTAssertEqual(snapshot.group(id: "/Applications/Slack.app")?.members.map(\.pid).sorted(), [100, 101, 102])
    }

    /// Root's process can be anyone's code, so the words say whose process it is.
    func testNoQuitSaysWhoseProcessItIs() {
        XCTAssertEqual(ProcessControl.whyNoQuit(uid: 0), "Runs as root, so Tattle cannot quit it")
        XCTAssertEqual(ProcessControl.whyNoQuit(uid: 65), "Runs as _mdnsresponder, so Tattle cannot quit it")
    }

    func testErrorsThePanelShowsReadAsSentences() {
        XCTAssertEqual(String(describing: ProcessControl.ControlError.failed(errno: ESRCH)), "The process could not be signalled: No such process.")
        XCTAssertEqual(String(describing: ProcessTable.ReadError.sysctl(errno: ENOMEM)), "The process table could not be read: Cannot allocate memory.")
        XCTAssertEqual(String(describing: SocketTable.ReadError.sysctl(name: "net.inet.tcp.pcblist_n", errno: EPERM)),
                       "The socket table (net.inet.tcp.pcblist_n) could not be read: Operation not permitted.")
    }

    func testOnlyAnAppGetsTheRegularQuit() {
        XCTAssertTrue(ProcessControl.quitsAsApp(bundle: "/Applications/Slack.app"))
        XCTAssertFalse(ProcessControl.quitsAsApp(bundle: "/opt/homebrew/bin/node"), "a command-line process Launch Services registered")
        XCTAssertFalse(ProcessControl.quitsAsApp(bundle: "/Library/Frameworks/Python.framework/Versions/3.13/Resources/Python.app"))
        XCTAssertFalse(ProcessControl.quitsAsApp(bundle: nil))
    }

    func testAttributionAndRollup() {
        let snapshot = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, runningApp: running, takenAt: epoch)
        XCTAssertEqual(snapshot.items.count, machine.count)
        let names = snapshot.groups(sortedBy: .memory).map { "\($0.name):\($0.members.count):\($0.memoryBytes)" }
        XCTAssertEqual(names, [
            "ollama:2:1050", "Comet:2:670", "Slack:2:500", "iTerm:4:425", "macOS:7:349", "Mail:1:300", "node:1:80", "backup.sh:1:3",
        ])
        let script = snapshot.group(id: "pid:600")!
        XCTAssertEqual(script.kind, .process, "a script run by Apple's shell is the user's, not macOS")
        XCTAssertEqual(script.leader?.signerText, "sh script")
        XCTAssertEqual(script.leader?.facts.prefix(4).map(\.name), ["Process", "Runs with", "Signed by", "Interpreter signed by"])
        XCTAssertEqual(snapshot.group(id: "/Applications/Comet.app")?.members.map(\.pid), [500, 501],
                       "the code-sign clone main process joins the helpers under the installed bundle")

        let slack = snapshot.group(id: "/Applications/Slack.app")!
        XCTAssertEqual(slack.kind, .app(AppBundle(path: "/Applications/Slack.app")))
        XCTAssertEqual(slack.members.map(\.pid), [101, 100], "members by memory")
        XCTAssertEqual(slack.signature?.summary, "Slack")
        XCTAssertEqual(slack.explainKey, "Slack")
        XCTAssertEqual(slack.leader?.pid, 100, "quitting the app means its main process, not the biggest helper")
        XCTAssertEqual(snapshot.group(id: "pid:300")?.leader?.pid, 300)
        XCTAssertNil(snapshot.group(id: ProcessGroup.systemID)?.leader)
        XCTAssertEqual(slack.members[0].facts.first { $0.name == "Part of" }?.value, "Slack")
        XCTAssertNil(slack.members[1].facts.first { $0.name == "Part of" }, "the app's own process is not part of itself")

        let iterm = snapshot.group(id: "/Applications/iTerm.app")!
        XCTAssertEqual(Set(iterm.members.map(\.name)), ["iTerm2", "zsh", "claude"], "a shell and what it runs belong to the terminal")
        XCTAssertEqual(iterm.members.first { $0.name == "claude" }?.parentName, "zsh")
        XCTAssertEqual(iterm.tree.map { "\($0.item.pid)@\($0.depth)" }, ["200@0", "201@1", "202@2", "203@2"],
                       "children follow their parent, largest first")
        XCTAssertEqual(iterm.tree.map(\.showsDirectory), [false, false, true, false],
                       "the directory shows where it first differs from the parent's")
        XCTAssertEqual(iterm.members.map(\.pid), [202, 200, 203, 201], "members themselves stay by memory")
        let session = snapshot.item(pid: 202)!
        XCTAssertEqual(session.workingDirectoryText, "~/dev/tattle")
        XCTAssertEqual(session.facts.first { $0.name == "Working in" }?.value, "~/dev/tattle")
        XCTAssertNil(snapshot.item(pid: 201)?.workingDirectoryText, "the home folder says nothing")
        XCTAssertNil(snapshot.item(pid: 200)?.workingDirectoryText, "nor does the root")
        XCTAssertEqual(snapshot.item(pid: 203)?.signerText, "executable no longer on disk")
        XCTAssertNil(snapshot.group(id: "/usr/local/bin/claude"), "a bare executable Launch Services reports is not an app")

        let ollama = snapshot.group(id: "pid:300")!
        XCTAssertEqual(ollama.kind, .process)
        XCTAssertEqual(ollama.path, "/usr/local/bin/ollama", "the root's path, not the largest member's")
        XCTAssertEqual(ollama.signature?.summary, "ollama")
        XCTAssertEqual(ollama.explainKey, "ollama")

        let node = snapshot.group(id: "pid:401")!
        XCTAssertEqual(node.members.count, 1, "an Apple shell above a third-party process stays with macOS")

        let system = snapshot.group(id: ProcessGroup.systemID)!
        XCTAssertEqual(Set(system.members.map(\.name)), ["kernel_task", "launchd", "trustd", "Dock", "Finder", "sh", "XProtect"])
        XCTAssertNil(system.explainKey)
        XCTAssertEqual(system.signature?.signer, .apple)
        XCTAssertEqual(system.facts.first?.value, "7")
        XCTAssertNil(system.path, "macOS is not one place to reveal")

        XCTAssertEqual(snapshot.group(id: "/System/Applications/Mail.app")?.name, "Mail", "Apple apps the user opens are their own row")
        XCTAssertTrue(snapshot.groups.allSatisfy { $0.cpu == nil }, "no previous reading, no CPU")
        XCTAssertEqual(snapshot.item(pid: 101)?.explainKey, "Slack Helper (GPU)")
    }

    func testCPUComesFromTheDifferenceAgainstThePreviousSnapshot() {
        let first = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, takenAt: epoch)
        var later = machine
        let index = { (pid: Int32) in later.firstIndex { $0.pid == pid }! }
        later[index(100)].usage!.cpuSeconds = 11       // Slack: +1 s over 2 s
        later[index(101)].usage!.cpuSeconds = 9        // helper: +4 s
        later[index(300)].usage!.cpuSeconds = 3        // ollama restarted: new start time, so no share
        later[index(300)].started = epoch.addingTimeInterval(1.5)
        let second = ProcessSnapshot.build(entries: later, previous: first, signature: sign, takenAt: epoch.addingTimeInterval(2))

        XCTAssertEqual(second.item(pid: 100)?.cpu, 0.5)
        XCTAssertEqual(second.item(pid: 101)?.cpu, 2)
        XCTAssertNil(second.item(pid: 300)?.cpu)
        XCTAssertEqual(second.item(pid: 1)?.cpu, 0)
        XCTAssertEqual(second.group(id: "/Applications/Slack.app")?.cpu, 2.5)
        XCTAssertEqual(second.group(id: "pid:300")?.cpu, 0, "the runner still counts, the restarted server does not")
        XCTAssertEqual(second.groups(sortedBy: .cpu).first?.name, "Slack")
        XCTAssertEqual(second.item(pid: 101)?.facts.last, Fact(name: "CPU", value: "200%"))
        XCTAssertEqual(ProcessItem.cpuText(0.004), "0.4%")
    }

    func testAppBundleContainment() {
        XCTAssertEqual(AppBundle.containing("/Applications/Slack.app/Contents/Frameworks/Slack Helper (GPU).app/Contents/MacOS/Slack Helper (GPU)")?.path, "/Applications/Slack.app")
        XCTAssertEqual(AppBundle.containing("/Applications/Slack.app/Contents/MacOS/Slack")?.name, "Slack")
        XCTAssertNil(AppBundle.containing("/usr/bin/zsh"))
        XCTAssertNil(AppBundle.containing("/Applications/Slack.app"), "a bundle path is not an executable inside one")
        XCTAssertTrue(AppBundle(path: "/System/Library/CoreServices/Finder.app").isSystem)
        XCTAssertTrue(AppBundle(path: "/Library/Apple/System/Library/CoreServices/XProtect.app").isSystem)
        XCTAssertNil(AppBundle.containing("/private/var/x/Comet.app.bundle/Contents/MacOS/Comet"), "a clone is not the bundle")
        XCTAssertFalse(AppBundle(path: "/System/Applications/Mail.app").isSystem)
    }

    func testAnAppInsideAFrameworkIsNotAnApp() {
        let tools = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"
        XCTAssertNil(AppBundle.containing(tools), "the framework's helper, not an app anyone opened")
        XCTAssertNil(AppBundle.containing("/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python"))
        let xcode = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"
        XCTAssertEqual(AppBundle.containing(xcode)?.path, "/Applications/Xcode.app", "inside an app, the app")

        let named = ProcessEntry.name(path: tools, arguments: [tools, "-c", "payload"], command: "Python")
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: Date()),
            ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: named.name, path: tools, interpreter: named.interpreter,
                         runsUnnamedCode: named.runsUnnamedCode, started: Date()),
        ]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: { _ in CodeSignature(signer: .apple) }, responsible: { _ in nil })
        let group = snapshot.group(id: "pid:700")
        XCTAssertEqual(group?.kind, .process)
        XCTAssertEqual(group?.leader?.signerText, "Python, unnamed code", "the row's subtitle")
    }

    func testAScriptIsNotPartOfTheAppItsInterpreterLivesIn() {
        let python = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python"
        let git = "/Applications/Xcode.app/Contents/Developer/usr/bin/git"
        let named = ProcessEntry.name(path: python, arguments: [python, "-c", "payload"], command: "Python")
        let status = ProcessEntry.name(path: git, arguments: ["git", "status"], command: "git",
                                       signature: CodeSignature(signer: .apple, identifier: "com.apple.git"))
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: Date()),
            ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: named.name, path: python, interpreter: named.interpreter,
                         runsUnnamedCode: named.runsUnnamedCode, started: Date()),
            ProcessEntry(pid: 701, parentPid: 1, uid: 501, name: status.name, path: git, interpreter: status.interpreter,
                         runsUnnamedCode: status.runsUnnamedCode, started: Date()),
        ]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: { _ in CodeSignature(signer: .apple) }, responsible: { $0 })
        XCTAssertNil(snapshot.item(pid: 700)?.app, "Xcode's Python runs the script, which is not Xcode's")
        XCTAssertEqual(snapshot.group(id: "pid:700")?.kind, .process)
        XCTAssertEqual(snapshot.group(id: "pid:700")?.leader?.signerText, "Python, unnamed code", "the row's subtitle")
        XCTAssertNil(snapshot.item(pid: 701)?.app, "nor what Xcode's developer tools are told to run")
    }

    func testAnAppAmongApplesDeveloperToolsReadsAsUnnamedCode() {
        // Launch Services opens Xcode's agent as an app of its own; its row reads as what the
        // agent is, one of Apple's developer tools, not as the bundle's signer.
        let service = "/Applications/Xcode.app/Contents/Developer/Library/Xcode/Agents/Xcode Service.app"
        let executable = "\(service)/Contents/MacOS/Xcode Service"
        let apple = CodeSignature(signer: .apple, identifier: "com.apple.dt.mcp-server", teamIdentifier: "59GAB85EFG")
        let named = ProcessEntry.name(path: executable, arguments: [executable], command: "Xcode Service", signature: apple)
        let mail = "/System/Applications/Mail.app"
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: Date()),
            ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: named.name, path: executable, interpreter: named.interpreter,
                         runsUnnamedCode: named.runsUnnamedCode, started: Date()),
            ProcessEntry(pid: 701, parentPid: 1, uid: 501, name: "Mail", path: "\(mail)/Contents/MacOS/Mail", started: Date()),
        ]
        let opened: [Int32: String] = [700: service, 701: mail]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: { _ in apple },
                                             runningApp: { opened[$0] }, responsible: { _ in nil })
        let group = snapshot.group(id: service)
        XCTAssertEqual(group?.kind, .app(AppBundle(path: service)))
        XCTAssertEqual(group?.signature?.summary, "unnamed code", "the row's subtitle")
        XCTAssertEqual(snapshot.group(id: mail)?.signature?.summary, "Apple", "Apple's app elsewhere is Apple's")
    }

    func testAScriptLaunchServicesRegistersIsNotPartOfItsInterpretersFrameworkApp() {
        // A script that opens a window (tkinter) registers with Launch Services, which then
        // reports the app its interpreter runs from.
        let bundle = "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app"
        let python = "\(bundle)/Contents/MacOS/Python"
        let window = ProcessEntry.name(path: python, arguments: [python, "/x/window.py"], command: "Python")
        // An app whose executable is a script runs as its interpreter.
        let tool = ProcessEntry.name(path: "/bin/bash", arguments: ["/bin/bash", "/Applications/Tool.app/Contents/MacOS/tool"], command: "bash")
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: Date()),
            ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: window.name, path: python, interpreter: window.interpreter, started: Date()),
            ProcessEntry(pid: 701, parentPid: 1, uid: 501, name: tool.name, path: "/bin/bash", interpreter: tool.interpreter, started: Date()),
        ]
        let opened: [Int32: String] = [700: bundle, 701: "/Applications/Tool.app"]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: { _ in CodeSignature(signer: .apple) },
                                             runningApp: { opened[$0] }, responsible: { $0 })
        XCTAssertNil(snapshot.item(pid: 700)?.app, "the Python.app in Python's framework is no one's app")
        XCTAssertEqual(snapshot.item(pid: 701)?.app?.path, "/Applications/Tool.app", "an app is its app whatever its executable is")
    }

    func testAnInterpretersTeamIsNamedAsTheInterpreters() {
        let node = "/opt/node/bin/node"
        let named = ProcessEntry.name(path: node, arguments: ["node", "/x/a.js"], command: "node")
        let entries = [ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: named.name, path: node, interpreter: named.interpreter, started: Date())]
        let snapshot = ProcessSnapshot.build(
            entries: entries, previous: nil,
            signature: { _ in CodeSignature(signer: .developerID(name: "Node"), teamIdentifier: "HX7739G8FX") }, responsible: { _ in nil })
        let facts = snapshot.item(pid: 700)?.facts.filter { ["Signed by", "Interpreter signed by", "Team", "Interpreter team"].contains($0.name) }
        XCTAssertEqual(facts?.map(\.name), ["Signed by", "Interpreter signed by", "Interpreter team"], "not the script's team")
        XCTAssertEqual(facts?.last?.value, "HX7739G8FX")
    }

    func testFacts() {
        let item = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, takenAt: epoch).item(pid: 401)!
        let facts = Dictionary(item.facts.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(facts["Process"], "node (pid 401)")
        XCTAssertEqual(facts["Parent"], "sh (pid 400)")
        XCTAssertEqual(facts["Runs as"], "root")
        XCTAssertEqual(facts["Signed by"], "node")
        XCTAssertEqual(facts["Team"], "T-node")
        XCTAssertEqual(facts["Memory"], "80 bytes resident")
    }

    func testTheCPURowStaysWithNoShareAndIsNotInThePrompt() throws {
        let snapshot = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, takenAt: epoch)
        let noShare = Fact(name: "CPU", value: "\u{2013}", inPrompt: false)
        XCTAssertEqual(snapshot.item(pid: 401)?.facts.last, noShare)
        XCTAssertEqual(snapshot.group(id: "/Applications/Slack.app")?.facts.last, noShare)
    }

    func testAReadingLongAfterThePreviousHasNoCPU() {
        let first = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, takenAt: epoch)
        var later = machine
        later[later.firstIndex { $0.pid == 100 }!].usage!.cpuSeconds = 11
        let near = ProcessSnapshot.build(entries: later, previous: first, signature: sign, takenAt: epoch.addingTimeInterval(9))
        XCTAssertNotNil(near.item(pid: 100)?.cpu)
        let far = ProcessSnapshot.build(entries: later, previous: first, signature: sign, takenAt: epoch.addingTimeInterval(60))
        XCTAssertTrue(far.items.allSatisfy { $0.cpu == nil }, "no share over a 60-second gap")
    }

    func testAReadingWithNoCPUKeepsTheOrderOfTheLastOneThatHadIt() {
        let first = ProcessSnapshot.build(entries: machine, previous: nil, signature: sign, takenAt: epoch)
        var later = machine
        later[later.firstIndex { $0.pid == 400 }!].usage!.cpuSeconds = 1.6
        later[later.firstIndex { $0.pid == 100 }!].usage!.cpuSeconds = 10.4
        let measured = ProcessSnapshot.build(entries: later, previous: first, signature: sign, takenAt: epoch.addingTimeInterval(2))
        let order = measured.groups(sortedBy: .cpu).map(\.id)
        XCTAssertNotEqual(order, measured.groups(sortedBy: .memory).map(\.id), "CPU and memory must differ for this to prove anything")

        let baseline = ProcessSnapshot.build(entries: later, previous: measured, continuesPrevious: false, signature: sign, takenAt: epoch.addingTimeInterval(60))
        XCTAssertTrue(baseline.groups.allSatisfy { $0.cpu == nil })
        XCTAssertEqual(baseline.groups(sortedBy: .cpu).map(\.id), order)

        let baselineAgain = ProcessSnapshot.build(entries: later, previous: baseline, continuesPrevious: false, signature: sign, takenAt: epoch.addingTimeInterval(61))
        XCTAssertEqual(baselineAgain.groups(sortedBy: .cpu).map(\.id), order, "a close during the first reading keeps it too")
    }

    /// Everything the panel shows about the user's own process, as the model would get it.
    func testPromptFactsOfTheUsersOwnProcessCarryNoLoginOrDirectory() throws {
        let login = String(cString: getpwuid(getuid()).pointee.pw_name)
        let entries = [entry(900, 1, "/Users/\(login)/dev/build/Mine.app/Contents/MacOS/Mine", uid: getuid(), cwd: "/Users/\(login)/dev/client-acme")]
        let snapshot = ProcessSnapshot.build(
            entries: entries, previous: nil,
            signature: { _ in CodeSignature(signer: .development, teamIdentifier: "ABCDE12345") }, takenAt: epoch)
        let item = try XCTUnwrap(snapshot.item(pid: 900))
        let shown = Dictionary(item.facts.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(shown["Signed by"], "Apple Development (ABCDE12345)")
        XCTAssertEqual(shown["Runs as"], "you (\(login))")
        XCTAssertNotNil(shown["Working in"])

        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .process, key: item.explainKey, facts: item.facts), redactor: .addressesOnly)
        XCTAssertTrue(sent.contains("Apple Development") && sent.contains("ABCDE12345"), sent)
        XCTAssertFalse(sent.contains("client-acme"), sent)
        XCTAssertFalse(sent.contains("Working in"), sent)
        XCTAssertFalse(sent.contains("you ("), sent)
        XCTAssertTrue(sent.contains(#"{"name":"Runs as","value":"you"}"#), sent)
    }

    /// The panel shows a process's title whole. The model, and the key an answer is kept under,
    /// get the program: for the process, for its row, and where it is another's parent.
    func testATitledProcessGoesOutAndIsKeptAsItsProgram() throws {
        let title = "postgres: appuser payroll_prod db01.corp.example.com(54321) idle"
        let postgres = "/opt/pg/bin/postgres"
        let named = ProcessEntry.name(path: postgres, arguments: [title, ""], command: "postgres")
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: epoch),
            ProcessEntry(pid: 700, parentPid: 1, uid: 501, name: named.name, path: postgres, program: named.program, started: epoch),
            entry(701, 700, "/opt/pg/bin/pg_helper"),
        ]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: sign, responsible: { _ in nil }, takenAt: epoch)
        let item = try XCTUnwrap(snapshot.item(pid: 700))
        XCTAssertEqual(item.name, title, "the row keeps the title")
        XCTAssertEqual(item.explainKey, "postgres")
        XCTAssertEqual(item.facts.first { $0.name == "Process" }?.value, "\(title) (pid 700)", "and so does the detail")
        let group = try XCTUnwrap(snapshot.group(id: "pid:700"))
        XCTAssertEqual(group.name, title)
        XCTAssertEqual(group.explainKey, "postgres")
        let child = try XCTUnwrap(snapshot.item(pid: 701))
        XCTAssertEqual(child.facts.first { $0.name == "Parent" }?.value, "\(title) (pid 700)")

        for (key, facts) in [(item.explainKey, item.facts), (try XCTUnwrap(group.explainKey), group.facts), (child.explainKey, child.facts)] {
            let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .process, key: key, facts: facts), redactor: .addressesOnly)
            for word in ["appuser", "payroll_prod", "db01", "idle"] { XCTAssertFalse(sent.contains(word), sent) }
        }
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .process, key: item.explainKey, facts: item.facts), redactor: .addressesOnly)
        XCTAssertTrue(sent.contains(#"{"name":"Process","value":"postgres (pid 700)"}"#), sent)
        let fromChild = Prompt.build(instructions: "x", request: ExplainRequest(kind: .process, key: child.explainKey, facts: child.facts), redactor: .addressesOnly)
        XCTAssertTrue(fromChild.contains(#"{"name":"Parent","value":"postgres (pid 700)"}"#), fromChild)
    }

    /// A process's path, its row's and its interpreter's are known whole, so each is sent
    /// without the folders under the home.
    func testAProcessesPathGoesOutWithoutItsFolders() throws {
        let folder = "/Users/username/Clients/Acme Corp"
        let entries = [
            ProcessEntry(pid: 1, parentPid: 0, uid: 0, name: "launchd", path: "/sbin/launchd", started: epoch),
            entry(900, 1, "\(folder)/bin/server"),
            entry(901, 1, "\(folder)/venv/bin/python3", name: "serve.py", interpreter: "python3"),
        ]
        let snapshot = ProcessSnapshot.build(entries: entries, previous: nil, signature: { _ in nil }, responsible: { _ in nil }, takenAt: epoch)
        let redactor = Redactor(home: "/Users/username", username: "username", machineNames: [])
        func sent(_ key: String, _ facts: [Fact]) -> String {
            Prompt.build(instructions: "x", request: ExplainRequest(kind: .process, key: key, facts: facts), redactor: redactor)
        }
        let server = try XCTUnwrap(snapshot.item(pid: 900))
        XCTAssertEqual(server.facts.first { $0.name == "Path" }?.value, "\(folder)/bin/server", "the panel shows it whole")
        let group = try XCTUnwrap(snapshot.group(id: "pid:900"))
        let script = try XCTUnwrap(snapshot.item(pid: 901))
        for prompt in [sent(server.explainKey, server.facts), sent(try XCTUnwrap(group.explainKey), group.facts), sent(script.explainKey, script.facts)] {
            XCTAssertFalse(prompt.contains("Acme"), prompt)
            XCTAssertFalse(prompt.contains("Clients"), prompt)
        }
        XCTAssertTrue(sent(server.explainKey, server.facts).contains(#"{"name":"Path","value":"<home>/<folders>/server"}"#))
        XCTAssertTrue(sent(script.explainKey, script.facts).contains(#"{"name":"Runs with","value":"python3 (<home>/<folders>/python3)"}"#))
    }

    func testBuiltinGlossaryResolves() throws {
        let database = try AppDatabase.inMemory()
        let rules = try RuleStore(database: database)
        let repoSeeds = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Resources/knowledge")
        SeedLoader(rules: rules).load(from: repoSeeds)
        for name in ["launchd", "kernel_task", "WindowServer", "logd", "cfprefsd", "distnoted", "coreaudiod", "trustd", "nsurlsessiond",
                     "apsd", "mDNSResponder", "cloudd", "bird", "rapportd", "sharingd", "mds"] {
            let rule = try XCTUnwrap(try rules.lookup(kind: .process, key: name), name)
            XCTAssertEqual(rule.category, "system", name)
            XCTAssertEqual(rule.owner, "Apple", name)
        }
        for name in ["mds_stores", "corespotlightd", "spotlightknowledged"] {
            XCTAssertNil(try rules.lookup(kind: .process, key: name), "\(name): Apple does not document it, so the glossary does not guess")
        }
        XCTAssertEqual(try rules.lookup(kind: .process, key: "claude")?.owner, "Anthropic")
        XCTAssertNil(try rules.lookup(kind: .process, key: "Slack Helper (GPU)"))
        XCTAssertNil(try rules.lookup(kind: .process, key: "mdnsresponder"), "process names are case-sensitive")
    }

    @MainActor
    func testTheFirstReadingOfARunIsABaselineWithNoCPU() async throws {
        let observer = ProcessesObserver()
        func readAfterAPause() async throws -> ProcessSnapshot {
            try await Task.sleep(for: .milliseconds(600))
            await observer.refresh()
            return try XCTUnwrap(observer.snapshot)
        }
        await observer.refresh()
        let continuing = try await readAfterAPause()
        XCTAssertTrue(continuing.items.contains { $0.cpu != nil }, "a reading that follows another has CPU")

        observer.beginReadings()
        let baseline = try await readAfterAPause()
        XCTAssertTrue(baseline.items.allSatisfy { $0.cpu == nil }, "nothing current to compare it with")

        let next = try await readAfterAPause()
        XCTAssertTrue(next.items.contains { $0.cpu != nil }, "the reading after the baseline has CPU")
    }

    /// A signature can take a tenth of a second to read, so a build reads one per file, not one
    /// per process, and the next build reads none of them again. Counted, not timed: how long
    /// the reads take depends on the machine.
    func testThisMachine() throws {
        final class Reads: @unchecked Sendable {
            private let lock = NSLock()
            private var paths: [String] = []
            func add(_ path: String) { lock.withLock { paths.append(path) } }
            var all: [String] { lock.withLock { paths } }
        }
        let reads = Reads()
        let cache = SignatureCache(read: {
            reads.add($0)
            return CodeSignature.reading(path: $0)
        })
        func build() throws -> ProcessSnapshot {
            ProcessSnapshot.build(
                entries: try ProcessTable.read(signature: cache.signature(of:at:)), previous: nil,
                signature: cache.signature(at:), executable: cache.reading(of:at:))
        }
        let snapshot = try build()
        XCTAssertFalse(reads.all.isEmpty, "the first build reads the signatures")
        _ = try build()
        let repeated = Dictionary(grouping: reads.all, by: { $0 }).filter { $0.value.count > 1 }.keys.sorted()
        XCTAssertEqual(repeated, [], "each file's signature is read once, unless the file changed meanwhile")
        XCTAssertEqual(snapshot.groups.reduce(0) { $0 + $1.members.count }, snapshot.items.count, "every process in exactly one row")
        XCTAssertEqual(Set(snapshot.groups.map(\.id)).count, snapshot.groups.count)
        let system = try XCTUnwrap(snapshot.group(id: ProcessGroup.systemID))
        XCTAssertTrue(system.members.contains { $0.pid == 0 && $0.name == "kernel_task" })
        XCTAssertTrue(system.members.contains { $0.pid == 1 })
        XCTAssertGreaterThan(system.members.count, 100)
        XCTAssertLessThan(snapshot.groups.count, snapshot.items.count / 4, "\(snapshot.groups.count) rows for \(snapshot.items.count) processes")
        let me = try XCTUnwrap(snapshot.item(pid: getpid()))
        XCTAssertTrue(me.usage?.memoryIsFootprint == true)
    }
}
