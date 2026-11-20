import XCTest
@testable import tattle

final class StartupSnapshotTests: XCTestCase {
    private func job(_ label: String, scope: LaunchdItem.Scope = .userAgent, program: String? = "/usr/bin/x", plist: String? = nil, triggers: [Trigger] = [.atLoad], disabled: Bool = false, placeholder: Bool = false) -> LaunchdItem {
        LaunchdItem(label: label, scope: scope, plistURL: URL(fileURLWithPath: plist ?? "/Library/LaunchAgents/\(label).plist"),
                    program: program, arguments: ["--run"], triggers: triggers, disabled: disabled,
                    associatedBundleIdentifiers: [], isPlaceholder: placeholder)
    }

    private func login(_ identifier: String, name: String, kind: LoginItem.Kind, url: String? = nil, executable: String? = nil,
                       container: String? = nil, developer: String? = nil, team: String? = nil, bundle: String? = nil,
                       enabled: Bool = true, allowed: Bool = true, legacy: Bool = false) -> LoginItem {
        LoginItem(identifier: identifier, name: name, kind: kind, developerName: developer, teamIdentifier: team,
                  bundleIdentifier: bundle, executablePath: executable, url: url, container: container,
                  enabled: enabled, allowed: allowed, hidden: false, notified: false, legacy: legacy)
    }

    /// What keeps an item from running comes before when it runs, so the sentence never says it
    /// starts under a State that says it does not.
    func testWhyHereSaysWhenItRunsOrWhatStopsIt() {
        func item(_ trigger: String?, _ state: StartupItem.State = .notLoaded, parent: String? = nil) -> StartupItem {
            StartupItem(id: "a", label: "a", group: .userAgents, name: "a", program: "/x", trigger: trigger, state: state, parent: parent, isLoginItem: false)
        }
        XCTAssertEqual(item("at login, kept running").whyHere(gone: false), "It runs at login, kept running.")
        XCTAssertEqual(item("at login, by its app", .enabled, parent: "Acme").whyHere(gone: false), "It runs at login, by its app. It belongs to Acme.")
        XCTAssertEqual(item("at login", .disabled).whyHere(gone: false), "It is disabled, so macOS does not start it.")
        XCTAssertEqual(item("at login", .off).whyHere(gone: false), "It is switched off in System Settings, so it does not run.")
        XCTAssertEqual(item("at login", .notTurnedOn).whyHere(gone: false), "Its app has not turned it on, so it does not run.")
        XCTAssertEqual(item("at login", .notTurnedOn).whyHere(gone: true), "Its app had not turned it on, so it did not run.")
        XCTAssertEqual(item("never", .placeholder).whyHere(gone: false), "Its file is empty, so nothing runs.")
        XCTAssertEqual(item(nil, .unreadable(reason: "x")).whyHere(gone: false), "Tattle could not read its file, so when it runs is not known.")
        XCTAssertEqual(item(nil, .enabled).whyHere(gone: false), "Nothing says when it runs.")
        XCTAssertEqual(item("at login", .running(pid: 1), parent: "Acme").whyHere(gone: true), "It ran at login. It belonged to Acme.")
    }

    func testJoinsRegisteredPlistAndGroupsTheRest() {
        let launchd = LaunchdReader.Result(items: [
            job("com.acme.updater"),
            job("com.other.daemon", scope: .daemon, triggers: [.keepAlive]),
            job("com.empty", placeholder: true),
            job("com.off", disabled: true),
        ], appleCount: 880, unreadable: [])
        let loginItems = [
            login("8.com.acme.updater", name: "Acme Updater", kind: .agent, url: "file:///Library/LaunchAgents/com.acme.updater.plist",
                  executable: "/usr/bin/x", container: "Acme Inc", developer: "Acme Inc", team: "TEAM1", legacy: true),
            login("Acme Inc", name: "Acme Inc", kind: .other(type: 0x20)),
            login("2.com.example.magnet", name: "Magnet", kind: .app, url: "file:///Applications/Magnet.app/", bundle: "com.example.magnet"),
            login("4.com.example.magnetLauncher", name: "magnetLauncher", kind: .loginItemHelper, url: "Contents/Library/LoginItems/magnetLauncher.app",
                  container: "2.com.example.magnet", bundle: "com.example.magnetLauncher", enabled: false, allowed: true),
            login("64.com.example.importer", name: "importer", kind: .spotlightImporter, url: "Contents/Library/Spotlight/Foo.mdimporter", container: "2.com.example.magnet", allowed: false),
            login("2.com.example.logic", name: "Logic", kind: .app, url: "file:///Applications/Logic.app/", bundle: "com.example.logic", enabled: false, allowed: true),
            login("4096.com.example.podcasts", name: "Podcasts refresh", kind: .backgroundRefresh, container: "2.com.example.logic", enabled: true, allowed: false),
        ]
        var state = LaunchctlState()
        state.gui.services = ["com.acme.updater": .init(pid: 42, lastExitStatus: nil), "com.example.magnet": .init(pid: 7, lastExitStatus: nil)]
        state.system.services = ["com.other.daemon": .init(pid: nil, lastExitStatus: 1)]
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: loginItems, state: state, signature: { path in
            path == "/usr/bin/x" ? CodeSignature(signer: .developerID(name: "Acme"), teamIdentifier: "TEAM1") : nil
        })

        XCTAssertEqual(snapshot.appleCount, 880)
        XCTAssertEqual(snapshot.items.count, 8, "developer groups and container-only apps are not rows")
        let extensions = snapshot.items(in: .extensions)
        XCTAssertEqual(extensions.map(\.name), ["importer"])
        XCTAssertEqual(extensions[0].trigger, "when Spotlight indexes its files")
        XCTAssertEqual(extensions[0].state, .off)
        XCTAssertEqual(extensions[0].parent, "Magnet")

        let updater = snapshot.items(in: .userAgents).first { $0.label == "com.acme.updater" }!
        XCTAssertEqual(updater.name, "Acme Updater", "the login-items name wins over the label")
        XCTAssertEqual(updater.state, .running(pid: 42))
        XCTAssertEqual(updater.developer, "Acme Inc")
        XCTAssertTrue(updater.isLoginItem)
        XCTAssertEqual(updater.runs, "/usr/bin/x --run")
        XCTAssertEqual(updater.trigger, "at login")
        XCTAssertEqual(updater.facts.map(\.name), ["Runs", "When", "State", "Signed by", "Team", "Developer", "Plist"])
        let prompt = Prompt.build(instructions: "", request: ExplainRequest(kind: .launchItem, key: updater.explainKey, facts: updater.facts), redactor: .addressesOnly)
        XCTAssertTrue(prompt.contains(#"{"name":"Runs","value":"/usr/bin/x (1 argument, not sent)"}"#),
                      "arguments can carry tokens and addresses: only the program goes out")
        XCTAssertEqual(snapshot.items.filter { $0.label == "com.acme.updater" }.count, 1, "joined, not duplicated")

        XCTAssertEqual(snapshot.items(in: .daemons).first?.state, .idle(lastExitStatus: 1))
        XCTAssertEqual(snapshot.items(in: .daemons).first?.trigger, "kept running")
        XCTAssertEqual(snapshot.items(in: .userAgents).first { $0.label == "com.empty" }?.state, .placeholder)
        XCTAssertEqual(snapshot.items(in: .userAgents).first { $0.label == "com.off" }?.state, .disabled)

        let apps = snapshot.items(in: .loginItems)
        XCTAssertEqual(apps.map(\.name), ["Magnet"], "only apps, as in System Settings' Open at Login")
        XCTAssertEqual(apps[0].label, "com.example.magnet")
        XCTAssertEqual(apps[0].state, .running(pid: 7))
        XCTAssertEqual(apps[0].runs, "/Applications/Magnet.app")
        let background = snapshot.items(in: .background)
        XCTAssertEqual(background.map(\.name), ["magnetLauncher", "Podcasts refresh"])
        XCTAssertEqual(background[0].state, .notTurnedOn, "allowed, but its app has not turned it on")
        XCTAssertEqual(background[0].parent, "Magnet")
        XCTAssertEqual(background[0].runs, "/Applications/Magnet.app/Contents/Library/LoginItems/magnetLauncher.app")
        XCTAssertEqual(background[1].state, .off, "set by the app but switched off by the user")
    }

    /// A helper or an agent an app registers runs only when its app has turned it on (the
    /// enabled bit) and System Settings allows it (the allowed bit). The allowed bit stays set
    /// on a record its app has not turned on, and launchd then has no job for it.
    func testARegisteredHelperOrAgentIsOnOnlyWhenItsAppTurnedItOnAndSettingsAllowIt() {
        let settingsOff = "It is switched off in System Settings, so it does not run."
        let appOff = "Its app has not turned it on, so it does not run."
        let cases: [(enabled: Bool, allowed: Bool, stopped: String?)] = [
            (true, true, nil), (true, false, settingsOff), (false, true, appOff), (false, false, appOff),
        ]
        for (enabled, allowed, stopped) in cases {
            let app = login("2.com.example.app", name: "Example", kind: .app, url: "file:///Applications/Example.app/",
                            bundle: "com.example.app", enabled: false, allowed: true)
            // As macOS records an agent registered from inside its app: no bundle id, paths
            // relative to the app.
            let agent = login("8.com.example.launcher", name: "ExampleLauncher", kind: .agent,
                              url: "Contents/Library/LaunchAgents/com.example.launcher.plist", executable: "Contents/Resources/ExampleLauncher",
                              container: "2.com.example.app", enabled: enabled, allowed: allowed)
            let helper = login("4.com.example.helper", name: "ExampleHelper", kind: .loginItemHelper,
                               url: "Contents/Library/LoginItems/ExampleHelper.app", container: "2.com.example.app",
                               bundle: "com.example.helper", enabled: enabled, allowed: allowed)
            let rows = StartupSnapshot.build(launchd: .init(items: [], appleCount: 0, unreadable: []), loginItems: [app, agent, helper],
                                             state: LaunchctlState(), signature: { _ in nil }).items(in: .background)
            XCTAssertEqual(rows.map(\.name), ["ExampleHelper", "ExampleLauncher"])
            for row in rows {
                let bits = "\(row.name), enabled \(enabled), allowed \(allowed)"
                XCTAssertEqual(row.state.text, stopped == nil ? "on" : "off", bits)
                XCTAssertEqual(row.state.isActive, stopped == nil, bits)
                XCTAssertEqual(row.whyHere(gone: false), (stopped ?? "It runs \(row.trigger ?? "").") + " It belongs to Example.", bits)
            }
        }
    }

    func testOnlyTheDaemonWithTheBrokersLabelIsTattlesBroker() {
        let launchd = LaunchdReader.Result(items: [
            job(CaptureBroker.label, scope: .daemon, plist: "/Library/LaunchDaemons/\(CaptureBroker.label).plist"),
            job(CaptureBroker.label, scope: .userAgent),
            job("com.other.daemon", scope: .daemon),
        ], appleCount: 0, unreadable: [])
        let items = StartupSnapshot.build(launchd: launchd, loginItems: [], state: LaunchctlState(), signature: { _ in nil }).items
        XCTAssertEqual(items.filter(\.isCaptureBroker).map(\.launchdScope), [.daemon])
    }

    /// Plists in different folders can carry one label, and so can a plist that could not be
    /// read, through macOS's record of it, and a registered agent whose plist is inside its
    /// app. Each is its own row with its own id, the same at every reading; the label still
    /// keys its answer.
    func testRowsSharingALabelHaveTheirOwnIds() {
        let label = "com.acme.agent"
        let unreadable = URL(fileURLWithPath: "/Library/LaunchAgents/com.acme.copy.plist")
        let launchd = LaunchdReader.Result(items: [
            job(label, scope: .userAgent, plist: "/Users/username/Library/LaunchAgents/\(label).plist"),
            job(label, scope: .globalAgent),
            job(label, scope: .daemon, plist: "/Library/LaunchDaemons/\(label).plist"),
        ], appleCount: 0, unreadable: [.init(url: unreadable, scope: .globalAgent, reason: "x")])
        let records = [
            login("8.\(label)", name: "Acme", kind: .agent, url: unreadable.absoluteString, legacy: true),
            login("16.\(label)", name: "Acme Agent", kind: .agent, bundle: label),
        ]
        func build() -> [StartupItem] {
            StartupSnapshot.build(launchd: launchd, loginItems: records, state: LaunchctlState(), signature: { _ in nil }).items
        }
        let items = build()
        XCTAssertEqual(items.count, 5)
        XCTAssertEqual(items.map(\.id), [
            "/Users/username/Library/LaunchAgents/\(label).plist", "/Library/LaunchAgents/\(label).plist",
            "/Library/LaunchDaemons/\(label).plist", unreadable.path, "16.\(label)",
        ])
        XCTAssertEqual(Set(items.map(\.label)), [label])
        XCTAssertEqual(Set(items.map(\.explainKey)), [label])
        XCTAssertEqual(build().map(\.id), items.map(\.id))
    }

    func testStartupFactKeepsTheCertificateNameOutOfItsPromptValue() throws {
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [job("com.acme.updater")], appleCount: 0, unreadable: []),
            loginItems: [], state: LaunchctlState(),
            signature: { _ in CodeSignature(signer: .development, teamIdentifier: "ABCDE12345") })
        assertPromptValues(try XCTUnwrap(snapshot.items.first).facts, runsAs: false)
    }

    func testALaunchItemThatIsNotApplesNeverReadsAsApple() throws {
        let apple: (String) -> CodeSignature? = { _ in CodeSignature(signer: .apple, identifier: "com.apple.x", teamIdentifier: nil) }
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [job("local.sqlite", program: "/usr/bin/sqlite3")], appleCount: 0, unreadable: []),
            loginItems: [
                login("1.agent", name: "registered agent", kind: .agent, executable: "/usr/bin/sqlite3"),
                login("1.daemon", name: "registered daemon", kind: .daemon, executable: "/bin/ls"),
                login("1.helper", name: "Apple's helper", kind: .loginItemHelper, executable: "/System/Applications/Passwords.app/Contents/MacOS/x"),
            ],
            state: LaunchctlState(), signature: apple)

        let item = try XCTUnwrap(snapshot.items.first { $0.label == "local.sqlite" })
        XCTAssertEqual(item.signature?.signer, .launchItem(applesProgram: "sqlite3"))
        XCTAssertEqual(item.signature?.summary, "launch item, not signed")
        XCTAssertEqual(item.facts.first { $0.name == "Signed by" }?.value, "launch item, not signed")
        XCTAssertEqual(item.facts.first { $0.name == "Runs Apple's" }?.value, "sqlite3")
        XCTAssertFalse(item.facts.contains { $0.value == "Apple" })

        let background = snapshot.items(in: .background)
        XCTAssertEqual(background.first { $0.name == "registered agent" }?.signature?.signer, .launchItem(applesProgram: "sqlite3"))
        XCTAssertEqual(background.first { $0.name == "registered daemon" }?.signature?.signer, .launchItem(applesProgram: "ls"))
        XCTAssertEqual(background.first { $0.name == "Apple's helper" }?.signature?.signer, .apple, "no plist says what it runs")
    }

    func testALaunchItemThatChangesItsRootDoesNotNameTheProgram() throws {
        var rooted = job("local.rooted", program: "/bin/ls")
        rooted.rootDirectory = "/x"
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [rooted], appleCount: 0, unreadable: []),
            loginItems: [], state: LaunchctlState(),
            signature: { _ in CodeSignature(signer: .apple) })
        let item = try XCTUnwrap(snapshot.items.first)
        XCTAssertEqual(item.signature?.signer, .launchItem(applesProgram: nil))
        XCTAssertEqual(item.signature?.summary, "launch item, not signed")
        XCTAssertFalse(item.facts.contains { $0.name == "Runs Apple's" }, "the path does not say which file runs")
    }

    /// A copy of one of Apple's programs is signed, by Apple, and reads as Processes reads it:
    /// not part of macOS, with no shield of Apple's vouching, and known to the rules by the
    /// item's command line and the copy's code, not as Apple's program.
    func testALaunchItemRunningACopyOfApplesProgramReadsAsApplesOutsideMacOS() throws {
        let copy = "/Users/username/bin/sleep"
        let signed = CodeSignature(signer: .apple, identifier: "com.apple.sleep", teamIdentifier: "APPLE12345", codeHash: "abc")
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [job("local.sleeper", program: copy)], appleCount: 0, unreadable: []),
            loginItems: [login("1.agent", name: "registered", kind: .agent, executable: copy)], state: LaunchctlState(),
            signature: { $0 == copy ? signed : nil })
        for item in snapshot.items {
            XCTAssertEqual(item.signature?.signer, .appleElsewhere, item.name)
            XCTAssertEqual(item.signature?.summary, "Apple, outside macOS")
            XCTAssertEqual(item.signature?.isVouchedFor, false, "the grey slashed shield")
            XCTAssertEqual(item.facts.first { $0.name == "Signed by" }?.value, "Apple, outside macOS")
            XCTAssertFalse(item.facts.contains { $0.name == "Runs Apple's" })
            XCTAssertEqual(item.facts.first { $0.name == "Team" }?.value, "APPLE12345", "the copy's team, as Processes shows it")
            let identity = try XCTUnwrap(item.identity, item.name)
            XCTAssertTrue(identity.text.hasPrefix("command:"), "not Apple's identity: \(identity.text)")
            XCTAssertTrue(identity.text.hasSuffix(":abc"), "the copy's code")
        }
        XCTAssertEqual(snapshot.items.count, 2)

        var rooted = job("local.rooted", program: copy)
        rooted.rootDirectory = "/x"
        let chrooted = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [rooted], appleCount: 0, unreadable: []),
            loginItems: [], state: LaunchctlState(), signature: { _ in signed })
        XCTAssertEqual(chrooted.items.first?.signature?.signer, .launchItem(applesProgram: nil), "the path does not say which file runs")
    }

    func testARegisteredItemAmongApplesDeveloperToolsReadsAsUnnamedCode() {
        let xcode = "/Applications/Xcode.app/Contents/Developer"
        let tools = "/Library/Developer/CommandLineTools"
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [], appleCount: 0, unreadable: []),
            loginItems: [
                login("1.app", name: "app", kind: .app, executable: "\(xcode)/Applications/App.app"),
                login("1.helper", name: "helper", kind: .loginItemHelper, executable: "\(tools)/usr/libexec/helper"),
                login("1.agent", name: "agent", kind: .agent, executable: "\(xcode)/usr/bin/agent"),
                login("1.extension", name: "extension", kind: .appExtension, executable: "\(xcode)/Library/X.appex"),
                login("1.publisher", name: "publisher", kind: .appExtension, executable: "\(tools)/Library/Y.appex"),
            ],
            state: LaunchctlState(),
            signature: { $0.hasSuffix("Y.appex") ? CodeSignature(signer: .developerID(name: "Acme")) : CodeSignature(signer: .apple) })
        for name in ["app", "helper", "agent", "extension"] {
            XCTAssertEqual(snapshot.items.first { $0.name == name }?.signature?.signer, .unnamed, name)
        }
        XCTAssertEqual(snapshot.items.first { $0.name == "publisher" }?.signature?.signer, .developerID(name: "Acme"))
    }

    func testARegisteredItemLinkedToOneOfApplesDeveloperToolsReadsAsUnnamedCode() throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let tool = folder.appending(path: "Fake.xctoolchain/usr/bin/agent")
        try FileManager.default.createDirectory(at: tool.deletingLastPathComponent(), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try Data().write(to: tool)
        let link = folder.appending(path: "agent")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: tool)
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [], appleCount: 0, unreadable: []),
            loginItems: [login("1.agent", name: "agent", kind: .agent, executable: link.path)],
            state: LaunchctlState(),
            signature: { _ in CodeSignature(signer: .apple) })
        XCTAssertEqual(snapshot.items.first?.signature?.signer, .unnamed)
    }

    func testALaunchItemRunningAnotherPublishersProgramKeepsItsSigner() throws {
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader.Result(items: [job("com.acme.updater")], appleCount: 0, unreadable: []),
            loginItems: [], state: LaunchctlState(),
            signature: { _ in CodeSignature(signer: .developerID(name: "Acme")) })
        let item = try XCTUnwrap(snapshot.items.first)
        XCTAssertEqual(item.signature?.signer, .developerID(name: "Acme"))
        XCTAssertFalse(item.facts.contains { $0.name == "Runs Apple's" })
    }

    func testLaunchctlOverrideAndNotLoaded() {
        let launchd = LaunchdReader.Result(items: [job("a"), job("b")], appleCount: 0, unreadable: [])
        var state = LaunchctlState()
        state.gui.overrides = ["a": true]
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil })
        XCTAssertEqual(snapshot.items.map(\.state), [.disabled, .notLoaded])
    }

    /// launchd follows its override over the plist's `Disabled`, and a job it has loaded runs
    /// whatever either says. `com.apple.ftp-proxy` has `Disabled` true, an `enabled` override
    /// and is loaded.
    func testWhatLaunchdHasLoadedWinsOverDisabled() {
        let launchd = LaunchdReader.Result(items: [
            job("plist-off-running", disabled: true), job("plist-off-idle", disabled: true),
            job("override-off-running"), job("override-on-unloaded", disabled: true),
            job("override-off-unloaded"), job("plist-off-unloaded", disabled: true),
        ], appleCount: 0, unreadable: [])
        var state = LaunchctlState()
        state.gui.services = ["plist-off-running": .init(pid: 9, lastExitStatus: nil), "plist-off-idle": .init(pid: nil, lastExitStatus: 0),
                               "override-off-running": .init(pid: 7, lastExitStatus: nil)]
        state.gui.overrides = ["plist-off-running": false, "override-off-running": true, "override-on-unloaded": false, "override-off-unloaded": true]
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil })
        XCTAssertEqual(snapshot.items.map(\.state), [
            .running(pid: 9), .idle(lastExitStatus: 0), .running(pid: 7), .notLoaded, .disabled, .disabled,
        ])
    }

    func testAJobInADomainLaunchctlCouldNotReadHasNoKnownState() {
        let launchd = LaunchdReader.Result(items: [job("loaded"), job("absent", disabled: true)], appleCount: 0, unreadable: [])
        var state = LaunchctlState()
        state.gui = LaunchctlState.domain("gui/501", printed: (status: 113, stdout: "", stderr: "Could not find domain\n"))
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil })
        let reason = "launchctl print gui/501 failed with status 113: Could not find domain"
        XCTAssertEqual(snapshot.items.map(\.state), [.unknown(reason: reason), .unknown(reason: reason)])
        XCTAssertTrue(snapshot.items[0].facts.contains(Fact(name: "Reason", value: reason)))

        XCTAssertEqual(LaunchctlState.domain("gui/501", printed: (status: 0, stdout: "", stderr: "")).unread, "launchctl print gui/501 listed no jobs")
        XCTAssertEqual(LaunchctlState.domain("gui/501", printed: nil).unread, "launchctl could not be started")
        let empty = LaunchctlState.domain("gui/501", printed: (status: 0, stdout: "gui/501 = {\n\tservices = {\n\t}\n}\n", stderr: ""))
        XCTAssertNil(empty.unread, "a domain with no jobs is read")
        XCTAssertEqual(empty.services, [:])
        let onlyDisabled = "gui/501 = {\n\tdisabled services = {\n\t\t\"a\" => disabled\n\t}\n}\n"
        XCTAssertEqual(LaunchctlState.domain("gui/501", printed: (status: 0, stdout: onlyDisabled, stderr: "")).unread,
                       "launchctl print gui/501 listed no jobs", "the disabled list is not the list of jobs")
    }

    /// An agent limited to the Background session loads in `user/<uid>`, not `gui/<uid>`.
    func testABackgroundAgentReadsTheUserDomain() throws {
        func agent(_ label: String, _ sessions: [String]) -> LaunchdItem {
            var item = job(label, plist: "/Library/LaunchAgents/\(label).plist")
            item.sessionTypes = sessions
            return item
        }
        let launchd = LaunchdReader.Result(items: [
            agent("background", ["Background"]), agent("aqua", ["Aqua"]), agent("plain", []), agent("both", ["Aqua", "Background"]),
            agent("only-gui-has-it", ["Background"]),
        ], appleCount: 0, unreadable: [])
        var state = LaunchctlState()
        state.user.services = ["background": .init(pid: 8, lastExitStatus: nil), "both": .init(pid: 9, lastExitStatus: nil), "aqua": .init(pid: 6, lastExitStatus: nil)]
        state.gui.services = ["only-gui-has-it": .init(pid: 7, lastExitStatus: nil), "plain": .init(pid: 5, lastExitStatus: nil)]
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil })
        XCTAssertEqual(snapshot.items.map(\.state), [
            .running(pid: 8), .notLoaded, .running(pid: 5), .running(pid: 9), .notLoaded,
        ], "each reads the domain its session type loads it in")
        XCTAssertEqual(snapshot.items.map(\.launchDomain), [.user, .gui, .gui, .user, .user],
                       "Load and Unload act where the job is, or where it would load")
    }

    func testAnOverrideIsReadFromTheJobsOwnDomain() {
        var item = job("background")
        item.sessionTypes = ["Background"]
        var state = LaunchctlState()
        state.gui.overrides = ["background": true]
        XCTAssertEqual(StartupSnapshot.build(launchd: .init(items: [item], appleCount: 0, unreadable: []), loginItems: [], state: state, signature: { _ in nil }).items.map(\.state), [.notLoaded])
        state.user.overrides = ["background": true]
        XCTAssertEqual(StartupSnapshot.build(launchd: .init(items: [item], appleCount: 0, unreadable: []), loginItems: [], state: state, signature: { _ in nil }).items.map(\.state), [.disabled])
    }

    /// An agent and a daemon can share a label: each is a job of its own domain, and the
    /// state of one says nothing of the other.
    func testEachDomainAnswersForItsOwnJobs() {
        let launchd = LaunchdReader.Result(items: [
            job("com.shared"), job("com.shared", scope: .globalAgent, plist: "/Library/LaunchAgents/other.plist"),
            job("com.shared", scope: .daemon, plist: "/Library/LaunchDaemons/com.shared.plist"),
            job("com.off", scope: .daemon, plist: "/Library/LaunchDaemons/com.off.plist"),
        ], appleCount: 0, unreadable: [])
        var state = LaunchctlState()
        state.gui.services = ["com.shared": .init(pid: 5, lastExitStatus: nil), "com.helper": .init(pid: 11, lastExitStatus: nil)]
        state.gui.overrides = ["com.off": true]
        state.gui.jobPaths = ["com.shared": "/Library/LaunchAgents/com.shared.plist"]
        state.system.overrides = ["com.shared": true]
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [
            login("16.com.helper", name: "Helper", kind: .daemon, url: "file:///x/com.helper.plist", bundle: "com.helper", allowed: true),
            login("8.com.helper", name: "Helper agent", kind: .agent, url: "file:///x/com.helper.agent.plist", bundle: "com.helper", allowed: true),
        ], state: state, signature: { _ in nil })
        XCTAssertEqual(snapshot.items.prefix(4).map(\.state), [.running(pid: 5), .notLoaded, .disabled, .notLoaded])
        XCTAssertEqual(snapshot.items.first { $0.name == "Helper agent" }?.state, .running(pid: 11))
        XCTAssertEqual(snapshot.items.first { $0.name == "Helper" }?.state, .enabled, "the daemon's domain has no such job running")
    }

    /// launchd holds one job per label in a domain. When two plists carry the label, the job is
    /// the one launchd says it loaded from; the other row is not loaded and offers no Load
    /// launchd would refuse. When launchd does not say, neither row reads as running.
    func testOnlyThePlistLaunchdLoadedFromReadsAsLoaded() throws {
        let label = "com.acme.agent"
        let a = "/Users/username/Library/LaunchAgents/a.plist", b = "/Library/LaunchAgents/b.plist"
        let launchd = LaunchdReader.Result(items: [
            job(label, scope: .userAgent, plist: a), job(label, scope: .globalAgent, plist: b),
            job(label, scope: .daemon, plist: "/Library/LaunchDaemons/\(label).plist"), job("com.alone"),
        ], appleCount: 0, unreadable: [])
        XCTAssertEqual(launchd.sharedLabels, [.gui: [label]], "an agent and a daemon are in different domains")
        func rows(loadedFrom path: String?, disabled: Bool = false) -> [StartupItem] {
            var state = LaunchctlState()
            state.gui.services = [label: .init(pid: 5, lastExitStatus: nil), "com.alone": .init(pid: 6, lastExitStatus: nil)]
            state.gui.jobPaths = path.map { [label: $0] } ?? [:]
            if disabled { state.gui.overrides = [label: true] }
            return StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil }).items
        }

        let fromB = rows(loadedFrom: b)
        XCTAssertEqual(fromB.map(\.state), [.notLoaded, .running(pid: 5), .notLoaded, .running(pid: 6)])
        XCTAssertEqual(fromB.map(\.labelHeldBy), [b, nil, nil, nil])
        XCTAssertEqual(fromB[0].facts.last, Fact(name: "Label held by", value: b, inPrompt: false))
        let prompt = Prompt.build(instructions: "", request: ExplainRequest(kind: .launchItem, key: fromB[0].explainKey, facts: fromB[0].facts),
                                  redactor: .addressesOnly)
        XCTAssertFalse(prompt.contains("Label held by"), "launchd's text stays on the page")
        XCTAssertFalse(prompt.contains(b))
        XCTAssertEqual(rows(loadedFrom: a).map(\.state).prefix(2), [.running(pid: 5), .notLoaded])

        let unknown = rows(loadedFrom: nil)
        XCTAssertEqual(unknown.prefix(2).map(\.state.text), ["state not known", "state not known"])
        XCTAssertFalse(unknown.contains { $0.label == label && $0.state.isActive })

        let submitted = rows(loadedFrom: "(submitted by Acme[42])")
        XCTAssertEqual(submitted.prefix(2).map(\.state), [.notLoaded, .notLoaded])
        XCTAssertEqual(submitted.prefix(2).map(\.labelHeldBy), ["(submitted by Acme[42])", "(submitted by Acme[42])"])
        XCTAssertEqual(rows(loadedFrom: b, disabled: true)[0].state, .disabled, "the override is the label's, whoever holds it")
    }

    /// An empty plist's label is its file's name, and launchd loads nothing from it: a job
    /// beside it with that label is the only one, its state read without asking for its path.
    func testAnEmptyPlistSharesNoLabel() {
        let launchd = LaunchdReader.Result(items: [
            job("com.acme.agent"), job("com.acme.agent", plist: "/Users/username/Library/LaunchAgents/com.acme.agent.plist", placeholder: true),
        ], appleCount: 0, unreadable: [])
        XCTAssertEqual(launchd.sharedLabels, [:])
        var state = LaunchctlState()
        state.gui.services = ["com.acme.agent": .init(pid: 5, lastExitStatus: nil)]
        let items = StartupSnapshot.build(launchd: launchd, loginItems: [], state: state, signature: { _ in nil }).items
        XCTAssertEqual(items.map(\.state), [.running(pid: 5), .placeholder])
    }

    /// A plist only root can read still runs as a job: its row stays in its group, saying so.
    func testAPlistThatCannotBeReadIsARowOfItsGroup() throws {
        let url = URL(fileURLWithPath: "/Library/LaunchDaemons/com.acme.helper.plist")
        let launchd = LaunchdReader.Result(items: [], appleCount: 0, unreadable: [
            .init(url: url, scope: .daemon, reason: "Tattle has no permission to read this file"),
        ])
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: LaunchctlState(), signature: { _ in nil })
        let row = try XCTUnwrap(snapshot.items(in: .daemons).first)
        XCTAssertEqual(row.name, "com.acme.helper")
        XCTAssertEqual(row.state.text, "could not be read")
        XCTAssertEqual(row.plistURL, url)
        XCTAssertEqual(row.launchdScope, .daemon)
        XCTAssertFalse(row.canExplain, "Tattle knows only the file's name")
        let facts = Dictionary(uniqueKeysWithValues: row.facts.map { ($0.name, $0.value) })
        XCTAssertEqual(facts["Reason"], "Tattle has no permission to read this file")
        XCTAssertEqual(facts["Plist"], url.path)
        XCTAssertNil(row.identity)
    }

    /// A startup item's program, plist and watched paths are known whole, so each is sent
    /// without the folders under a home: a client's or a cloud drive's name.
    func testAStartupItemsPathsGoOutWithoutTheirFolders() throws {
        let folder = "/Users/username/Library/CloudStorage/GoogleDrive-name@example.com/My Drive/Client Acme"
        let job = job("com.acme.sync", program: "\(folder)/bin/sync", plist: "/Users/username/Library/LaunchAgents/com.acme.sync.plist",
                      triggers: [.atLoad, .watchPaths(["\(folder)/inbox", "/etc/hosts"])])
        let snapshot = StartupSnapshot.build(launchd: .init(items: [job], appleCount: 0, unreadable: []), loginItems: [], state: LaunchctlState(), signature: { _ in nil })
        let item = try XCTUnwrap(snapshot.items.first)
        let shown = Dictionary(item.facts.map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(shown["When"], "at login, when \(folder)/inbox, /etc/hosts change", "the panel shows them whole")
        XCTAssertEqual(shown["Runs"], "\(folder)/bin/sync --run")

        let redactor = Redactor(home: "/Users/username", username: "username", machineNames: [])
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .launchItem, key: item.explainKey, facts: item.facts), redactor: redactor)
        for word in ["name@example.com", "GoogleDrive", "My Drive", "Acme"] { XCTAssertFalse(sent.contains(word), sent) }
        XCTAssertTrue(sent.contains(#"{"name":"Runs","value":"<home>/Library/CloudStorage/<folders>/sync (1 argument, not sent)"}"#), sent)
        XCTAssertTrue(sent.contains(#"{"name":"When","value":"at login, when <home>/Library/CloudStorage/<folders>/inbox, /etc/hosts change"}"#), sent)
        XCTAssertTrue(sent.contains(#"{"name":"Plist","value":"<home>/Library/LaunchAgents/com.acme.sync.plist"}"#), sent)
    }

    /// A watched folder that is a disk or an account, under a Volumes or a Users folder in the
    /// home, goes out as the placeholder a path in any text gets.
    func testAWatchedDiskOrAccountUnderTheHomeGoesOutAsAPlaceholder() throws {
        let job = job("com.acme.sync", triggers: [.watchPaths(["/Users/username/Volumes/ClientNAS", "/Users/username/Users/someone"])])
        let snapshot = StartupSnapshot.build(launchd: .init(items: [job], appleCount: 0, unreadable: []), loginItems: [], state: LaunchctlState(), signature: { _ in nil })
        let item = try XCTUnwrap(snapshot.items.first)
        let redactor = Redactor(home: "/Users/username", username: "username", machineNames: [])
        let sent = Prompt.build(instructions: "x", request: ExplainRequest(kind: .launchItem, key: item.explainKey, facts: item.facts), redactor: redactor)
        XCTAssertTrue(sent.contains(#"{"name":"When","value":"when <home>/Volumes/<volume>, <home>/Users/<other-user> change"}"#), sent)
    }

    /// A plist's author picks how many paths its job watches. Each is held apart from the
    /// words around it, so none is searched for: four times the paths take about four times as
    /// long to send, not sixteen.
    func testAPromptForManyWatchedPathsTakesTimeInProportionToThem() throws {
        let redactor = Redactor(home: "/Users/username", username: "username", machineNames: [])
        func seconds(paths count: Int) throws -> Double {
            let watched = (0..<count).map { "/Users/username/Clients/Acme \($0)/inbox/item \($0)" }
            let snapshot = StartupSnapshot.build(launchd: .init(items: [job("com.acme.sync", triggers: [.watchPaths(watched)])], appleCount: 0, unreadable: []),
                                                 loginItems: [], state: LaunchctlState(), signature: { _ in nil })
            let item = try XCTUnwrap(snapshot.items.first)
            let request = ExplainRequest(kind: .launchItem, key: item.explainKey, facts: item.facts)
            let clock = ContinuousClock()
            // The best of three: another process's work is not this one's.
            let runs = (0..<3).map { _ in
                clock.measure { XCTAssertTrue(Prompt.build(instructions: "x", request: request, redactor: redactor).contains("<home>/<folders>/item 0")) }
            }
            let best = try XCTUnwrap(runs.min()).components
            return Double(best.seconds) + Double(best.attoseconds) / 1e18
        }
        let (few, many) = (try seconds(paths: 1_000), try seconds(paths: 4_000))
        XCTAssertLessThan(many, few * 8, "\(few) s for 1,000 paths, \(many) s for 4,000")
    }

    /// Whatever is in a folder that cannot be listed is unknown: the group says so.
    func testAFolderThatCannotBeListedIsARowOfItsGroup() throws {
        let url = URL(fileURLWithPath: "/Library/LaunchDaemons")
        let launchd = LaunchdReader.Result(items: [], appleCount: 0, unreadable: [.init(url: url, scope: .daemon, reason: "why", isFolder: true)])
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [], state: LaunchctlState(), signature: { _ in nil })
        let row = try XCTUnwrap(snapshot.items(in: .daemons).first)
        XCTAssertEqual(row.name, "LaunchDaemons")
        XCTAssertEqual(row.state.text, "could not be listed")
        XCTAssertEqual(row.plistURL, url)
        XCTAssertNil(row.launchdScope, "a folder has no job to load or unload")
        XCTAssertFalse(row.canExplain)
        let facts = Dictionary(uniqueKeysWithValues: row.facts.map { ($0.name, $0.value) })
        XCTAssertEqual(facts["Reason"], "why")
        XCTAssertEqual(facts["Folder"], url.path)
        XCTAssertNil(facts["Plist"])
    }

    /// With Full Disk Access macOS has a record for every plist in these folders. The row is
    /// still the unreadable plist's, in its group, and takes what the record knows.
    func testAnUnreadablePlistMacOSRegisteredStaysInItsGroupWithWhatTheRecordKnows() throws {
        let url = URL(fileURLWithPath: "/Library/LaunchDaemons/com.acme.helper.plist")
        let launchd = LaunchdReader.Result(items: [], appleCount: 0, unreadable: [.init(url: url, scope: .daemon, reason: "x")])
        let signed = CodeSignature(signer: .developerID(name: "Acme"), teamIdentifier: "TEAM1")
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [
            login("16.com.acme.helper", name: "Acme Helper", kind: .daemon, url: url.absoluteString, executable: "/usr/bin/x",
                  developer: "Acme Inc", team: "TEAM1", legacy: true),
        ], state: LaunchctlState(), signature: { $0 == "/usr/bin/x" ? signed : nil })
        XCTAssertEqual(snapshot.items.count, 1, "the record is not a second row")
        let row = try XCTUnwrap(snapshot.items(in: .daemons).first)
        XCTAssertEqual(row.name, "Acme Helper")
        XCTAssertEqual(row.state, .unreadable(reason: "x"))
        XCTAssertEqual(row.program, "/usr/bin/x")
        XCTAssertEqual(row.signature, signed)
        XCTAssertEqual(row.developer, "Acme Inc")
        XCTAssertNil(row.trigger, "the plist says when it runs, and it was not read")
        XCTAssertEqual(row.plistURL, url)
        XCTAssertEqual(row.launchdScope, .daemon)
        XCTAssertTrue(row.isLoginItem)
        XCTAssertTrue(row.canExplain, "the record says what runs")
    }

    /// An answer is filed under the job's label, the key the row has once the plist is
    /// readable. A legacy record has no bundle identifier: it keeps the label after its type.
    func testAnUnreadablePlistIsKeyedByTheLabelMacOSRecorded() {
        let url = URL(fileURLWithPath: "/Library/LaunchDaemons/com.acme.helper.plist")
        let launchd = LaunchdReader.Result(items: [], appleCount: 0, unreadable: [.init(url: url, scope: .daemon, reason: "x")])
        func key(_ records: [LoginItem]) -> String? {
            StartupSnapshot.build(launchd: launchd, loginItems: records, state: LaunchctlState(), signature: { _ in nil }).items(in: .daemons).first?.explainKey
        }
        XCTAssertEqual(key([login("16.com.acme.helper", name: "Acme", kind: .daemon, url: url.absoluteString, legacy: true)]), "com.acme.helper")
        XCTAssertEqual(key([login("16.com.acme.helper", name: "Acme", kind: .daemon, url: url.absoluteString, bundle: "com.acme.job", legacy: true)]), "com.acme.job")
        XCTAssertEqual(key([]), url.path, "with no record, the file is all there is")
    }

    /// A legacy record whose plist the reader did not find is keyed like one whose plist it
    /// could not read: by the label, not by the record's type-numbered identifier.
    func testARecordWithNoPlistIsKeyedByItsLabel() {
        func key(_ record: LoginItem) -> String? {
            StartupSnapshot.build(launchd: LaunchdReader.Result(items: [], appleCount: 0, unreadable: []), loginItems: [record],
                                  state: LaunchctlState(), signature: { _ in nil }).items.first?.explainKey
        }
        XCTAssertEqual(key(login("8.com.acme.agent", name: "Acme", kind: .agent, legacy: true)), "com.acme.agent")
        XCTAssertEqual(key(login("8.com.acme.agent", name: "Acme", kind: .agent, bundle: "com.acme.job", legacy: true)), "com.acme.job")
        XCTAssertEqual(key(login("2.com.acme.app", name: "Acme", kind: .app, bundle: "com.acme.app")), "com.acme.app")
    }

    /// A legacy record of a kind Tattle does not list gives no row of its own.
    func testARecordOfAnUnknownKindDoesNotHideAnUnreadablePlist() {
        let url = URL(fileURLWithPath: "/Library/LaunchAgents/com.acme.agent.plist")
        let launchd = LaunchdReader.Result(items: [], appleCount: 0, unreadable: [.init(url: url, scope: .globalAgent, reason: "x")])
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [
            login("64.com.acme.agent", name: "Acme", kind: .other(type: 0x40), url: url.absoluteString, legacy: true),
        ], state: LaunchctlState(), signature: { _ in nil })
        XCTAssertEqual(snapshot.items(in: .globalAgents).map(\.state), [.unreadable(reason: "x")])
    }

    /// macOS keeps the record of a plist whose label has since changed beside the record for
    /// the new label. The job takes the record that carries its label, and neither is a
    /// second row.
    func testTwoRecordsForOnePlistAreOneRowNamedByTheRecordWithTheJobsLabel() throws {
        let url = "file:///Library/LaunchAgents/com.acme.agent.plist"
        let launchd = LaunchdReader.Result(items: [job("com.acme.agent", scope: .globalAgent)], appleCount: 0, unreadable: [])
        let stale = login("8.com.acme.launcher", name: "Acme Launcher", kind: .agent, url: url, developer: "Acme Old", legacy: true)
        let current = login("8.com.acme.agent", name: "Acme Agent", kind: .agent, url: url, developer: "Acme Inc", legacy: true)
        for records in [[stale, current], [current, stale]] {
            let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: records, state: LaunchctlState(), signature: { _ in nil })
            XCTAssertEqual(snapshot.items.count, 1, "neither record is a second row")
            let row = try XCTUnwrap(snapshot.items(in: .globalAgents).first)
            XCTAssertEqual(row.label, "com.acme.agent")
            XCTAssertEqual(row.name, "Acme Agent")
            XCTAssertEqual(row.developer, "Acme Inc")
            XCTAssertTrue(row.isLoginItem)
        }
        // With no record under the job's label, the first one names it.
        let snapshot = StartupSnapshot.build(launchd: launchd, loginItems: [stale], state: LaunchctlState(), signature: { _ in nil })
        XCTAssertEqual(snapshot.items.map(\.name), ["Acme Launcher"])
    }

    func testThisMachineBuilds() throws {
        // Without Full Disk Access the app builds from the launchd jobs alone, and so does this.
        let loginItems: [LoginItem]
        do {
            loginItems = try LoginItemsDatabase.readCurrent().items
        } catch LoginItemsDatabase.ReadError.cannotList(_), LoginItemsDatabase.ReadError.noDatabase {
            loginItems = []
        }
        let cache = SignatureCache()
        let snapshot = StartupSnapshot.build(
            launchd: LaunchdReader().read(), loginItems: loginItems,
            state: LaunchctlState.read(), signature: cache.signature(at:))
        XCTAssertFalse(snapshot.items.isEmpty)
        XCTAssertEqual(Set(snapshot.items.map(\.id)).count, snapshot.items.count, "ids are unique")
        XCTAssertTrue(snapshot.items.contains { $0.signature != nil }, "signatures are read")
    }

    private func identity(_ program: String, _ arguments: [String], reading: @escaping (String) -> CodeSignature?) throws -> CodeIdentity? {
        var item = job("a", program: program)
        item.arguments = arguments
        let snapshot = StartupSnapshot.build(launchd: LaunchdReader.Result(items: [item], appleCount: 0, unreadable: []), loginItems: [],
                                             state: LaunchctlState(), signature: reading)
        return try XCTUnwrap(snapshot.items.first).identity
    }

    /// An answer goes with one version of the code. A line that holds its code is that
    /// version; one that does not say where its code is has none to keep an answer for.
    func testALaunchItemIsKnownByItsLineOnlyWhenItsLineHoldsItsCode() throws {
        let apple: (String) -> CodeSignature? = { CodeSignature(signer: .apple, identifier: "com.apple." + URL(fileURLWithPath: $0).lastPathComponent) }
        let elsewhere: [(String, [String])] = [
            ("/usr/bin/env", ["-S", "/x/job"]),
            ("/usr/bin/env", ["./job"]),
            ("/bin/sh", []),
            ("/usr/bin/python3", ["-m", "pkg"]),
            ("/usr/bin/java", ["-cp", "/x", "Main"]),
            ("/usr/bin/java", ["-m", "pkg"]),
            ("/usr/bin/php", ["-S", "localhost:80"]),
            ("/usr/bin/node", ["--run", "serve"]),
            ("/usr/bin/node", ["."]),
            ("/usr/bin/make", []),
        ]
        for (program, arguments) in elsewhere {
            XCTAssertNil(try identity(program, arguments, reading: apple), "\(program) \(arguments)")
        }
        let held: [(String, [String])] = [
            ("/bin/sh", ["-c", "echo"]),
            ("/usr/bin/python3", ["-c", "pass"]),
            ("/usr/bin/perl", ["-e", "1"]),
            ("/usr/bin/php", ["-r", "1;"]),
            ("/usr/bin/node", ["--eval", "1"]),
            ("/usr/bin/osascript", ["-e", "1"]),
            ("/usr/bin/awk", ["{ print }"]),
            ("/usr/bin/nohup", ["/bin/sh", "-c", "echo"]),
        ]
        for (program, arguments) in held {
            XCTAssertEqual(try identity(program, arguments, reading: apple), CodeIdentity.command(([program] + arguments).joined(separator: " ")), "\(program) \(arguments)")
        }
    }

    /// Only macOS installs a program in those folders, and an update rebuilds it: the line says
    /// all there is. A copy elsewhere keeps Apple's signature and is a file like any other.
    func testALaunchItemRunningOneOfApplesProgramsIsNotPinnedToOneBuild() throws {
        func signed(_ hash: String) -> (String) -> CodeSignature? {
            { _ in CodeSignature(signer: .apple, identifier: "com.apple.sleep", codeHash: hash) }
        }
        XCTAssertEqual(try identity("/bin/sleep", ["100"], reading: signed("aa")), CodeIdentity.command("/bin/sleep 100"))
        XCTAssertEqual(try identity("/bin/sleep", ["100"], reading: signed("bb")), CodeIdentity.command("/bin/sleep 100"))
        XCTAssertNotEqual(try identity("/Users/x/sleep", ["100"], reading: signed("aa")), try identity("/Users/x/sleep", ["100"], reading: signed("bb")))
    }

    func testARegisteredItemRunningOneOfApplesProgramsIsNotPinnedToOneBuild() throws {
        func identity(_ item: LoginItem, _ hash: String) throws -> CodeIdentity? {
            let snapshot = StartupSnapshot.build(launchd: LaunchdReader.Result(items: [], appleCount: 0, unreadable: []), loginItems: [item],
                                                 state: LaunchctlState(),
                                                 signature: { _ in CodeSignature(signer: .apple, identifier: "com.apple.x", codeHash: hash) })
            return try XCTUnwrap(snapshot.items.first).identity
        }
        for item in [login("1.agent", name: "agent", kind: .agent, executable: "/usr/sbin/x"),
                     login("1.helper", name: "helper", kind: .loginItemHelper, executable: "/System/Applications/Passwords.app/Contents/MacOS/x")] {
            XCTAssertEqual(try identity(item, "aa"), try identity(item, "bb"), item.name)
            XCTAssertNil(try identity(item, "aa")?.contentFile, item.name)
        }
        let copy = login("1.copy", name: "copy", kind: .agent, executable: "/Users/x/agent")
        XCTAssertNotEqual(try identity(copy, "aa"), try identity(copy, "bb"))
    }

    func testStateText() {
        XCTAssertEqual(StartupItem.State.running(pid: 3).text, "running, pid 3")
        XCTAssertEqual(StartupItem.State.idle(lastExitStatus: 0).text, "not running")
        XCTAssertEqual(StartupItem.State.idle(lastExitStatus: -9).text, "not running, last exit -9")
        XCTAssertTrue(StartupItem.State.enabled.isActive)
        XCTAssertFalse(StartupItem.State.off.isActive)
    }
}
