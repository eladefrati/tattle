import XCTest
@testable import tattle

final class SeedLoaderTests: XCTestCase {
    private var rules: RuleStore!
    private var loader: SeedLoader!

    private let repoSeeds = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Resources/knowledge")

    override func setUpWithError() throws {
        rules = try RuleStore(database: try AppDatabase.inMemory())
        loader = SeedLoader(rules: rules)
    }

    func testRepoSeedsLoadAndRelayNamesResolve() throws {
        XCTAssertEqual(loader.load(from: repoSeeds), [.appleList, .builtin, .trackerRadar])
        for host in ["mask.icloud.com", "mask-api.icloud.com", "MASK-H2.icloud.com", "ohttp-relay.cloudflare.com"] {
            XCTAssertEqual(try rules.lookup(kind: .host, key: host)?.category, "relay", host)
        }
        XCTAssertEqual(try rules.lookup(kind: .host, key: "cloudflare-ech.com")?.category, "ech-cover")
        XCTAssertNil(try rules.lookup(kind: .host, key: "gateway.icloud.com"))
        XCTAssertTrue(try rules.rules().allSatisfy { $0.source == .builtin }, "the other seed files are empty")
    }

    /// Every detail page answers what, why and should I care; Tattle's own rules answer all three.
    func testEveryBuiltinRuleAnswersWhyAndCare() throws {
        XCTAssertTrue(loader.load(from: repoSeeds).contains(.builtin))
        let builtin = try rules.rules().filter { $0.source == .builtin }
        XCTAssertFalse(builtin.isEmpty)
        for rule in builtin {
            XCTAssertFalse(rule.why?.isEmpty ?? true, rule.pattern)
            XCTAssertFalse(rule.care?.isEmpty ?? true, rule.pattern)
        }
    }

    func testASeedRuleCarriesItsWhyAndCare() throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = #"{"source":"builtin","rules":[{"kind":"process","pattern":"a","purpose":"What.","why":"Why.","care":"Care.","risk":"low"},{"kind":"process","pattern":"b","purpose":"Only what."}]}"#
        try Data(file.utf8).write(to: folder.appending(path: "builtin.json"))
        XCTAssertEqual(loader.load(from: folder), [.builtin])
        let a = try XCTUnwrap(try rules.rules().first { $0.pattern == "a" })
        XCTAssertEqual([a.purpose, a.why, a.care], ["What.", "Why.", "Care."])
        let b = try XCTUnwrap(try rules.rules().first { $0.pattern == "b" })
        XCTAssertNil(b.why)
        XCTAssertNil(b.care)
    }

    /// A relay or cover rule makes a row read "relayed" or "name hidden", so a name that only
    /// starts like an operator's host must not reach it.
    func testRelayAndCoverRulesAreAnchoredToTheOperatorsDomains() throws {
        _ = loader.load(from: repoSeeds)
        for host in ["ohttp-relay-a.cloudflare.com", "ohttp-relay.fastly-edge.com"] {
            XCTAssertEqual(try rules.lookup(kind: .host, key: host)?.category, "relay", host)
        }
        for host in [
            "mask.evil.example", "mask.icloud.com.evil.example", "mask.icloud.com.evil.net",
            "apple-relay.c2.example", "apple-relay.apple.com.evil.example",
            "apple-relay.cloudflare.com.evil.example", "apple-relay.fastly-edge.com.evil.example",
            "ohttp-relay.evil.example", "ohttp-relay.cloudflare.com.evil.example",
            "ohttp-relay.fastly-edge.com.evil.example", "cloudflare-ech.com.evil.example",
        ] {
            XCTAssertNil(try rules.lookup(kind: .host, key: host), host)
        }
    }

    /// Apple's host list (support.apple.com/101555) names what these serve, and none is Private
    /// Relay. The two for Private Cloud Compute are third parties' relays, so they read as
    /// relayed (ADR-0001); the one for Extensions is where the traffic goes.
    func testHostsAppleNamesReadAsWhatAppleSaysTheyAre() throws {
        _ = loader.load(from: repoSeeds)
        for (host, owner) in [("apple-relay.cloudflare.com", "Cloudflare"), ("apple-relay.fastly-edge.com", "Fastly")] {
            let rule = try XCTUnwrap(try rules.lookup(kind: .host, key: host), host)
            XCTAssertEqual(ConnectionName.kind(forCategory: rule.category), .relay, host)
            XCTAssertEqual(rule.owner, owner, "a third party runs Private Cloud Compute's relay")
            XCTAssertTrue(rule.purpose.contains("Private Cloud Compute"), host)
            XCTAssertFalse(rule.purpose.contains("Private Relay"), host)
            XCTAssertFalse(rule.purpose.contains("hidden"), host)
        }
        let extensions = try XCTUnwrap(try rules.lookup(kind: .host, key: "apple-relay.apple.com"))
        XCTAssertEqual(ConnectionName.kind(forCategory: extensions.category), .destination)
        XCTAssertTrue(extensions.purpose.contains("Apple Intelligence Extensions"))
        XCTAssertFalse(extensions.purpose.contains("hidden"))
    }

    /// No source says Apple runs or uses these: their domains are the operators'.
    func testOhttpRelaysClaimNothingAboutApple() throws {
        _ = loader.load(from: repoSeeds)
        for (host, owner) in [("ohttp-relay.cloudflare.com", "Cloudflare"), ("ohttp-relay.fastly-edge.com", "Fastly")] {
            let rule = try XCTUnwrap(try rules.lookup(kind: .host, key: host), host)
            XCTAssertEqual(rule.owner, owner, host)
            XCTAssertFalse(rule.purpose.contains("Apple"), host)
            XCTAssertEqual(rule.confidence, .medium, "read from its name alone: \(host)")
        }
    }

    /// A port-wide rule (`*:udp/5353`) explains whoever binds the port, so it cannot say who
    /// that is: no owner, and no more than medium confidence.
    func testAPortWideRuleClaimsNothingAboutWhoListens() throws {
        _ = loader.load(from: repoSeeds)
        let portWide = try rules.rules().filter { $0.kind == .port && $0.match == .glob && $0.pattern.hasPrefix("*:") }
        XCTAssertFalse(portWide.isEmpty)
        for rule in portWide {
            XCTAssertNil(rule.owner, rule.pattern)
            XCTAssertNotEqual(rule.confidence, .high, rule.pattern)
        }
    }

    /// The categories the shipped rules may carry. `relay` and `ech-cover` change how a row
    /// reads (`ConnectionName.kind`); the rest only describe. A new one is added here, so a
    /// mistyped category cannot ship.
    private static let shippedCategories: Set = ["relay", "ech-cover", "system", "sharing", "developer-tool"]

    /// The loader decodes the shipped files without validating them, so this test does: a
    /// mistyped `relay` would read a relay as the destination, and two files with one source
    /// would replace each other's rules at every launch.
    func testShippedFilesUseKnownCategoriesAndOneSourceEach() throws {
        let files = try FileManager.default.contentsOfDirectory(at: repoSeeds, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
        XCTAssertFalse(files.isEmpty)
        var sources: [Rule.Source: String] = [:]
        for url in files {
            let file = try JSONDecoder().decode(SeedLoader.File.self, from: Data(contentsOf: url))
            if let other = sources[file.source] {
                XCTFail("\(url.lastPathComponent) and \(other) both carry source \(file.source.rawValue)")
            }
            sources[file.source] = url.lastPathComponent
            for entry in file.rules {
                guard let category = entry.category else { continue }
                XCTAssertTrue(Self.shippedCategories.contains(category), "\(url.lastPathComponent), \(entry.pattern): \(category)")
            }
        }
    }

    /// The shipped rules are the app's own files, read at every launch: none goes into the
    /// database, where another process could write one (ADR-0005).
    func testShippedRulesAreNotWrittenToTheDatabase() throws {
        XCTAssertEqual(loader.load(from: repoSeeds).count, 3)
        XCTAssertFalse(try rules.rules().isEmpty)
        let rows = try rules.database.writer.read { try Int.fetchOne($0, sql: "SELECT COUNT(*) FROM rule") }
        XCTAssertEqual(rows, 0)
        let hashes = try rules.database.writer.read { try Int.fetchOne($0, sql: "SELECT COUNT(*) FROM setting") }
        XCTAssertEqual(hashes, 0, "and no record of a file's last load, which another process could write too")
        XCTAssertEqual(try RuleStore(database: rules.database).rules(), [], "another launch starts with none until it loads them")
    }

    func testALaterLoadReplacesTheSourcesRules() throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appending(path: "builtin.json")

        try seed(file, ["a.example": "first", "stale.example": "going"])
        XCTAssertEqual(loader.load(from: folder), [.builtin])
        XCTAssertEqual(try rules.lookup(kind: .host, key: "a.example")?.purpose, "first")

        try seed(file, ["a.example": "second", "new.example": "fresh"])
        XCTAssertEqual(loader.load(from: folder), [.builtin])
        XCTAssertEqual(try rules.lookup(kind: .host, key: "a.example")?.purpose, "second")
        XCTAssertNil(try rules.lookup(kind: .host, key: "stale.example"))
        XCTAssertNotNil(try rules.lookup(kind: .host, key: "new.example"))
    }

    func testBadFilesAreSkippedAndMissingFolderIsFine() throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        try Data("not json".utf8).write(to: folder.appending(path: "builtin.json"))
        try Data(#"{"source":"llm","rules":[]}"#.utf8).write(to: folder.appending(path: "tracker-radar.json"))
        XCTAssertEqual(loader.load(from: folder), [], "a file that does not parse and one whose source is no seed's are skipped")
        XCTAssertEqual(loader.load(from: folder.appending(path: "missing")), [])
    }

    private func seed(_ url: URL, _ hosts: [String: String]) throws {
        let entries = hosts.map { #"{"kind":"host","pattern":"\#($0.key)","purpose":"\#($0.value)"}"# }
        try Data(#"{"source":"builtin","rules":[\#(entries.joined(separator: ","))]}"#.utf8).write(to: url)
    }
}
