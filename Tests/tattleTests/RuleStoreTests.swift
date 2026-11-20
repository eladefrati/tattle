import GRDB
import XCTest
@testable import tattle

final class RuleStoreTests: XCTestCase {
    func testANameCanHoldARuleWithNoIdentityAndOneForEachIdentity() throws {
        let queue = try DatabaseQueue()
        try AppDatabase.migrator.migrate(queue)
        try queue.write { db in
            try db.execute(sql: """
                INSERT INTO rule (kind, match, pattern, purpose, source, confirmed, created)
                VALUES ('process', 'exact', 'updater', 'old', 'llm', 0, 0)
                """)
            XCTAssertEqual(try Rule.fetchAll(db).first?.identity, "")
            var a = Rule(kind: .process, pattern: "updater", purpose: "a", source: .llm, identity: "team:A:x")
            var b = Rule(kind: .process, pattern: "updater", purpose: "b", source: .llm, identity: "team:B:x")
            var again = Rule(kind: .process, pattern: "updater", purpose: "a2", source: .llm, identity: "team:A:x")
            try a.upsert(db)
            try b.upsert(db)
            try again.upsert(db)
            XCTAssertEqual(try Rule.order(Column("purpose")).fetchAll(db).map(\.purpose), ["a2", "b", "old"])
        }
    }

    private var store: RuleStore!

    override func setUpWithError() throws {
        store = try RuleStore(database: try AppDatabase.inMemory())
    }

    /// Ships `rules` as the builtin seed file would, in place of those shipped before.
    private func ship(_ rules: Rule...) throws {
        try store.replaceShipped(source: .builtin, with: rules)
    }

    private func rule(
        _ pattern: String, kind: Rule.Kind = .host, match: Rule.Match = .exact,
        source: Rule.Source, purpose: String = "p", confirmed: Date? = nil,
        created: Date = Date()
    ) -> Rule {
        Rule(kind: kind, match: match, pattern: pattern, purpose: purpose,
             source: source, confirmed: confirmed, created: created)
    }

    func testExactLookupAndMiss() throws {
        try ship(rule("gateway.icloud.com", source: .builtin, purpose: "iCloud"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "gateway.icloud.com")?.purpose, "iCloud")
        XCTAssertNil(try store.lookup(kind: .host, key: "example.com"))
        XCTAssertNil(try store.lookup(kind: .process, key: "gateway.icloud.com"), "kind is part of the key")
    }

    func testGlobMatches() throws {
        try ship(rule("p*-caldav.icloud.com", match: .glob, source: .builtin, purpose: "CalDAV"),
                 rule("com.apple.*", kind: .launchItem, match: .glob, source: .builtin, purpose: "Apple"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "p61-caldav.icloud.com")?.purpose, "CalDAV")
        XCTAssertNil(try store.lookup(kind: .host, key: "p61-caldav.icloud.com.evil.net"))
        XCTAssertEqual(try store.lookup(kind: .launchItem, key: "com.apple.mdworker")?.purpose, "Apple")
    }

    func testHostsNormalizeCaseAndTrailingDot() throws {
        try ship(rule("Gateway.iCloud.com.", source: .builtin, purpose: "iCloud"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "GATEWAY.ICLOUD.COM")?.purpose, "iCloud")
        try ship(rule("/usr/bin/Foo", kind: .process, source: .builtin, purpose: "foo"))
        XCTAssertNil(try store.lookup(kind: .process, key: "/usr/bin/foo"), "process keys stay case-sensitive")
    }

    func testHostNormalizationLowercasesAsciiOnly() throws {
        // U+212A KELVIN SIGN lowercases to ASCII "k" under Unicode rules; a different
        // host must not fold onto slack.com.
        XCTAssertEqual(Rule.normalize("slac\u{212A}.COM..", for: .host), "slac\u{212A}.com")
        XCTAssertNotEqual(Rule.normalize("slac\u{212A}.com", for: .host), "slack.com")
        XCTAssertEqual(Rule.normalize("Slack.COM.", for: .host), "slack.com")
    }

    func testSourcePrecedence() throws {
        let shipped: [Rule.Source] = [.builtin, .appleList, .trackerRadar]
        for source in shipped.reversed() {
            try store.replaceShipped(source: source, with: [rule("a.example", source: source, purpose: source.rawValue)])
        }
        try store.save(rule("a.example", source: .llm, purpose: "llm"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "a.example")?.source, .builtin)
        XCTAssertEqual(try store.candidates(kind: .host, key: "a.example").map(\.source), shipped + [.llm])
    }

    func testConfirmedRuleRanksWithUser() throws {
        try ship(rule("a.example", source: .builtin, purpose: "builtin"))
        let llm = try store.save(rule("a.example", source: .llm, purpose: "llm"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "a.example")?.purpose, "builtin")

        try store.confirm(id: llm.id!)
        let best = try XCTUnwrap(try store.lookup(kind: .host, key: "a.example"))
        XCTAssertEqual(best.purpose, "llm")
        XCTAssertEqual(best.source, .llm, "provenance is kept")
        XCTAssertNotNil(best.confirmed)
    }

    func testExactBeatsGlobAndLongerGlobBeatsShorter() throws {
        let short = rule("*.icloud.com", match: .glob, source: .builtin, purpose: "short")
        let long = rule("*-caldav.icloud.com", match: .glob, source: .builtin, purpose: "long")
        try ship(short, long)
        XCTAssertEqual(try store.lookup(kind: .host, key: "p61-caldav.icloud.com")?.purpose, "long")
        try ship(short, long, rule("p61-caldav.icloud.com", source: .builtin, purpose: "exact"))
        XCTAssertEqual(try store.lookup(kind: .host, key: "p61-caldav.icloud.com")?.purpose, "exact")
    }

    func testUnconfirmedLLMRulesExpireAfter45Days() throws {
        let now = Date()
        let old = now.addingTimeInterval(-46 * 86_400)
        let fresh = now.addingTimeInterval(-44 * 86_400)
        try store.save(rule("old.example", source: .llm, created: old))
        try store.save(rule("fresh.example", source: .llm, created: fresh))
        try store.save(rule("kept.example", source: .llm, confirmed: now, created: old))
        try ship(rule("builtin.example", source: .builtin, created: old))

        XCTAssertNil(try store.lookup(kind: .host, key: "old.example", now: now), "ignored before pruning")
        XCTAssertNotNil(try store.lookup(kind: .host, key: "fresh.example", now: now))

        XCTAssertEqual(try store.pruneExpired(now: now), 1)
        XCTAssertEqual(try store.rules().map(\.pattern), ["builtin.example", "fresh.example", "kept.example"])
    }

    /// The app runs for weeks: an answer that expires after launch goes while it runs, not
    /// at the next launch.
    @MainActor
    func testAnAnswerThatExpiresAfterLaunchIsPrunedWhileTheAppRuns() async throws {
        let state = try AppState(database: try AppDatabase.inMemory(), socketTable: { [] }, pruneInterval: .milliseconds(50))
        try state.rules.save(rule("old.example", source: .llm, created: Date().addingTimeInterval(-46 * 86_400)))
        try state.rules.save(rule("fresh.example", source: .llm, created: Date()))
        let deadline = Date().addingTimeInterval(10)
        while try state.rules.rules(kind: .host).count > 1, Date() < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertEqual(try state.rules.rules(kind: .host).map(\.pattern), ["fresh.example"])
    }

    func testSaveReplacesSameKindPatternSource() throws {
        try store.save(rule("a.example", source: .llm, purpose: "first"))
        try store.save(rule("a.example", source: .llm, purpose: "second"))
        try ship(rule("a.example", source: .builtin, purpose: "builtin"))
        XCTAssertEqual(try store.rules().count, 2)
        XCTAssertEqual(try store.candidates(kind: .host, key: "a.example").map(\.purpose), ["builtin", "second"])
    }

    /// The file holds a model's answers for exact items, and memory the shipped sources'
    /// rules. What a lookup would never read is refused, not stored unread.
    func testTheStoreRefusesWhatALookupNeverReads() throws {
        for source in Rule.Source.allCases where source != .llm {
            XCTAssertThrowsError(try store.save(rule("a.example", source: source)), source.rawValue) {
                XCTAssertEqual($0 as? RuleStoreError, .notAnAnswer)
            }
        }
        XCTAssertThrowsError(try store.save(rule("*.example", match: .glob, source: .llm)), "a pattern") {
            XCTAssertEqual($0 as? RuleStoreError, .notAnAnswer)
        }
        let rows = try store.database.writer.read { try Int.fetchOne($0, sql: "SELECT COUNT(*) FROM rule") }
        XCTAssertEqual(rows, 0)
        for source in [Rule.Source.llm, .user, .iap] {
            XCTAssertThrowsError(try store.replaceShipped(source: source, with: [rule("a.example", source: source)]), source.rawValue) {
                XCTAssertEqual($0 as? RuleStoreError, .notShipped(source))
            }
        }
        XCTAssertEqual(try store.rules(), [])

        // A row another process wrote under a shipped source is not there to confirm.
        try store.database.writer.write { db in
            try db.execute(sql: """
                INSERT INTO rule (id, kind, match, pattern, purpose, source, created)
                VALUES (7, 'host', 'exact', 'a.example', 'p', 'builtin', datetime('now'))
                """)
        }
        XCTAssertThrowsError(try store.confirm(id: 7)) { XCTAssertEqual($0 as? RuleStoreError, .notFound(7)) }
    }

    /// Forgetting deletes a kept answer, confirmed or not, and nothing else: the shipped rule a
    /// confirmed answer stood before answers again, by the same precedence as before.
    func testForgettingAConfirmedAnswerLeavesTheShippedRule() throws {
        try store.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "a.example", purpose: "shipped", source: .builtin)])
        let kept = try store.save(Rule(kind: .host, pattern: "a.example", purpose: "mine", source: .llm))
        try store.confirm(id: kept.id!)
        XCTAssertEqual(try store.lookup(kind: .host, key: "a.example")?.purpose, "mine", "confirmed, it ranks above the shipped rule")
        let before = store.revision
        try store.forget(kept)
        XCTAssertEqual(try store.lookup(kind: .host, key: "a.example")?.purpose, "shipped")
        XCTAssertGreaterThan(store.revision, before, "what was derived from the answer is stale")
        XCTAssertNil(try store.confirmedRule(replacedBy: kept))

        let unconfirmed = try store.save(Rule(kind: .host, pattern: "b.example", purpose: "guess", source: .llm))
        try store.forget(unconfirmed)
        XCTAssertNil(try store.lookup(kind: .host, key: "b.example"))
        XCTAssertThrowsError(try store.forget(unconfirmed)) { XCTAssertEqual($0 as? RuleStoreError, .notFound(unconfirmed.id!)) }
    }

    /// A shipped rule's id is its row's in memory, and an answer in the file can carry the
    /// same number: forgetting the shipped rule must not delete that answer.
    func testForgettingARuleThatIsNotAnAnswerDeletesNothing() throws {
        try store.replaceShipped(source: .builtin, with: [Rule(kind: .host, pattern: "a.example", purpose: "shipped", source: .builtin)])
        let shipped = try XCTUnwrap(try store.lookup(kind: .host, key: "a.example"))
        let answer = try store.save(Rule(kind: .host, pattern: "b.example", purpose: "mine", source: .llm))
        XCTAssertEqual(shipped.id, answer.id, "the two tables number their rows alike")
        XCTAssertThrowsError(try store.forget(shipped)) { XCTAssertEqual($0 as? RuleStoreError, .notAnAnswer) }
        XCTAssertEqual(try store.lookup(kind: .host, key: "b.example")?.purpose, "mine")
        XCTAssertEqual(try store.lookup(kind: .host, key: "a.example")?.purpose, "shipped")
        XCTAssertThrowsError(try store.forget(Rule(kind: .host, pattern: "c.example", purpose: "unkept", source: .llm))) {
            XCTAssertEqual($0 as? RuleStoreError, .notAnAnswer)
        }
    }

    /// Only an answer is forgotten: a row in the file that is not one stays, as it is not read.
    func testForgetDeletesOnlyAnAnswer() throws {
        try store.database.writer.write { db in
            try db.execute(sql: "INSERT INTO rule (id, kind, match, pattern, purpose, source, identity, created) VALUES (77, 'host', 'glob', '*.example', 'p', 'llm', '', datetime('now'))")
        }
        var pattern = Rule(kind: .host, match: .glob, pattern: "*.example", purpose: "p", source: .llm)
        pattern.id = 77
        XCTAssertThrowsError(try store.forget(pattern)) { XCTAssertEqual($0 as? RuleStoreError, .notAnAnswer) }
        var claimed = pattern
        claimed.match = .exact
        XCTAssertThrowsError(try store.forget(claimed)) { XCTAssertEqual($0 as? RuleStoreError, .notFound(77)) }
        XCTAssertEqual(try store.database.writer.read { try Int.fetchOne($0, sql: "SELECT count(*) FROM rule WHERE id = 77") }, 1)
    }

    func testConfirmUnknownIdThrows() {
        XCTAssertThrowsError(try store.confirm(id: 999)) { error in
            XCTAssertEqual(error as? RuleStoreError, .notFound(999))
        }
    }

    func testFileDatabaseMigratesAndPersists() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "tattle.sqlite")

        try RuleStore(database: try AppDatabase(at: url)).save(rule("a.example", source: .llm))
        let reopened = try RuleStore(database: try AppDatabase(at: url))
        XCTAssertEqual(try reopened.rules().count, 1)
    }
}
