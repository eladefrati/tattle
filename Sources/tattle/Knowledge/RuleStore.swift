import Foundation
import GRDB
import os

/// The knowledge base: the shipped rules, in memory, and the model's answers, in the file.
/// Any process of the user can write the file, so of its rule table only a model's answers
/// are read, each for the exact item: a row there that claims a shipped source or the user's,
/// or that holds a pattern, is not a rule (ADR-0005).
struct RuleStore: Sendable {
    let database: AppDatabase
    /// The shipped rules, where no other process writes: a database in memory, made by the
    /// file's own migrations, so its rule table has the file's columns at every version.
    private let shipped: DatabaseQueue

    init(database: AppDatabase) throws {
        self.database = database
        shipped = try DatabaseQueue()
        try AppDatabase.migrator.migrate(shipped)
    }

    /// Counts the writes through this store and its copies, so a reader that remembers
    /// answers derived from rules can tell when they may be stale.
    private let writes = OSAllocatedUnfairLock(initialState: 0)

    var revision: Int { writes.withLock { $0 } }

    private func wrote() { writes.withLock { $0 += 1 } }

    /// The sources whose rules ship with the app. Only these are held in memory.
    static let shippedSources: Set<Rule.Source> = [.builtin, .appleList, .trackerRadar]

    /// What in the file is a rule: a model's answer for the exact item. The one place that
    /// says so, for what is kept there and for what is read from it.
    private enum Answer {
        static func holds(_ rule: Rule) -> Bool { rule.source == .llm && rule.match == .exact }

        static var rows: QueryInterfaceRequest<Rule> {
            Rule.filter(Column("source") == Rule.Source.llm.rawValue && Column("match") == Rule.Match.exact.rawValue)
        }
    }

    /// Keeps a model's answer in the file, replacing an existing one with the same kind, match,
    /// pattern, source and identity. Returns the stored rule with its id. Anything else is
    /// refused: no lookup would read it. An unconfirmed rule never replaces a
    /// confirmed one of the same key: the upsert would reset the confirmation and the
    /// creation date, and a confirmed rule is the user's own.
    @discardableResult
    func save(_ rule: Rule) throws -> Rule {
        guard Answer.holds(rule) else { throw RuleStoreError.notAnAnswer }
        defer { wrote() }
        return try database.writer.write { db in
            if rule.confirmed == nil, let kept = try Self.confirmed(rule, in: db) {
                throw RuleStoreError.alreadyConfirmed(kept.id!)
            }
            var rule = rule
            try rule.upsert(db)
            return rule
        }
    }

    func confirmedRule(replacedBy rule: Rule) throws -> Rule? {
        try database.writer.read { try Self.confirmed(rule, in: $0) }
    }

    private static func confirmed(_ rule: Rule, in db: Database) throws -> Rule? {
        guard Answer.holds(rule) else { return nil }
        return try Answer.rows
            .filter(Column("kind") == rule.kind.rawValue && Column("pattern") == rule.pattern
                    && Column("identity") == rule.identity && Column("confirmed") != nil)
            .fetchOne(db)
    }

    /// The rule that explains `key`, or nil. Ties are broken by precedence rank, then
    /// exact over glob, then the longer (more specific) pattern, then the newest rule.
    /// Expired LLM rules are ignored even before they are pruned.
    func lookup(kind: Rule.Kind, key: String, now: Date = Date()) throws -> Rule? {
        try candidates(kind: kind, key: key, now: now).first
    }

    /// Every rule matching `key`, best first.
    func candidates(kind: Rule.Kind, key: String, now: Date = Date()) throws -> [Rule] {
        let key = Rule.normalize(key, for: kind)
        let answers = try database.writer.read { db in
            try Answer.rows.filter(Column("kind") == kind.rawValue && Column("pattern") == key).fetchAll(db)
        }
        return Self.bestFirst(try shipped(kind: kind, key: key) + answers.filter { !$0.isExpired(at: now) })
    }

    /// The shipped rules matching `key`, best first. Reads nothing from the file, so nothing
    /// written there, readable or not, changes the answer.
    func shippedCandidates(kind: Rule.Kind, key: String) throws -> [Rule] {
        Self.bestFirst(try shipped(kind: kind, key: Rule.normalize(key, for: kind)))
    }

    private func shipped(kind: Rule.Kind, key: String) throws -> [Rule] {
        try shipped.read { db in
            try Rule.fetchAll(
                db,
                sql: """
                    SELECT * FROM rule
                    WHERE kind = :kind
                      AND ((match = 'exact' AND pattern = :key)
                        OR (match = 'glob' AND :key GLOB pattern))
                    """,
                arguments: ["kind": kind.rawValue, "key": key])
        }
    }

    private static func bestFirst(_ rules: [Rule]) -> [Rule] {
        rules.sorted { a, b in
            if a.rank != b.rank { return a.rank < b.rank }
            if a.match != b.match { return a.match == .exact }
            if a.pattern.count != b.pattern.count { return a.pattern.count > b.pattern.count }
            return a.created > b.created
        }
    }

    /// Replaces the shipped rules of `source` with `rules`, in memory. A source that does not
    /// ship is refused: the user's rules and a model's answers are not the app's.
    func replaceShipped(source: Rule.Source, with rules: [Rule]) throws {
        guard Self.shippedSources.contains(source) else { throw RuleStoreError.notShipped(source) }
        defer { wrote() }
        try shipped.write { db in
            try Rule.filter(Column("source") == source.rawValue).deleteAll(db)
            for var rule in rules {
                rule.id = nil
                rule.source = source
                try rule.upsert(db)
            }
        }
    }

    /// Marks a model's answer confirmed. The source is kept so provenance is never lost; the
    /// rule ranks with user rules from now on. A row in the file that is not an answer is
    /// not found.
    func confirm(id: Int64, at date: Date = Date()) throws {
        defer { wrote() }
        try database.writer.write { db in
            guard var rule = try Answer.rows.filter(key: id).fetchOne(db) else {
                throw RuleStoreError.notFound(id)
            }
            rule.confirmed = date
            try rule.update(db)
        }
    }

    /// Deletes a kept model's answer, confirmed or not, so the item can be asked about again.
    /// Any other rule is refused: a shipped rule's id is its row's in memory, and the file
    /// can hold an answer under the same number. A row in the file that is not an answer is
    /// not found.
    func forget(_ rule: Rule) throws {
        guard Answer.holds(rule), let id = rule.id else { throw RuleStoreError.notAnAnswer }
        defer { wrote() }
        try database.writer.write { db in
            guard try Answer.rows.filter(key: id).deleteAll(db) > 0 else { throw RuleStoreError.notFound(id) }
        }
    }

    /// Deletes unconfirmed LLM rules older than their lifetime. Returns how many went.
    @discardableResult
    func pruneExpired(now: Date = Date()) throws -> Int {
        defer { wrote() }
        let cutoff = now.addingTimeInterval(-Rule.unconfirmedLLMLifetime)
        return try database.writer.write { db in
            try Rule
                .filter(Column("source") == Rule.Source.llm.rawValue)
                .filter(Column("confirmed") == nil)
                .filter(Column("created") < cutoff)
                .deleteAll(db)
        }
    }

    /// Every rule a lookup reads: the shipped ones and the model's answers.
    func rules(kind: Rule.Kind? = nil) throws -> [Rule] {
        var request = Rule.all()
        if let kind { request = request.filter(Column("kind") == kind.rawValue) }
        let rules = try shipped.read { try request.fetchAll($0) }
        var kept = Answer.rows
        if let kind { kept = kept.filter(Column("kind") == kind.rawValue) }
        let answers = try database.writer.read { try kept.fetchAll($0) }
        return (rules + answers).sorted { ($0.kind.rawValue, $0.pattern) < ($1.kind.rawValue, $1.pattern) }
    }
}

enum RuleStoreError: Error, Equatable {
    case notFound(Int64)
    case alreadyConfirmed(Int64)
    /// The file keeps only a model's answer for an exact item.
    case notAnAnswer
    /// Only a shipped source's rules are held in memory.
    case notShipped(Rule.Source)
}
