import Foundation

/// The item under the cursor and everything the engine already knows about it.
struct ExplainRequest: Equatable, Sendable {
    var kind: Rule.Kind
    var key: String
    /// Deterministic facts from the Identify step: signer, owner, category, declared
    /// intent. Sent with the item so the model explains them instead of guessing.
    var facts: [Fact]
    /// The item is Apple's own program by the name in its key (`ApplesProgram`).
    var isApplesProgram: Bool
    /// What tells the item's code from another's by the same key (`CodeIdentity`). Nil for a
    /// host, which is its own name, and for code nothing tells apart.
    var identity: CodeIdentity?

    /// What an answer is about: the item and its code, without the facts, which change from
    /// one reading to the next.
    struct Subject: Equatable, Sendable {
        var kind: Rule.Kind
        var key: String
        var identity: CodeIdentity?
    }

    var subject: Subject { Subject(kind: kind, key: key, identity: identity) }

    init(kind: Rule.Kind, key: String, facts: [Fact] = [], isApplesProgram: Bool = false, identity: CodeIdentity? = nil) {
        self.kind = kind
        self.key = Rule.normalize(key, for: kind)
        self.facts = facts
        self.isApplesProgram = isApplesProgram
        self.identity = identity
    }
}

struct Fact: Equatable, Sendable {
    /// A piece of a value: its words, or a path it holds, whole.
    enum Part: Equatable, Sendable {
        case text(String)
        case path(String)

        var text: String {
            switch self {
            case .text(let text), .path(let text): text
            }
        }
    }

    var name: String
    var value: String
    /// What the model is told when it must differ from what the panel shows: the panel can
    /// name the user's own account or certificate, a prompt that leaves the machine cannot.
    var promptValue: String?
    /// False for a fact only the panel shows.
    var inPrompt: Bool
    /// What the model is told of a value that holds paths, in parts, in place of the value.
    /// Text alone does not show where a path with spaces ends; known whole, a path under a
    /// home folder or on another disk is sent without its folders (`Redactor.cut`). Held apart
    /// from the words around it, a path is never searched for, however many a value holds.
    var promptParts: [Part]

    init(name: String, value: String, promptValue: String? = nil, inPrompt: Bool = true, promptParts: [Part] = []) {
        self.name = name
        self.value = value
        self.promptValue = promptValue
        self.inPrompt = inPrompt
        self.promptParts = promptParts
    }

    /// A fact the panel shows and the model is told in the same parts.
    init(name: String, parts: [Part]) {
        self.init(name: name, value: parts.map(\.text).joined(), promptParts: parts)
    }

    /// A fact whose value is one path.
    static func path(_ name: String, _ path: String) -> Fact {
        Fact(name: name, parts: [.path(path)])
    }

    static func signedBy(_ signature: CodeSignature, as name: String = "Signed by") -> Fact {
        Fact(name: name, value: signature.summary)
    }

    /// The account a process runs as; the model is not told the login name.
    static func runsAs(_ uid: uid_t) -> Fact {
        Fact(name: "Runs as", value: UserName.describe(uid), promptValue: UserName.describeForModel(uid))
    }

    /// A CPU share, or a dash when there is none yet: the row stays, so what is below it does
    /// not move. The model is told only a real share.
    static func cpu(_ share: Double?) -> Fact {
        Fact(name: "CPU", value: share.map(ProcessItem.cpuText) ?? "\u{2013}", inPrompt: share != nil)
    }
}
