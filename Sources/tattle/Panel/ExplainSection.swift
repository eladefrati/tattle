import SwiftUI

/// The explanation for one item, as three answers: what it is, why it is probably here, and
/// whether to care. The knowledge base's answer, or a button that asks the model,
/// confirmation of an unconfirmed answer, and a way to forget a kept one. Shared by every
/// tab's detail view.
struct ExplainSection: View {
    let request: ExplainRequest
    /// The app's own sentence that opens "Why it is probably here", from the facts.
    let whyHere: String?
    let state: AppState
    @State private var rule: Rule?
    /// The code `rule` was asked about, when the answer was the model's in this view.
    @State private var answered: CodeIdentity?
    /// The item on screen. A running task sees the `request` it started with, so an answer
    /// that arrives late is checked against this.
    @State private var shown: ExplainRequest.Subject?
    @State private var busy = false
    @State private var error: String?
    /// Forget was pressed once: the next press deletes the kept answer.
    @State private var forgetting = false
    /// When the row's buttons last changed, as the Mac's uptime.
    @State private var changed: TimeInterval?

    var body: some View {
        Card {
            question("What is this", rule?.purpose)
            RowLine()
            // Before there is an answer the app's own sentence still stands, and the other
            // two say that they are waiting.
            if let rule {
                if let why = Self.why(rule, opening: whyHere) {
                    question("Why it is probably here", why)
                    RowLine()
                }
                if let care = Self.care(rule) {
                    question("Should I care", care)
                    RowLine()
                }
            } else {
                question("Why it is probably here", whyHere)
                RowLine()
                question("Should I care", nil)
                RowLine()
            }
            let controls = Self.controls(for: rule, forgetting: forgetting)
            VStack(alignment: .leading, spacing: 5) {
                // What a kept answer is stands on a line of its own, and Forget at the row's
                // other end from the buttons that keep it.
                if let rule, !controls.leading.isEmpty {
                    Text(provenance(rule))
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.sub)
                }
                HStack(spacing: 8) {
                    if controls.leading.isEmpty {
                        Text(rule.map(provenance) ?? "No explanation yet.")
                            .font(PanelFont.small)
                            .foregroundStyle(PanelColor.sub)
                    } else {
                        ForEach(controls.leading, id: \.self) { button($0) }
                    }
                    Spacer(minLength: 0)
                    if busy { ProgressView().controlSize(.small) }
                    ForEach(controls.trailing, id: \.self) { button($0) }
                }
                .onChange(of: controls) { changed = ProcessInfo.processInfo.systemUptime }
                .frame(minHeight: 22)
                if rule == nil && !providerConfigured {
                    Text("Choose a provider in Settings to ask a model.")
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.sub)
                }
                if let error {
                    Text(error)
                        .font(PanelFont.small)
                        .foregroundStyle(PanelColor.bad)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
        .task(id: request) { await load() }
    }

    /// A button of the answer's row.
    enum Control: Hashable {
        case explain, askAgain, confirm, forget, cancel, forgetAnswer
    }

    /// The row's buttons: Forget's at its leading edge, the others at its trailing one.
    struct Controls: Equatable {
        var leading: [Control]
        var trailing: [Control]
    }

    /// The buttons an answer's row holds. Only a kept answer, confirmed or not, can be
    /// forgotten: one shown only in this view has nothing to forget, and no other rule is the
    /// user's to delete. Pressed once, Forget leaves only its own two buttons.
    static func controls(for rule: Rule?, forgetting: Bool) -> Controls {
        guard let rule else { return Controls(leading: [], trailing: [.explain]) }
        let isModels = rule.source == .llm
        let isKept = isModels && rule.id != nil
        if isKept && forgetting { return Controls(leading: [.cancel, .forgetAnswer], trailing: []) }
        let asks: [Control] = isModels && rule.confirmed == nil ? (isKept ? [.askAgain, .confirm] : [.askAgain]) : []
        return Controls(leading: isKept ? [.forget] : [], trailing: asks)
    }

    /// Whether a press counts. One that follows a change of the row's buttons sooner than a
    /// double click's second press was aimed at the button that stood there before. Both
    /// times are the Mac's uptime, which setting the clock does not move; a press timed
    /// before the change counts, so no reading can leave the buttons dead.
    static func counts(pressAt now: TimeInterval, changed: TimeInterval?, interval: TimeInterval) -> Bool {
        guard let changed else { return true }
        let since = now - changed
        return since < 0 || since >= interval
    }

    /// Runs a button's action unless the press came straight after the row's buttons changed:
    /// a double press then does what one press does, whichever button took the first one's place.
    private func press(_ action: () -> Void) {
        guard Self.counts(pressAt: ProcessInfo.processInfo.systemUptime, changed: changed, interval: NSEvent.doubleClickInterval) else { return }
        action()
    }

    @ViewBuilder
    private func button(_ control: Control) -> some View {
        switch control {
        case .explain:
            Button("Explain") { press { ask() } }
                .buttonStyle(PanelButtonStyle(kind: .primary, height: 22))
                .disabled(busy || !providerConfigured)
        case .askAgain:
            Button("Ask again") { press { ask() } }
                .buttonStyle(PanelButtonStyle(height: 22))
                .disabled(busy || !providerConfigured)
        case .confirm:
            Button("Confirm") { press { if let rule { confirm(rule) } } }
                .buttonStyle(PanelButtonStyle(kind: .primary, height: 22))
        case .forget:
            Button("Forget\u{2026}") { press { forgetting = true } }
                .buttonStyle(PanelButtonStyle(height: 22))
                .disabled(busy)
        case .cancel:
            Button("Cancel") { press { forgetting = false } }
                .buttonStyle(PanelButtonStyle(height: 22))
        case .forgetAnswer:
            Button("Forget answer") { press { if let rule { forget(rule) } } }
                .buttonStyle(PanelButtonStyle(kind: .danger, height: 22))
        }
    }

    /// One question with its answer, or with the words that stand in for one.
    private func question(_ heading: String, _ answer: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(heading)
                .font(PanelFont.smallBold)
                .foregroundStyle(PanelColor.sub)
                .accessibilityAddTraits(.isHeader)
            Text(answer ?? "Not explained yet.")
                .foregroundStyle(answer == nil ? PanelColor.sub : PanelColor.text)
                .lineSpacing(2)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// The app's sentence from the facts, then the rule's. A host's rule is asked not to say which
    /// program opened the connection: the app's sentence does.
    static func why(_ rule: Rule?, opening: String?) -> String? {
        joined([opening, rule?.why])
    }

    /// The words the app picks from the rule's risk, then the rule's reason. The app picks them
    /// so they never disagree with the risk shown under them; none when the rule has no risk or
    /// was a guess.
    static func care(_ rule: Rule) -> String? {
        joined([verdict(rule), rule.care])
    }

    static func verdict(_ rule: Rule) -> String? {
        guard let risk = rule.risk, rule.confidence != .low else { return nil }
        switch risk {
        case .low: return "Probably not."
        case .medium: return "Worth a look."
        case .high: return "Yes."
        }
    }

    private static func joined(_ parts: [String?]) -> String? {
        let parts = parts.compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    private var providerConfigured: Bool {
        !state.settings.providerCommand.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func load() async {
        // Another item, or other code under the name: the press was about the answer before.
        if shown != request.subject { forgetting = false }
        shown = request.subject
        let unkept = Self.unkept(rule, givenFor: answered, request: request)
        let found = try? await state.explainer.lookup(request)
        guard !Task.isCancelled else { return }
        // The answer the first press was about is gone or replaced: the second would be
        // about another rule.
        if found?.id != rule?.id { forgetting = false }
        rule = Self.shown(kept: found, unkept: unkept)
    }

    /// The answer the view shows: the knowledge base's, or one given here and not kept. That
    /// one also stands in for the unconfirmed model answer it was asked to replace, which the
    /// knowledge base still holds; a confirmed answer and a shipped rule speak first.
    static func shown(kept: Rule?, unkept: Rule?) -> Rule? {
        guard let unkept else { return kept }
        guard let kept, kept.source != .llm || kept.confirmed != nil else { return unkept }
        return kept
    }

    /// The answer given here and not kept (no id), for as long as the view holds the code it
    /// was given for.
    static func unkept(_ rule: Rule?, givenFor identity: CodeIdentity?, request: ExplainRequest) -> Rule? {
        guard let rule, rule.id == nil, rule.pattern == request.key, identity == request.identity else { return nil }
        return rule
    }

    private func ask() {
        busy = true
        error = nil
        let asked = request.subject
        Task {
            defer { busy = false }
            do {
                let answer = try await state.explainer.ask(request)
                guard shown == asked else { return }
                rule = answer
                answered = asked.identity
            } catch {
                self.error = describe(error)
            }
        }
    }

    private func confirm(_ rule: Rule) {
        guard let id = rule.id else { return }
        do {
            try state.rules.confirm(id: id)
            Task { await load() }
        } catch {
            self.error = describe(error)
        }
    }

    /// Deletes the kept answer. What the knowledge base says without it shows next: a shipped
    /// rule a confirmed answer stood before, or nothing, with the button that asks.
    private func forget(_ rule: Rule) {
        forgetting = false
        do {
            try state.rules.forget(rule)
            self.rule = nil
            answered = nil
            Task { await load() }
        } catch {
            self.error = describe(error)
        }
    }

    /// Where the answer came from, and how much the source trusted it.
    private func provenance(_ rule: Rule) -> String {
        var parts = [rule.sourceText]
        if let risk = rule.risk { parts.append("risk \(risk.rawValue)") }
        if let confidence = rule.confidence { parts.append("confidence \(confidence.rawValue)") }
        return parts.joined(separator: " \u{00B7} ")
    }

    private func describe(_ error: Error) -> String {
        switch error {
        case ProviderError.notConfigured: "No provider configured."
        case ProviderError.timedOut: "The provider did not answer in time."
        case ProviderError.tooMuchOutput: "The provider wrote more than an answer could hold, so it was stopped."
        case ProviderError.cannotDisclaim: "The command was not run, because this version of macOS would give it Tattle's permissions."
        case ProviderError.failed(let status, let stderr): "The provider failed (exit \(status)). \(stderr)"
        case let parse as LLMAnswer.ParseError: "The answer was not in the expected shape (\(parse))."
        default: String(describing: error)
        }
    }
}

extension Rule {
    /// Where the answer came from.
    var sourceText: String {
        switch source {
        case .llm: confirmed == nil ? "Model answer, unconfirmed" : "Model answer, confirmed by you"
        case .user: "Your rule"
        case .builtin: "Tattle's rules"
        case .iap: "Declared by the app"
        case .appleList: "Apple's host list"
        case .trackerRadar: "Tracker Radar"
        }
    }
}
