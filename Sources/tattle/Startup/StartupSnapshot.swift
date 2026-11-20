import Foundation

/// One row of the Startup tab: a launchd job, a login item, or both joined.
struct StartupItem: Equatable, Sendable, Identifiable {
    enum Group: Int, CaseIterable, Sendable {
        case loginItems, background, userAgents, globalAgents, daemons, extensions

        var title: String {
            switch self {
            case .loginItems: "Open at login"
            case .background: "Allowed in the background"
            case .userAgents: LaunchdItem.Scope.userAgent.title
            case .globalAgents: LaunchdItem.Scope.globalAgent.title
            case .daemons: LaunchdItem.Scope.daemon.title
            case .extensions: "App extensions"
            }
        }

        var description: String {
            switch self {
            case .loginItems: "Apps you or they added to System Settings' Open at Login list."
            case .background: "Helpers, agents and background refresh that apps registered; System Settings lists them under Allow in the Background by app."
            case .userAgents: "Jobs in your Library/LaunchAgents: run as you when you log in, usually installed by apps you use."
            case .globalAgents: "Jobs in /Library/LaunchAgents: run for whoever logs in, installed with an administrator password."
            case .daemons: "Jobs in /Library/LaunchDaemons: run as root from boot, logged in or not."
            case .extensions: "Spotlight importers, Quick Look and other extensions, Dock tile plug-ins: run when macOS needs them, not at startup."
            }
        }
    }

    enum State: Equatable, Sendable {
        case running(pid: Int32)
        case idle(lastExitStatus: Int32?)
        case notLoaded
        case disabled
        /// An empty plist.
        case placeholder
        /// A login item System Settings allows (a helper or an agent its app registered also
        /// needs its app to have turned it on), or one System Settings does not allow.
        case enabled, off
        /// A login item its app has not turned on: it does not run, whatever System Settings allows.
        case notTurnedOn
        /// A plist Tattle could not read: launchd may still run the job.
        case unreadable(reason: String)
        /// A folder Tattle could not list: launchd may still run the jobs in it.
        case unlisted(reason: String)
        /// launchd's domain could not be read, so whether the job is loaded is not known.
        case unknown(reason: String)

        var text: String {
            switch self {
            case .running(let pid): "running, pid \(pid)"
            case .idle(let status?) where status != 0: "not running, last exit \(status)"
            case .idle: "not running"
            case .notLoaded: "not loaded"
            case .disabled: "disabled"
            case .placeholder: "empty file, nothing runs"
            case .enabled: "on"
            case .off, .notTurnedOn: "off"
            case .unreadable: "could not be read"
            case .unlisted: "could not be listed"
            case .unknown: "state not known"
            }
        }

        var isActive: Bool {
            switch self {
            case .running, .enabled: true
            default: false
            }
        }
    }

    /// Unique among the rows and the same at every reading: the plist's path, or for a login
    /// item not joined to a plist, the identifier of macOS's record. A label is not: two
    /// plists can carry one, and so can a login item and a plist it was not joined to.
    var id: String
    /// The launchd label, or a login item's bundle id; the plist's path when nothing names it.
    var label: String
    var group: Group
    var name: String
    /// What runs: the program, or the app.
    var program: String?
    var arguments: [String] = []
    /// When it runs; nil when nothing says.
    var trigger: String?
    /// `trigger` in parts, with each file or folder launchd watches for the job held whole.
    var triggerParts: [Fact.Part] = []
    var state: State
    var signature: CodeSignature?
    /// What says which version of the code its command line reaches this is.
    var codeVersion: LaunchedVersion = .unknown
    var developer: String?
    var teamIdentifier: String?
    /// The app this item belongs to, for helpers and registered agents.
    var parent: String?
    var plistURL: URL?
    /// Managed in System Settings, Login Items.
    var isLoginItem: Bool
    var launchdScope: LaunchdItem.Scope?
    /// Where Load and Unload act.
    var launchDomain = LaunchDomain.gui
    /// What launchd says the loaded job of this label came from, when that is not this plist:
    /// another plist's path, or what submitted a job that has none. launchd refuses to load
    /// this plist while that job holds the label.
    var labelHeldBy: String?

    var runs: String? { program.map { ([$0] + arguments).joined(separator: " ") } }

    /// The knowledge-base key: the launchd label, or the bundle id for an app.
    var explainKey: String { label }

    /// Tattle's own daemon, the one system job Tattle removes (ADR-0003). An agent that
    /// carries its label is someone else's job.
    var isCaptureBroker: Bool { label == CaptureBroker.label && launchdScope == .daemon }

    var isUnlistedFolder: Bool {
        if case .unlisted = state { return true }
        return false
    }

    /// Of a file Tattle could not read it knows only the name, unless macOS's record says
    /// what runs: otherwise there is nothing to ask a model.
    var canExplain: Bool {
        switch state {
        case .unreadable: program != nil
        case .unlisted: false
        default: true
        }
    }

    /// What tells this item's code from another's of its label (`CodeIdentity`): its
    /// publisher's signature, else its command line. `signature` is of the code the line
    /// reaches, and `program` its first word, which can be a wrapper: only a team says whose
    /// code it is whichever file that is. Apple's team on a copy outside macOS says only who
    /// made the file, so the line and the copy's code are the identity. Nil when the line
    /// does not say where its code is.
    var identity: CodeIdentity? {
        if signature?.teamIdentifier != nil, signature?.signer != .appleElsewhere,
           let published = CodeIdentity.of(signature, path: program) { return published }
        guard let runs else { return nil }
        switch codeVersion {
        case .line: return CodeIdentity.command(runs)
        case .file(let file): return CodeIdentity.command(runs, codeHash: signature?.codeHash, file: file)
        case .unknown: return nil
        }
    }

    /// The app's sentence that opens "Why it is probably here": when it runs, or what keeps it
    /// from running, and the app it belongs to. In the past tense once it is gone.
    func whyHere(gone: Bool) -> String {
        let (be, does) = gone ? ("was", "did") : ("is", "does")
        let when = switch state {
        case .disabled: "It \(be) disabled, so macOS \(does) not start it."
        case .off: "It \(be) switched off in System Settings, so it \(does) not run."
        case .notTurnedOn: "Its app \(gone ? "had" : "has") not turned it on, so it \(does) not run."
        case .placeholder: "Its file \(be) empty, so nothing \(gone ? "ran" : "runs")."
        case .unreadable, .unlisted: "Tattle could not read its file, so when it runs is not known."
        default: trigger.map { "It \(gone ? "ran" : "runs") \($0)." } ?? "Nothing says when it runs."
        }
        guard let parent else { return when }
        return when + " It \(gone ? "belonged" : "belongs") to \(parent)."
    }

    /// Deterministic facts sent with an explain request and shown in the detail view.
    var facts: [Fact] {
        var facts: [Fact] = []
        if let program, let runs {
            // Arguments can carry tokens, addresses and paths: the model gets only their count.
            let count = arguments.count == 1 ? "1 argument" : "\(arguments.count) arguments"
            facts.append(Fact(name: "Runs", value: runs, promptParts: [.path(program)] + (arguments.isEmpty ? [] : [.text(" (\(count), not sent)")])))
        }
        facts.append(Fact(name: "When", value: trigger ?? "unknown", promptParts: triggerParts))
        facts.append(Fact(name: "State", value: state.text))
        switch state {
        case .unreadable(let reason), .unlisted(let reason), .unknown(let reason): facts.append(Fact(name: "Reason", value: reason))
        default: break
        }
        if let signature {
            facts.append(.signedBy(signature))
            if case .launchItem(let program?) = signature.signer { facts.append(Fact(name: "Runs Apple's", value: program)) }
            if let team = signature.teamIdentifier ?? teamIdentifier { facts.append(Fact(name: "Team", value: team)) }
        } else if let teamIdentifier {
            facts.append(Fact(name: "Team", value: teamIdentifier))
        }
        if let developer { facts.append(Fact(name: "Developer", value: developer)) }
        if let parent { facts.append(Fact(name: "Part of", value: parent)) }
        if let plistURL { facts.append(.path(isUnlistedFolder ? "Folder" : "Plist", plistURL.path)) }
        // launchd's own text, which can name another plist or the app that submitted the job:
        // shown, not sent.
        if let labelHeldBy { facts.append(Fact(name: "Label held by", value: labelHeldBy, inPrompt: false)) }
        return facts
    }
}

/// Everything the tab shows at one moment.
struct StartupSnapshot: Equatable, Sendable {
    var items: [StartupItem]
    var appleCount: Int
    var loginItemsError: String?
    /// The error is one that granting Full Disk Access would cure.
    var loginItemsNeedFullDiskAccess = false

    func items(in group: StartupItem.Group) -> [StartupItem] {
        items.filter { $0.group == group }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// Joins the sources. `signature` is called for each executable path; the observer
    /// passes a cached reader, tests pass a table.
    static func build(
        launchd: LaunchdReader.Result, loginItems: [LoginItem], state: LaunchctlState,
        signature: (String) -> CodeSignature?
    ) -> StartupSnapshot {
        let byIdentifier = Dictionary(loginItems.map { ($0.identifier, $0) }, uniquingKeysWith: { a, _ in a })
        // macOS can hold more than one record for a plist: one whose label has since changed
        // stays beside the record made for the new label.
        var byPlistPath: [String: [LoginItem]] = [:]
        for item in loginItems {
            guard item.legacy, let url = item.url.flatMap(URL.init(string:)), url.isFileURL else { continue }
            byPlistPath[url.path, default: []].append(item)
        }

        var items: [StartupItem] = []
        var joined = Set<String>()
        let shared = launchd.sharedLabels

        for job in launchd.items {
            let (jobState, heldBy) = launchdState(job, state: state, shared: shared)
            let records = byPlistPath[job.plistURL.path] ?? []
            joined.formUnion(records.map(\.identifier))
            let registered = records.first { $0.jobLabel == job.label } ?? records.first
            let started = job.program.map {
                CodeSignature.started(program: $0, arguments: job.arguments, environmentPath: job.environmentPath,
                                      asRoot: job.scope == .daemon, changesRoot: job.rootDirectory != nil, reading: signature)
            }
            items.append(StartupItem(
                id: job.plistURL.path,
                label: job.label,
                group: group(for: job.scope),
                name: registered?.name ?? job.label,
                program: job.program,
                arguments: job.arguments,
                trigger: job.isPlaceholder ? "never" : job.triggers.map { $0.description(scope: job.scope) }.joined(separator: ", "),
                triggerParts: job.isPlaceholder ? [] : Array(job.triggers.map { $0.parts(scope: job.scope) }.joined(separator: [.text(", ")])),
                state: jobState,
                signature: started?.signature,
                codeVersion: started?.version ?? .unknown,
                developer: registered?.developerName,
                teamIdentifier: registered?.teamIdentifier,
                parent: nil,
                plistURL: job.plistURL,
                isLoginItem: registered != nil,
                launchdScope: job.scope,
                launchDomain: job.domains.first { state[$0].services[job.label] != nil } ?? job.domains[0],
                labelHeldBy: heldBy))
        }

        for plist in launchd.unreadable {
            // With Full Disk Access macOS has a record of the plist, which knows what runs.
            let records = byPlistPath[plist.url.path] ?? []
            joined.formUnion(records.map(\.identifier))
            let registered = records.first
            let path = registered?.executablePath.flatMap { $0.hasPrefix("/") ? $0 : nil }
            let signed = registered.flatMap { item in path.flatMap { registeredSignature(of: item, at: $0, reading: signature) } }
            items.append(StartupItem(
                id: plist.url.path,
                label: registered?.jobLabel ?? plist.url.path,
                group: group(for: plist.scope),
                name: registered?.name ?? plist.url.deletingPathExtension().lastPathComponent,
                program: path,
                trigger: nil,
                state: plist.isFolder ? .unlisted(reason: plist.reason) : .unreadable(reason: plist.reason),
                signature: signed,
                codeVersion: path.map { .of(program: $0, signature: signed) } ?? .unknown,
                developer: registered?.developerName,
                teamIdentifier: registered?.teamIdentifier,
                plistURL: plist.url,
                isLoginItem: registered != nil,
                launchdScope: plist.isFolder ? nil : plist.scope))
        }

        for item in loginItems where (item.isStartupItem || item.isExtension) && !joined.contains(item.identifier) {
            // An app record without the enabled bit is only the container for its helpers
            // and extensions; System Settings does not list it under Open at Login.
            if item.kind == .app && !item.enabled { continue }
            let container = item.container.flatMap { byIdentifier[$0] }
            let path = executablePath(of: item, container: container)
            let plist = item.url.flatMap(URL.init(string:)).flatMap { $0.isFileURL && $0.pathExtension == "plist" ? $0 : nil }
            let signed = path.flatMap { registeredSignature(of: item, at: $0, reading: signature) }
            items.append(StartupItem(
                id: item.identifier,
                label: item.jobLabel ?? item.identifier,
                group: item.isExtension ? .extensions : item.kind == .app ? .loginItems : .background,
                name: item.name,
                program: path,
                trigger: trigger(for: item),
                state: loginItemState(item, state: state),
                signature: signed,
                codeVersion: path.map { .of(program: $0, signature: signed) } ?? .unknown,
                developer: item.developerName ?? container?.developerName,
                teamIdentifier: item.teamIdentifier,
                parent: container.map { $0.name } ?? item.container,
                plistURL: plist,
                isLoginItem: true,
                launchdScope: nil))
        }

        return StartupSnapshot(items: items, appleCount: launchd.appleCount)
    }

    private static func group(for scope: LaunchdItem.Scope) -> StartupItem.Group {
        switch scope {
        case .userAgent: .userAgents
        case .globalAgent: .globalAgents
        case .daemon: .daemons
        }
    }

    /// The job's state, and what holds its label when launchd's job of that label is another
    /// plist's.
    private static func launchdState(
        _ job: LaunchdItem, state: LaunchctlState, shared: [LaunchDomain: Set<String>]
    ) -> (StartupItem.State, heldBy: String?) {
        if job.isPlaceholder { return (.placeholder, nil) }
        var heldBy: String?
        // A loaded job runs whatever the plist says, and a disable only stops the next load.
        if let domain = job.domains.first(where: { state[$0].services[job.label] != nil }),
           let service = state[domain].services[job.label] {
            if shared[domain]?.contains(job.label) == true {
                // Another plist carries the label: the job is this one's only if launchd says so.
                guard let path = state[domain].jobPaths[job.label] else {
                    return (.unknown(reason: "Another plist carries its label, and launchd did not say which of them its loaded job came from"), nil)
                }
                if !Launchctl.isSameFile(path, job.plistURL.path) { heldBy = path }
            }
            if heldBy == nil {
                if let pid = service.pid { return (.running(pid: pid), nil) }
                return (.idle(lastExitStatus: service.lastExitStatus), nil)
            }
        }
        let domains = job.domains.map { state[$0] }
        if let reason = domains.lazy.compactMap(\.unread).first { return (.unknown(reason: reason), heldBy) }
        return (domains.lazy.compactMap({ $0.overrides[job.label] }).first ?? job.disabled ? .disabled : .notLoaded, heldBy)
    }

    private static func loginItemState(_ item: LoginItem, state: LaunchctlState) -> StartupItem.State {
        if let label = item.bundleIdentifier, let service = state[item.kind == .daemon ? .system : .gui].services[label], let pid = service.pid {
            return .running(pid: pid)
        }
        switch item.kind {
        // A helper or an agent its app registered runs only with both bits set: the app sets
        // enabled when it turns the item on, and allowed stays set after the app turns it off.
        case .loginItemHelper, .agent where !item.legacy:
            if !item.enabled { return .notTurnedOn }
            return item.allowed ? .enabled : .off
        // No record has shown what the enabled bit does for the other kinds: they keep to the
        // allowed bit.
        default:
            return item.allowed ? .enabled : .off
        }
    }

    private static func trigger(for item: LoginItem) -> String? {
        switch item.kind {
        case .app, .loginItemHelper: "at login"
        case .agent: "at login, by its app"
        case .daemon: "at boot, by its app"
        case .backgroundRefresh: "in the background"
        case .spotlightImporter: "when Spotlight indexes its files"
        case .dockTilePlugin: "while its app is in the Dock"
        case .appExtension: "when macOS needs it"
        case .other: nil
        }
    }

    /// How a registered item reads: one among Apple's developer tools as unnamed code, and a
    /// launch agent or daemon as any launch item does.
    private static func registeredSignature(
        of item: LoginItem, at path: String, reading signature: (String) -> CodeSignature?
    ) -> CodeSignature? {
        let signed = signature(path)
        let realPath = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        if LaunchedCode.Identity(path: path, signature: signed, realPath: realPath).isDeveloperTool { return CodeSignature(signer: .unnamed) }
        return item.isLaunchItem ? CodeSignature.launchItem(running: path, signature: signed) : signed?.located(at: realPath)
    }

    /// The app bundle for an app, or the helper's path inside its container.
    private static func executablePath(of item: LoginItem, container: LoginItem?) -> String? {
        if let path = item.executablePath, path.hasPrefix("/") { return path }
        guard let url = item.url else { return nil }
        if let absolute = URL(string: url), absolute.isFileURL { return absolute.path }
        if let base = container?.url.flatMap(URL.init(string:)), base.isFileURL {
            return base.appending(path: item.executablePath ?? url).path
        }
        return nil
    }
}

extension LaunchdReader.Result {
    /// Labels more than one plist carries within a domain. launchd holds one job per label in a
    /// domain, so which plist a loaded job of such a label came from must be asked. An empty
    /// plist is no job: its label is only its file's name.
    var sharedLabels: [LaunchDomain: Set<String>] {
        var counts: [LaunchDomain: [String: Int]] = [:]
        for job in items where !job.isPlaceholder {
            for domain in job.domains { counts[domain, default: [:]][job.label, default: 0] += 1 }
        }
        return counts.mapValues { Set($0.filter { $0.value > 1 }.keys) }.filter { !$0.value.isEmpty }
    }
}
