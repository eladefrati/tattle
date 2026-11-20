import Foundation

/// Who made a connection, resolved once when it opens.
struct ConnectionOwner: Equatable, Sendable {
    var processName: String
    /// The program alone when the name is a title the process set for itself
    /// (`ProcessEntry.program`).
    var program: String?
    var path: String?
    /// The interpreter's file name when the process runs code that is not its executable's
    /// (`ProcessEntry.interpreter`).
    var interpreter: String?
    var app: AppBundle?
    /// Who signed the code the process runs: its executable, or no one for a script or
    /// unnamed code. Nil when the file at its path is not the code it runs.
    var signature: CodeSignature?
    /// The executable's signature when it is an interpreter running a script or unnamed code.
    var interpreterSignature: CodeSignature?
    /// Who signed the app the connection is filed under. The app only started the process, or
    /// holds it in its bundle, so this says nothing about the process's own code.
    var appSignature: CodeSignature?
    /// The executable is a file in the app's bundle that the app's signer did not sign, or
    /// one that is not the code the process runs (`AppBundle.holdsForeign`).
    var isForeignToApp = false
    /// What tells the process's code from another's of its name (`ProcessEntry.identity`).
    var identity: CodeIdentity?

    /// The app when there is one, else the process: what the row is filed under.
    var displayName: String { app?.name ?? processName }
    var groupID: String { app?.path ?? "process:\(processName)" }
    /// What the row is asked about by: the Processes tab's key for the same app or program
    /// (`ProcessGroup.explainKey`), which of a title is the program alone.
    var explainKey: String { app?.name ?? program ?? processName }
    /// Not a signer the app's signature names, for a file in the app's bundle that the signer
    /// did not sign or that is not the code the process runs (`isForeignToApp`). A reading
    /// that names no one stays.
    var groupSignature: CodeSignature? {
        guard app != nil else { return signature }
        return isForeignToApp && appSignature?.namesSigner == true ? nil : appSignature
    }
    /// None for such a file in the app's bundle.
    var groupIdentity: CodeIdentity? {
        guard let app else { return identity }
        return isForeignToApp ? nil : CodeIdentity.of(appSignature, path: app.path)
    }
    var isApplesProgram: Bool { ApplesProgram.isNamed(displayName, path: path, signature: signature) }

    static let unknown = ConnectionOwner(processName: "unknown process")

    /// The pids among `opened` whose owner has to be read: one not known yet, or one that has
    /// replaced itself with another program, which keeps its pid. A running program whose file
    /// is gone has no path, and neither has a tool upgraded in place: the kernel's name for the
    /// process tells them apart. Of a pid that has exited, what is known is better than nothing.
    static func unresolved(opened: Set<Int32>, known: [Int32: ConnectionOwner], executable: (Int32) -> String?, commandName: (Int32) -> String?) -> Set<Int32> {
        opened.filter { pid in
            guard let owner = known[pid] else { return true }
            if let path = executable(pid) { return path != owner.path }
            guard let known = owner.path, let name = commandName(pid) else { return false }
            return name != ProcessTable.commandName(ofExecutable: known)
        }
    }

    /// Resolves a pid against a process list, attributing helpers to their app the same
    /// way the Processes tab does, and reads what it runs as that tab does. `byPid` is named
    /// without signatures; `executable` reads the executable of each process the owner's line
    /// passes through, for its pid and path, and `signature` the app bundle.
    static func resolve(
        pid: Int32, in byPid: [Int32: ProcessEntry], runningApp: (Int32) -> String?,
        responsible: (Int32) -> Int32? = ResponsibleProcess.pid(for:),
        executable: (Int32, String) -> CodeSignature?, signature: (String) -> CodeSignature?
    ) -> ConnectionOwner {
        // The list carries no signatures, so the owner and the ancestors its app comes from
        // are named here by theirs.
        func named(_ pid: Int32) -> ProcessEntry? {
            byPid[pid].map { $0.named(signature: $0.executableSignature(executable)) }
        }
        guard let entry = named(pid) else { return ConnectionOwner(processName: "pid \(pid)") }
        var memo: [Int32: AppBundle?] = [:]
        let app = ProcessSnapshot.app(of: pid, in: named, runningApp: runningApp, responsible: responsible, memo: &memo)
        let signed = entry.executableSignature(executable)
        let own = entry.codeSignature(executable: signed)
        let interpreter = entry.interpreterSignature(executable: signed)
        let appSignature = app?.signature(reading: signature)
        return ConnectionOwner(
            processName: entry.name, program: entry.program, path: entry.path, interpreter: entry.interpreter, app: app,
            signature: own, interpreterSignature: interpreter, appSignature: appSignature,
            isForeignToApp: app?.holdsForeign(entry.path, signed: interpreter ?? own, bundle: appSignature) ?? false,
            identity: entry.identity(executable: signed))
    }
}

/// A connection as the tab shows it.
struct LiveConnection: Equatable, Sendable, Identifiable {
    var connection: Connection
    var owner: ConnectionOwner
    /// First time this Mac reaches this address.
    var isNew: Bool
    /// From the sniffer, when it saw the handshake; nil until then or without packet access.
    var name: ConnectionName? = nil
    /// Why the sniffer found no name, once it has given up.
    var unnamedReason: FlowEvent.Reason? = nil

    var outcome: NameOutcome? {
        if let name { return .named(name) }
        if let unnamedReason { return .unnamed(unnamedReason) }
        return nil
    }

    init(connection: Connection, owner: ConnectionOwner, isNew: Bool, outcome: NameOutcome? = nil) {
        self.connection = connection
        self.owner = owner
        self.isNew = isNew
        name = outcome?.name
        unnamedReason = outcome?.reason
    }

    var id: String { connection.id }

    var destination: String {
        connection.isIPv6 ? "[\(connection.remoteAddress)]:\(connection.remotePort)" : "\(connection.remoteAddress):\(connection.remotePort)"
    }

    /// What the row is headed by: the name where it is the destination, what kind of
    /// non-destination it is otherwise, the address when there is no name.
    var title: String {
        switch name?.kind {
        case .destination: name!.name
        case .relay: "relayed"
        case .hidden: "name hidden"
        case nil: destination
        }
    }

    /// The destination name came only from a DNS reply for the address, which may serve
    /// many names: shown marked (ADR-0001 decision 2).
    var isFromDNS: Bool { name?.source == .dns }

    /// Knowledge-base key: the name once the sniffer supplies one, the address until then.
    /// A relay or cover name is still the right key: the rule for it says what it is.
    var explainKey: String { name?.name ?? connection.wireAddress }

    /// The detail's heading.
    var headline: String {
        switch connection.direction {
        case .outbound: "\(owner.displayName) to \(title)"
        case .inbound: "\(owner.displayName) from \(destination)"
        case .unknown: "\(owner.displayName) with \(destination)"
        }
    }

    /// Whether the address is one this Mac has not reached before, and remembers that it has.
    /// Only a connection proven to be this Mac's counts: a peer that connected in, or one no
    /// one can say about, is not an address it reached.
    static func isFirstContact(_ connection: Connection, known: inout Set<String>) -> Bool {
        connection.direction == .outbound && known.insert(connection.wireAddress).inserted
    }

    /// The app's sentence that opens "Why it is probably here": who holds the connection.
    var whyHere: String {
        switch connection.direction {
        case .outbound: "\(owner.displayName) opened it."
        case .inbound: "It came in to \(owner.displayName) on port \(connection.localPort)."
        case .unknown: "\(owner.displayName) holds it."
        }
    }

    func facts(now: Date) -> [Fact] {
        var facts: [Fact] = []
        switch connection.direction {
        // What the model hears of this connection's direction it would say of the host, and
        // its answer is shown on every connection to the host.
        case .inbound:
            facts.append(Fact(name: "From", value: destination, inPrompt: false))
            facts.append(Fact(name: "To port", value: String(connection.localPort), inPrompt: false))
        case .unknown:
            facts.append(Fact(name: "Peer", value: destination, inPrompt: false))
            facts.append(Fact(name: "Local port", value: String(connection.localPort), inPrompt: false))
        case .outbound:
            switch name?.kind {
            case .destination:
                facts.append(Fact(name: "Destination", value: name!.name, inPrompt: false))
                facts.append(Fact(name: "Address", value: destination))
            case .relay:
                facts.append(Fact(name: "Destination", value: "hidden inside a relay", inPrompt: false))
                facts.append(Fact(name: "Relay", value: name!.name))
                facts.append(Fact(name: "Address", value: destination))
            case .hidden:
                facts.append(Fact(name: "Destination", value: "hidden by Encrypted Client Hello", inPrompt: false))
                facts.append(Fact(name: "Cover name", value: name!.name))
                facts.append(Fact(name: "Address", value: destination))
            case nil:
                facts.append(Fact(name: "Destination", value: destination, inPrompt: false))
            }
        }
        facts += [
            Fact(name: "Protocol", value: connection.proto.rawValue.uppercased() + (connection.stateText.map { ", \($0)" } ?? "")),
            Fact(name: "Reach", value: connection.scope == .local ? "this network" : "the internet"),
        ]
        // The model is asked what the host is, and its answer is shown on every connection to
        // the host: what it hears of this connection's owner it would say of theirs.
        facts += ownerFacts.map { fact in
            var fact = fact
            fact.inPrompt = false
            return fact
        }
        if connection.preExisting {
            facts.append(Fact(name: "Since", value: "before Tattle started looking"))
        } else {
            facts.append(Fact(name: "Since", value: Self.ago(connection.firstSeen, now: now)))
        }
        if connection.direction == .outbound { facts.append(Fact(name: "First contact", value: isNew ? "yes, never seen this address before" : "no, seen before", inPrompt: false)) }
        if let name {
            facts.append(Fact(name: "Name from", value: name.source.text))
        } else if let unnamedReason {
            facts.append(Fact(name: "No name", value: unnamedReason.text))
        }
        return facts
    }

    private var ownerFacts: [Fact] {
        var facts = [Fact(name: "Process", value: "\(owner.processName) (pid \(connection.pid))")]
        if let interpreter = owner.interpreter, let path = owner.path { facts.append(Fact(name: "Runs with", value: "\(interpreter) (\(path))")) }
        if let app = owner.app, app.name != owner.processName { facts.append(Fact(name: "App", value: app.name)) }
        var signers = [(owner.signature, "Signed by", "Team"), (owner.interpreterSignature, "Interpreter signed by", "Interpreter team")]
        if let app = owner.appSignature, !app.isSameSigner(as: owner.signature) { signers.append((app, "App signed by", "App team")) }
        for (signature, label, teamLabel) in signers {
            guard let signature else { continue }
            facts.append(.signedBy(signature, as: label))
            if let team = signature.teamIdentifier { facts.append(Fact(name: teamLabel, value: team)) }
        }
        facts.append(.runsAs(connection.uid))
        return facts
    }

    static func ago(_ date: Date, now: Date) -> String {
        let seconds = max(now.timeIntervalSince(date), 0)
        if seconds < 60 { return "\(Int(seconds)) s ago" }
        if seconds < 3600 { return "\(Int(seconds / 60)) min ago" }
        if seconds < 86400 { return "\(Int(seconds / 3600)) h ago" }
        return "\(Int(seconds / 86400)) d ago"
    }
}

/// One row of the tab: an app or program and its open connections.
struct ConnectionGroup: Equatable, Sendable, Identifiable {
    var id: String
    var name: String
    /// Newest first.
    var connections: [LiveConnection]

    /// Who signed the row's program, when its connections all say the same: a process that
    /// took the name shares the row, so the newest connection's alone could name Apple over
    /// the impostor's connections. Not the app's signer with a connection from a file in the
    /// app's bundle that the signer did not sign or that is not the code its process runs
    /// (`ConnectionOwner.groupSignature`).
    var signature: CodeSignature? {
        guard let newest = connections.first?.owner.groupSignature,
              connections.allSatisfy({ newest.isSameSigner(as: $0.owner.groupSignature) }) else { return nil }
        return newest
    }

    /// Apple's own program by the group's name when every connection's owner is. A process
    /// that took the name shares the row, so the newest connection's signature alone would
    /// pass that process too.
    var isApplesProgram: Bool { connections.allSatisfy(\.owner.isApplesProgram) }

    /// What tells the row's program from another's of its name, when its connections are all
    /// one program's: a process that took the name shares the row.
    var identity: CodeIdentity? {
        let identities = Set(connections.map(\.owner.groupIdentity))
        return identities.count == 1 ? identities.first ?? nil : nil
    }

    /// The key an answer about the row's program is asked and kept under: the newest
    /// connection's, as the row's path is.
    var explainKey: String { connections.first?.owner.explainKey ?? name }

    var newCount: Int { connections.filter(\.isNew).count }
    var remoteCount: Int { connections.filter { $0.connection.scope == .remote }.count }
    var localCount: Int { connections.count - remoteCount }

    /// The row's subtitle, by where its connections go or come from.
    var reachSummary: [String] {
        func remote(_ direction: Connection.Direction) -> Int {
            connections.filter { $0.connection.scope == .remote && $0.connection.direction == direction }.count
        }
        var parts: [String] = []
        if remote(.outbound) > 0 { parts.append("\(remote(.outbound)) to the internet") }
        if remote(.inbound) > 0 { parts.append("\(remote(.inbound)) from the internet") }
        if remote(.unknown) > 0 { parts.append("\(remote(.unknown)) with the internet") }
        if localCount > 0 { parts.append("\(localCount) on this network") }
        return parts
    }

    /// The app's sentence that opens "Why it is probably here".
    func whyHere(gone: Bool) -> String {
        let count = connections.count == 1 ? "1 connection" : "\(connections.count) connections"
        return gone ? "It had \(count) open." : "It is running and has \(count) open."
    }

    func facts(gone: Bool) -> [Fact] {
        var facts = [Fact(name: gone ? "Were open" : "Open", value: String(connections.count))]
        if remoteCount > 0 { facts.append(Fact(name: "Internet", value: String(remoteCount))) }
        if localCount > 0 { facts.append(Fact(name: "This network", value: String(localCount))) }
        if newCount > 0 { facts.append(Fact(name: "First contact", value: String(newCount))) }
        if let signature {
            facts.append(.signedBy(signature))
            if let team = signature.teamIdentifier { facts.append(Fact(name: "Team", value: team)) }
        }
        return facts
    }
}

struct NetworkSnapshot: Equatable, Sendable {
    var connections: [LiveConnection]
    var takenAt: Date

    /// Groups by app or program, most connections first.
    var groups: [ConnectionGroup] {
        var byID: [String: ConnectionGroup] = [:]
        var order: [String] = []
        for live in connections.sorted(by: { $0.connection.firstSeen > $1.connection.firstSeen }) {
            let id = live.owner.groupID
            if byID[id] == nil {
                byID[id] = ConnectionGroup(id: id, name: live.owner.displayName, connections: [])
                order.append(id)
            }
            byID[id]!.connections.append(live)
        }
        return order.compactMap { byID[$0] }.sorted { ($0.connections.count, $1.name) > ($1.connections.count, $0.name) }
    }

    var newCount: Int { connections.filter(\.isNew).count }
    var preExistingCount: Int { connections.filter(\.connection.preExisting).count }
    var namedCount: Int { connections.filter { $0.name?.kind == .destination && !$0.isFromDNS }.count }
    var dnsCount: Int { connections.filter(\.isFromDNS).count }
    var relayedCount: Int { connections.filter { $0.name?.kind == .relay }.count }
    var hiddenCount: Int { connections.filter { $0.name?.kind == .hidden }.count }

    func connection(id: String) -> LiveConnection? { connections.first { $0.id == id } }

    /// Settles a row as this Mac reaching out, once its opening is seen. Returns false when
    /// no row is that connection.
    mutating func confirmOutbound(id: String, isNew: Bool) -> Bool {
        guard let index = connections.firstIndex(where: { $0.id == id }) else { return false }
        connections[index].connection.direction = .outbound
        connections[index].isNew = isNew
        return true
    }
    func group(id: String) -> ConnectionGroup? { groups.first { $0.id == id } }

    /// Puts the sniffer's outcome on the flow's row. Returns false when no row is the flow's
    /// yet.
    mutating func attach(_ outcome: NameOutcome, to flow: FlowKey, openedAt: Date) -> Bool {
        guard let index = connections.firstIndex(where: {
            $0.connection.flowKey == flow.text
                && ConnectionStore.isConnection(of: flow, firstSeen: $0.connection.firstSeen, isOpen: $0.connection.isOpen, openedAt: openedAt)
        }) else { return false }
        connections[index].name = outcome.name
        connections[index].unnamedReason = outcome.reason
        return true
    }
}
