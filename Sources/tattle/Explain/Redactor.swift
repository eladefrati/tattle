import Foundation
import SystemConfiguration

/// Replaces what would identify this Mac or its user before a prompt leaves the machine:
/// the home path, the username, private and local IP addresses, the machine's names,
/// Tailscale names, which identify the account, other accounts' folders, disk names,
/// email addresses and host names only this network resolves.
struct Redactor: Sendable {
    /// What a text is. An item's key and facts share one, so the same rules apply to both.
    enum Context {
        case host
        /// A process or a listening port.
        case program
        case launchItem
        /// Prompt instructions the user has edited.
        case instructions

        init(_ kind: Rule.Kind) {
            switch kind {
            case .host: self = .host
            case .process, .port: self = .program
            case .launchItem: self = .launchItem
            }
        }
    }

    var home: String
    var username: String
    var machineNames: [String]
    /// The mounted disks' names, which can hold spaces and brackets.
    var volumeNames: [String] = []
    /// The network's search domains: a host under one is a name this network gave.
    var searchDomains: [String] = []

    /// The machine's names come from the dynamic store and the kernel, never from a name
    /// lookup: macOS holds an app's reverse lookups of its own addresses, loopback included,
    /// behind the Local Network alert, and unanswered they fail after 35 s (measured on
    /// the test Mac, 2026-10-28). Host.current() makes those lookups.
    static var current: Redactor {
        var buffer = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
        let hostName = gethostname(&buffer, buffer.count) == 0 ? String(cString: buffer) : nil
        let domains = SystemDNS.current.domains
        return Redactor(
            home: NSHomeDirectory(),
            username: NSUserName(),
            machineNames: machineNames(
                computerName: SCDynamicStoreCopyComputerName(nil, nil) as String?,
                localHostName: SCDynamicStoreCopyLocalHostName(nil) as String?,
                hostName: hostName, domains: domains),
            volumeNames: (try? FileManager.default.contentsOfDirectory(atPath: "/Volumes")) ?? [],
            searchDomains: domains)
    }

    /// The computer name, the Bonjour name bare and with .local, the hostname, and each host
    /// label under every search domain, which is how Tailscale and the router's DHCP name
    /// this Mac.
    ///
    /// Not covered: a name the router invents and no search domain carries, Tailscale's suffix for a name another device
    /// already has (`-1`), and a rename in Tailscale's admin console.
    static func machineNames(computerName: String?, localHostName: String?, hostName: String?, domains: [String]) -> [String] {
        let bare = [computerName, localHostName, localHostName.map { $0 + ".local" }, hostName].compactMap { $0 }
        let labels = [localHostName, hostName.map(firstLabel), computerName.map(tailscaleLabel)].compactMap { $0 }
        let names = bare + labels.flatMap { label in domains.map { label + "." + $0 } }
        var seen = Set<String>()
        return names.filter { name in
            let first = firstLabel(name).lowercased()
            return first != "" && first != "localhost" && seen.insert(name.lowercased()).inserted
        }
    }

    /// The label Tailscale's MagicDNS gives this Mac, which it takes from the computer name,
    /// not the local host name: its HostName is the computer name (measured on this Mac,
    /// 2026-10-28). A port of SanitizeHostname in tailscale/tailscale util/dnsname/dnsname.go,
    /// byte for byte, so a curly apostrophe vanishes.
    static func tailscaleLabel(_ computerName: String) -> String {
        var name = Array(computerName.utf8)
        for suffix in [".local", ".localdomain", ".lan"].map({ Array($0.utf8) }) where name.suffix(suffix.count).elementsEqual(suffix) {
            name.removeLast(suffix.count)
        }
        let upper = UInt8(ascii: "A")...UInt8(ascii: "Z")
        func isAlphanumeric(_ byte: UInt8) -> Bool {
            upper.contains(byte) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        }
        var label = name.prefix(63)
        while let byte = label.first, !isAlphanumeric(byte) { label.removeFirst() }
        while let byte = label.last, !isAlphanumeric(byte) { label.removeLast() }
        let dashes = Set("- .@_".utf8)
        let bytes = label.compactMap { byte -> UInt8? in
            if upper.contains(byte) { return byte + 32 }
            if isAlphanumeric(byte) { return byte }
            return dashes.contains(byte) ? UInt8(ascii: "-") : nil
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func firstLabel(_ name: String) -> String {
        String(name.prefix { $0 != "." })
    }

    /// Where an absolute path begins, for every pass that reads one: not inside a longer word
    /// or path, or straight after a disk's root, as in "/System/Volumes/Data/Users/x". A disk's
    /// name holds no slash and at most 255 characters.
    private static let pathStart = "(?:(?<![\\w.-])|(?<=/Volumes/[^/\\n]{1,255}))"

    /// A folder's or disk's name, and where one ends. A dot belongs to the name only with more
    /// of it after, so a sentence's period stays.
    private static let pathName = "[\\w.~@+%-]*[\\w~@+%-]"
    private static let pathEnd = "(?![\\w~@+%-]|\\.[\\w~@+%-])"

    /// A name that is all of a host, for every pass that reads one: no label, "_" or "-" joins
    /// it on either side. A dot that ends a sentence joins nothing.
    private static func wholeHost(_ name: String) -> String {
        "(?<![\\w.-])" + name + "(?![\\w-]|\\.[\\w-])"
    }

    /// An item's key as a prompt carries it. A startup item with no label is known by its
    /// plist's path, which is cut as a path. A host with no dot is a name only this network
    /// resolves; only the key is read so, since in a fact's text the same letters are a word.
    func redact(key: String, of kind: Rule.Kind) -> String {
        let sent = redact([kind == .launchItem && key.hasPrefix("/") ? .path(key) : .text(key)], as: Context(kind))
        let isBareName = !key.isEmpty && !key.contains(".") && !key.contains(":")
        return kind == .host && isBareName && sent == key ? "<private-host>" : sent
    }

    /// A value in parts as a prompt carries it: each path cut where it stands, then the whole
    /// redacted as any text.
    func redact(_ parts: [Fact.Part], as context: Context) -> String {
        let text = parts.map { part in
            switch part {
            case .text(let text): text
            case .path(let path): cut(path: path)
            }
        }
        return redact(text.joined(), as: context)
    }

    /// macOS's own folders in a home folder, and in its Library: the same on every Mac.
    private static let homeFolders: Set<String> = [
        "Applications", "Desktop", "Documents", "Downloads", "Library", "Movies", "Music", "Pictures", "Public",
    ]
    private static let libraryFolders: Set<String> = [
        "Application Scripts", "Application Support", "Caches", "CloudStorage", "Containers", "Group Containers",
        "LaunchAgents", "Logs", "Mobile Documents", "Preferences", "Services",
    ]

    /// A whole path as a prompt carries it. Under a home folder, another account's or another
    /// disk, the folders are the user's own words (a client, a project, a cloud drive named
    /// with an email address): the path goes out as its root, macOS's own folders at its start
    /// and its last part, "<home>/Library/Application Support/<folders>/tool". Any other path
    /// is where software is installed and goes out whole.
    ///
    /// The path's parts are the file system's: a repeated or a trailing slash and a "." part
    /// name nothing.
    func cut(path: String) -> String {
        guard path.hasPrefix("/") else { return path }
        let same = { (a: String, b: String) in a.caseInsensitiveCompare(b) == .orderedSame }
        let homeParts = home.split(separator: "/").map(String.init)
        let written = path.split(separator: "/").filter { $0 != "." }
        let all = written.map(String.init)
        var rest = all[...]
        // The path up to one of its parts, as it is written and as the file system reads it.
        func leads(to index: Int) -> [String] {
            [String(path[..<written[index].startIndex]), "/" + all[..<index].map { $0 + "/" }.joined()]
        }
        // Whether the path goes on through the home folder, in any case, as APFS reads a path.
        func dropHome() -> Bool {
            guard !homeParts.isEmpty, rest.count >= homeParts.count, zip(rest, homeParts).allSatisfy(same) else { return false }
            rest = rest.dropFirst(homeParts.count)
            return true
        }
        var root = ""
        var isAccount = false
        if dropHome() {
            (root, isAccount) = ("<home>", true)
        } else {
            // A disk's root, then an account on it: the boot disk's firmlink keeps its name.
            var isPersonal = false
            if rest.count >= 3, same(rest[rest.startIndex], "System"), same(rest[rest.startIndex + 1], "Volumes") {
                // macOS's own name for the disk, unless the passes over text read another's there.
                root = "/System/Volumes/" + (leads(to: rest.startIndex + 2).lazy.compactMap(nameRead).first ?? rest[rest.startIndex + 2])
                rest = rest.dropFirst(3)
            } else if rest.count >= 2, same(rest[rest.startIndex], "Volumes") {
                (root, isPersonal) = ("/Volumes/<volume>", true)
                rest = rest.dropFirst(2)
            }
            if dropHome() {
                (root, isAccount) = (root + "<home>", true)
            } else if rest.count >= 2, same(rest[rest.startIndex], "Users") {
                // /Users/Shared is no account, but what is in it is still the user's.
                root += same(rest[rest.startIndex + 1], "Shared") ? "/Users/Shared" : "/Users/<other-user>"
                rest = rest.dropFirst(2)
                isAccount = true
            } else if !isPersonal {
                return path
            }
        }
        var kept: [String] = []
        if isAccount, rest.count > 1, let first = rest.first, Self.homeFolders.contains(first) {
            kept.append(first)
            rest = rest.dropFirst()
            if first == "Library", rest.count > 1, let second = rest.first, Self.libraryFolders.contains(second) {
                kept.append(second)
                rest = rest.dropFirst()
            }
        }
        var tail = rest.count > 1 ? ["<folders>", rest[rest.endIndex - 1]] : Array(rest)
        // Straight inside a Users or a Volumes folder the last part is an account's or a
        // disk's name where the passes over text read one: when that folder stands straight
        // after the home, after a disk's own folder, or after a mark, which a second slash
        // is. The passes themselves are asked, so the two cannot differ, and about each way
        // to read the path: as it is written, which is how they would have met it, as the
        // file system reads it, and with the home where this found it. One yes replaces the
        // part, whole and whatever it holds. Inside any other folder of the name
        // ("api/users/server") the last part is the file's own name, and /Users/Shared is no
        // account.
        let isNamesFolder = all.count > 1 && all[all.count - 2].range(
            of: "^(?:Users|Volumes)$", options: [.regularExpression, .caseInsensitive]) != nil
        if isNamesFolder, let last = rest.last {
            var ways = leads(to: all.count - 1)
            if root.hasSuffix("<home>") { ways.append("<home>/" + (kept + rest.dropLast()).map { $0 + "/" }.joined()) }
            if let name = ways.lazy.compactMap(nameRead).first, !(name == "<other-user>" && same(last, "Shared")) {
                // The root has taken the folder where it read it as a disk's or an account's name.
                let folder = rest.count > 1 ? (rest.count > 2 ? ["<folders>"] : []) + [rest[rest.endIndex - 2]] : []
                tail = folder + [name]
            }
        }
        return ([root] + kept + tail).joined(separator: "/")
    }

    /// The placeholder the passes over text put for a name that stands straight after `lead`,
    /// the start of a path up to a slash: an account's or a disk's, where they read one.
    private func nameRead(after lead: String) -> String? {
        let read = redactFolders(redactHome(lead) + "x")
        return ["<volume>", "<other-user>"].first(where: read.hasSuffix)
    }

    func redact(_ text: String, as context: Context) -> String {
        let captured = context != .instructions
        var out = text
        // Home path before username: the path contains the username.
        out = redactHome(out)
        // Before any name: a disk's or a folder's name can hold the login.
        if captured { out = redactFolders(out) }
        // Before the login: an address that starts with it would keep its domain.
        if captured { out = out.replacingOccurrences(of: Self.email, with: "<email>", options: .regularExpression) }
        out = redactMachineNames(out, in: context)
        // After the machine's names, so this Mac's own MagicDNS name reads as the machine. A
        // peer's is device.tailnet.ts.net, and the tailnet's name identifies the account. A
        // label can hold "_", which DNS allows outside host names.
        if captured {
            out = out.replacingOccurrences(
                of: Self.wholeHost("[a-z0-9_-]+(?:\\.[a-z0-9_-]+)*\\.ts\\.net"),
                with: "<tailnet-device>", options: [.regularExpression, .caseInsensitive])
        }
        if context == .host { out = redactPrivateHosts(out) }
        out = redactUsername(out, in: context)
        return Self.redactAddresses(out, spelledWithHyphens: captured)
    }

    /// On a path boundary: home "/Users/u" must not take the front off "/Users/user/...".
    /// In any case, as APFS reads a path.
    private func redactHome(_ text: String) -> String {
        guard !home.isEmpty else { return text }
        let pattern = Self.pathStart + NSRegularExpression.escapedPattern(for: home) + Self.pathEnd
        return text.replacingOccurrences(of: pattern, with: "<home>", options: [.regularExpression, .caseInsensitive])
    }

    /// An email address, whoever's: a cloud drive names its folder with one. The domain's last
    /// label is letters and its first is not a number, so a package's version ("python@3.12",
    /// "pkg@1.2.3") and a login at a terminal ("user@ttys003") are not one. Whatever else has
    /// the shape is read as one ("pkg@latest.tgz").
    private static let email = "(?<![\\w.%+-])[\\w.%+-]+@(?!\\d+\\.)(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}(?![\\w-])"

    /// Where a text can say it is this Mac. A host is, only when all of it is one of the Mac's
    /// names: "dev.azure.com" is not the Mac called dev. A process's name is its author's, so
    /// a Mac's name in it is a coincidence. A launch item can be named for its Mac only as the
    /// author's part of its label. Edited instructions read as prose: the name matches as a
    /// word or a first label, so "Apple Development" and "pages.dev" stay whole on a Mac called
    /// dev and "dev.lan" reads <machine>.lan. Either apostrophe matches: macOS stores a curly
    /// one in the computer name, and other text often has a straight one.
    private func redactMachineNames(_ text: String, in context: Context) -> String {
        let bounded: (String) -> String
        switch context {
        case .program: return text
        case .host: bounded = Self.wholeHost
        case .launchItem: bounded = Self.authorPart
        case .instructions: bounded = { "(?<![A-Za-z0-9-])(?<![A-Za-z0-9-]\\.)" + $0 + "(?![A-Za-z0-9-])" }
        }
        var out = text
        for name in machineNames.sorted(by: { $0.count > $1.count }) {
            let escaped = NSRegularExpression.escapedPattern(for: name)
                .replacingOccurrences(of: "['’]", with: "['’]", options: .regularExpression)
            out = out.replacingOccurrences(of: bounded(escaped), with: "<machine>", options: [.regularExpression, .caseInsensitive])
        }
        return out
    }

    /// Endings no public name has: Bonjour's, the ones routers and private networks give, and
    /// the ones reserved for them.
    private static let privateEndings = ["local", "lan", "internal", "home.arpa", "home", "corp", "localdomain"]

    /// A host's name only this network resolves says what is on it ("payroll-db.corp.example.com",
    /// "users-nas.local"), and it can stand at a public address. Under a private ending the
    /// ending stays: it says what kind of network the name is from, and is the same on every
    /// one. A search domain names the network, so a name under one goes whole; the domain alone
    /// is not a host on it.
    private func redactPrivateHosts(_ text: String) -> String {
        let labels = "(?:[a-z0-9_-]+\\.)+"
        let endings = Self.privateEndings.map(NSRegularExpression.escapedPattern).joined(separator: "|")
        var out = text.replacingOccurrences(
            of: Self.wholeHost(labels + "(" + endings + ")"), with: "<private-host>.$1", options: [.regularExpression, .caseInsensitive])
        for domain in searchDomains.sorted(by: { $0.count > $1.count }) where !domain.isEmpty {
            out = out.replacingOccurrences(
                of: Self.wholeHost(labels + NSRegularExpression.escapedPattern(for: domain)),
                with: "<private-host>", options: [.regularExpression, .caseInsensitive])
        }
        return out
    }

    /// The author's part of a reverse-DNS name that is not a host: the label straight after a
    /// leading com, org, net or io, with another label following, as in "com.username.helper". Any
    /// other label is a product or an extension, so "at.obdev.x", "server.js" and
    /// "com.apple.mail.x" stay whole for a user called at, js or mail. A script's extension as
    /// the last label does not count as the one following: "io.server.js" is a file. A login
    /// item's id can carry macOS's number first ("8.com.username.helper").
    private static func authorPart(_ name: String) -> String {
        "(?<=(?<![\\w.-])(?:\\d{1,10}\\.)?(?:com|org|net|io)\\.)" + name + "(?=\\.[\\w-])(?!\\." + scriptExtension + "(?![\\w.-]))"
    }

    private static let scriptExtension = "(?:sh|bash|zsh|ksh|csh|tcsh|command|py|pl|rb|php|js|mjs|cjs|ts|lua|tcl|exp|awk|scpt|applescript)"

    /// Another account's folder names that account, and a disk's name is the user's own words.
    /// /Users/Shared is no account. A mounted disk is found by its whole name; any other path
    /// under /Volumes loses one word, since text cannot show where a name with spaces ends.
    private func redactFolders(_ text: String) -> String {
        let volumes = "(?i)" + Self.pathStart + "/Volumes/"
        var out = text
        for name in volumeNames.sorted(by: { $0.count > $1.count }) {
            out = out.replacingOccurrences(
                of: volumes + NSRegularExpression.escapedPattern(for: name) + Self.pathEnd,
                with: "/Volumes/<volume>", options: .regularExpression)
        }
        return out
            .replacingOccurrences(of: volumes + Self.pathName, with: "/Volumes/<volume>", options: .regularExpression)
            .replacingOccurrences(
                of: "(?i)" + Self.pathStart + "/Users/(?!Shared" + Self.pathEnd + ")" + Self.pathName,
                with: "/Users/<other-user>", options: .regularExpression)
    }

    /// The login matches only as written, so the login "code" leaves the app "Code" alone.
    /// In a host it matches only as a whole name, so "mail.google.com" and
    /// "mail-attachment.example" stay whole for a user called mail. Elsewhere a label of a
    /// dotted name goes only as its author's part, and in edited instructions not at all. A
    /// dot that ends a sentence does not join a label.
    ///
    /// A login of one or two letters would match ordinary text ("-e"), so it goes only where
    /// a login stands: before an "@" ("e@ttys003"), first after the program in a process title
    /// ("postgres: u db") and as the author's part of a dotted name. Where it appears in a path
    /// the home replacement covers it; the facts built for a prompt never carry it as "you
    /// (u)" (UserName.describeForModel).
    private func redactUsername(_ text: String, in context: Context) -> String {
        guard !username.isEmpty else { return text }
        let login = NSRegularExpression.escapedPattern(for: username)
        var out = text
        if username.count >= 3 {
            let pattern = context == .host ? Self.wholeHost(login) : "(?<![\\w-]\\.)\\b" + login + "\\b(?!\\.[\\w-])"
            out = out.replacingOccurrences(of: pattern, with: "<user>", options: .regularExpression)
        } else if context != .instructions {
            out = out
                .replacingOccurrences(of: "(?<![\\w.+-])" + login + "(?=@)", with: "<user>", options: .regularExpression)
                .replacingOccurrences(of: "(?m)^([\\w.-]+: )" + login + "(?=\\s|$)", with: "$1<user>", options: .regularExpression)
        }
        if context == .program || context == .launchItem {
            out = out.replacingOccurrences(of: Self.authorPart(login), with: "<user>", options: .regularExpression)
        }
        return out
    }

    /// Replaces private and local IP addresses only. The hyphen spelling belongs to host names;
    /// in the user's own words the same digits are just numbers.
    static func redactAddresses(_ text: String, spelledWithHyphens: Bool = true) -> String {
        redactIPv6(redactIPv4(text, forms: spelledWithHyphens ? [ipv4, hyphenatedIPv4] : [ipv4]))
    }

    private static let ipv4 = try! NSRegularExpression(
        pattern: "\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b")

    /// An address spelled with hyphens in a host name ("ip-10-0-1-5.ec2.internal"): exactly
    /// four numbers, so a longer run of them is not read as one.
    private static let hyphenatedIPv4 = try! NSRegularExpression(
        pattern: "(?<!\\d)(?<!\\d-)(\\d{1,3})-(\\d{1,3})-(\\d{1,3})-(\\d{1,3})(?!-?\\d)")

    /// RFC 1918, loopback, link-local and CGNAT ranges.
    static func isPrivateIPv4(_ octets: [Int]) -> Bool {
        guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }) else { return false }
        switch (octets[0], octets[1]) {
        case (10, _), (127, _), (192, 168), (169, 254): return true
        case (172, 16...31): return true
        case (100, 64...127): return true
        default: return false
        }
    }

    /// The value is written out once, piece by piece: whoever wrote it picks how many addresses
    /// it holds, and a copy of the whole for each would take time by their square.
    private static func redactIPv4(_ text: String, forms: [NSRegularExpression]) -> String {
        forms.reduce(text) { text, form in
            let ns = text as NSString
            var out = ""
            var end = 0
            for match in form.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let octets = (1...4).compactMap { Int(ns.substring(with: match.range(at: $0))) }
                guard isPrivateIPv4(octets) else { continue }
                out += ns.substring(with: NSRange(location: end, length: match.range.location - end)) + "<private-ip>"
                end = match.range.location + match.range.length
            }
            return end == 0 ? text : out + ns.substring(from: end)
        }
    }

    /// Link-local (fe80::/10), unique local (fc00::/7) and loopback (::1).
    private static let ipv6 = try! NSRegularExpression(
        pattern: "(?i)\\b(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f])(?::[0-9a-f]{0,4}){1,7}(?:%[a-z0-9]+)?|(?<![0-9a-f:])::1\\b")

    private static func redactIPv6(_ text: String) -> String {
        ipv6.stringByReplacingMatches(
            in: text, range: NSRange(location: 0, length: (text as NSString).length),
            withTemplate: "<private-ip>")
    }
}
