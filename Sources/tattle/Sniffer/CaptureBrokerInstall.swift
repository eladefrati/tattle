import CCodePolicy
import Foundation
import Security

/// Installing and removing the packet-access broker through the administrator dialog
/// (ADR-0003 decision 4), and the identity of this build that install pins.
extension CaptureBroker {
    enum InstallError: Error, Equatable {
        case noHelperInBundle
        /// The running app has no signature the broker could check callers against.
        case unsigned
        /// The app's executable on disk is not the code that is running: replaced or rebuilt
        /// since launch. Install would pin the wrong build, so it does not start.
        case changedOnDisk
        /// The broker would refuse this build (code_policy.h), so installing it gains nothing.
        case notHardened
        /// The administrator dialog was cancelled or the script failed; the message is
        /// osascript's, which carries the script's own sentence.
        case failed(String)

        /// What the user reads, never the case name.
        var text: String {
            switch self {
            case .noHelperInBundle: "This copy of Tattle has no packet-access broker inside it. Build it with make app, or download Tattle again."
            case .unsigned: "This copy of Tattle has no code signature the broker could check. Build it with make app."
            case .changedOnDisk: "Tattle's files on disk changed after it started, for instance by a rebuild. Quit Tattle, open it again, and try again."
            case .notHardened: "This copy of Tattle is not signed with the hardened runtime, so the broker would refuse it. Build it with make app."
            case .failed(let message): message.isEmpty ? "The administrator dialog was cancelled." : message
            }
        }
    }

    /// Where the broker sits in the app bundle. Root installs it from its own verified copy of
    /// the bundle, at this same path.
    static let helperInBundle = "Contents/MacOS/tattle-capture-broker"

    // MARK: Identity

    /// An architecture as codesign names it. Its name goes into a command root runs, so only
    /// the two Tattle is built for exist.
    struct Architecture: Equatable, Sendable {
        let name: String

        init?(_ name: String) {
            guard ["arm64", "x86_64"].contains(name) else { return nil }
            self.name = name
        }

        /// The slice this code was compiled into, which is the slice that runs.
        static let running: Architecture = {
            #if arch(arm64)
            Architecture("arm64")!
            #elseif arch(x86_64)
            Architecture("x86_64")!
            #else
            #error("Tattle is built for arm64 and x86_64 only")
            #endif
        }()
    }

    /// This build of Tattle, as its signature names it. Every field is checked on the way in,
    /// so the requirements built from it compile and a crafted identifier or team cannot end
    /// the quoted string and add a clause.
    struct BuildIdentity: Equatable, Sendable {
        /// Code directory hash of the main executable's running slice: each slice of a
        /// universal build has its own.
        let cdhash: Data
        let identifier: String
        /// The Apple team when signed with an Apple identity; nil ad hoc.
        let team: String?
        /// The slice `cdhash` belongs to. Never taken from a caller.
        let architecture = Architecture.running

        /// Nil unless `cdhash` is 20 bytes, `identifier` is 1 to 255 of letters, digits, '.'
        /// and '-', and `team` is absent or 10 uppercase letters and digits.
        init?(cdhash: Data, identifier: String, team: String?) {
            func only(_ text: String, _ allowed: (Character) -> Bool) -> Bool { text.allSatisfy { $0.isASCII && allowed($0) } }
            guard cdhash.count == 20, (1...255).contains(identifier.count),
                  only(identifier, { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }) else { return nil }
            if let team, !(team.count == 10 && only(team, { $0.isUppercase || $0.isNumber })) { return nil }
            self.cdhash = cdhash
            self.identifier = identifier
            self.team = team
        }

        /// What the broker checks callers against (ADR-0003). With a team: the team and the
        /// identifier, which survive rebuilds and certificate renewal, admitting the release
        /// app and its dev copy alike. Both builds produce the same text, so neither reads the
        /// other's install as stale. Ad hoc: this build's running slice, so a universal build run
        /// under Rosetta is another build to the broker.
        var callerRequirement: String {
            if let team {
                let release = identifier.hasSuffix(Self.devSuffix) && identifier.count > Self.devSuffix.count
                    ? String(identifier.dropLast(Self.devSuffix.count)) : identifier
                return "anchor apple generic and (identifier \"\(release)\" or identifier \"\(release)\(Self.devSuffix)\")"
                    + " and certificate leaf[subject.OU] = \"\(team)\""
            }
            return buildRequirement
        }

        /// What `make run` appends to the bundle identifier for the dev copy.
        static let devSuffix = ".dev"

        /// This exact build, in either signing mode.
        var buildRequirement: String { "cdhash H\"\(cdhash.map { String(format: "%02x", $0) }.joined())\"" }

        /// The running app, confirmed against the code the kernel loaded.
        static func running() throws -> BuildIdentity {
            var selfCode: SecCode?
            guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let code = selfCode else { throw InstallError.unsigned }
            return try confirmed(code)
        }

        /// Reads `code`'s signature from its file, then confirms it describes the code that is
        /// running and that the broker would answer that code. `running()` passes this app;
        /// tests pass another process.
        static func confirmed(_ code: SecCode) throws -> BuildIdentity {
            var staticCode: SecStaticCode?
            var infoRef: CFDictionary?
            guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let fixed = staticCode,
                  SecCodeCopySigningInformation(fixed, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef) == errSecSuccess,
                  let info = infoRef as? [String: Any],
                  let cdhash = info[kSecCodeInfoUnique as String] as? Data,
                  let identifier = info[kSecCodeInfoIdentifier as String] as? String
            else { throw InstallError.unsigned }
            let team = (info[kSecCodeInfoTeamIdentifier as String] as? String).flatMap { $0.isEmpty ? nil : $0 }
            guard let identity = BuildIdentity(cdhash: cdhash, identifier: identifier, team: team) else { throw InstallError.unsigned }
            // Any process of this user may have renamed another binary over the file since
            // launch, and the file is what was just read. The dynamic check compares against the
            // code directory the kernel loaded: a changed file fails it (errSecCSStaticCodeChanged),
            // and a file changed back since the read fails the hash.
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString("\(identity.callerRequirement) and \(identity.buildRequirement)" as CFString, [], &requirement) == errSecSuccess,
                  let requirement, SecCodeCheckValidity(code, [], requirement) == errSecSuccess
            else { throw InstallError.changedOnDisk }
            guard tattle_code_hardening(code) == TATTLE_HARDENING_OK else { throw InstallError.notHardened }
            return identity
        }
    }

    // MARK: Layout

    /// Where install and remove put things. `.system` is the only layout the app uses; tests
    /// render the same scripts against a temporary directory and a stand-in launchctl, which
    /// is how the root scripts are run without root.
    struct Layout: Sendable {
        let helperDirectory: String
        let daemonsDirectory: String
        let service: Service
        /// Who owns what is installed: "root:wheel", or a test's own account.
        let owner: String
        let launchctl: String

        var helperPath: String { "\(helperDirectory)/\(label)" }
        var plistPath: String { "\(daemonsDirectory)/\(label).plist" }

        static let system = Layout(helperDirectory: "/Library/PrivilegedHelperTools", daemonsDirectory: "/Library/LaunchDaemons",
                                   service: .system, owner: "root:wheel", launchctl: "/bin/launchctl")
    }

    // MARK: What is installed

    /// What is installed, judged against what this build would install for this user.
    /// `NetworkObserver` owns the current one; views read it, never the disk.
    struct Status: Equatable, Sendable {
        let installation: Installation
        /// The launch daemon this build installs, the same text `install()` puts in the script,
        /// or why this build cannot install one.
        let proposed: Result<String, InstallError>
        /// The installed plist, when there is one and it is not `proposed`.
        let installed: String?
    }

    enum Installation: Equatable, Sendable {
        /// Neither the plist nor the broker is there.
        case absent
        /// This build's plist and broker, for this user, and launchd is running it.
        case current
        case stale(Staleness)
    }

    enum Staleness: Equatable, Sendable {
        /// Only one of the plist and the broker is there: an install or removal was cut short.
        case incomplete
        /// This build's, but launchd holds no job for it.
        case notLoaded
        /// Installed for another account, which the broker answers instead of this one.
        case otherUser(uid_t)
        /// Another build's plist or broker. Ad hoc, the broker refuses this build; with an
        /// Apple identity it may still serve it.
        case otherBuild
    }

    /// Reads the installed plist and broker and judges them against this build.
    static func status(bundle: URL = Bundle.main.bundleURL, identity: () throws -> BuildIdentity = BuildIdentity.running,
                       uid: uid_t = getuid(), layout: Layout = .system) -> Status {
        let bundled = bundle.appending(path: helperInBundle).path
        let proposed = Result { () throws -> String in
            guard FileManager.default.fileExists(atPath: bundled) else { throw InstallError.noHelperInBundle }
            return plist(requirement: try identity().callerRequirement, uid: uid, layout: layout)
        }.mapError { $0 as? InstallError ?? .unsigned }
        let text = try? String(contentsOfFile: layout.plistPath, encoding: .utf8)
        let installed = text == (try? proposed.get()) ? nil : text
        guard let text else {
            return Status(installation: FileManager.default.fileExists(atPath: layout.helperPath) ? .stale(.incomplete) : .absent,
                          proposed: proposed, installed: nil)
        }
        let installation: Installation
        if !FileManager.default.fileExists(atPath: layout.helperPath) {
            installation = .stale(.incomplete)
        } else if let other = installedUID(text), other != uid {
            installation = .stale(.otherUser(other))
        } else if (installed == nil || (try? proposed.get()) == nil), let hash = cdhash(atPath: layout.helperPath), hash == cdhash(atPath: bundled) {
            // Code hash, not bytes: re-signing the same code changes the bytes but not the hash.
            // When this build cannot say what it would install, the broker alone is compared.
            installation = isRegistered(layout.service) ? .current : .stale(.notLoaded)
        } else {
            installation = .stale(.otherBuild)
        }
        return Status(installation: installation, proposed: proposed, installed: installed)
    }

    /// The `--uid` value in an installed plist's ProgramArguments.
    private static func installedUID(_ plist: String) -> uid_t? {
        guard let parsed = try? PropertyListSerialization.propertyList(from: Data(plist.utf8), format: nil) as? [String: Any],
              let arguments = parsed["ProgramArguments"] as? [String],
              let flag = arguments.firstIndex(of: "--uid"), flag + 1 < arguments.count else { return nil }
        return uid_t(arguments[flag + 1])
    }

    /// The code hash of the signed file at `path`, from its own signature.
    private static func cdhash(atPath path: String) -> Data? {
        var code: SecStaticCode?
        var info: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(filePath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, [], &info) == errSecSuccess else { return nil }
        return (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data
    }

    // MARK: Install and remove

    /// The launch daemon as installed: the requirement and the installing user travel in the
    /// root-owned plist, where only an administrator can change them.
    static func plist(requirement: String, uid: uid_t, layout: Layout = .system) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(layout.helperPath)</string>
                <string>--requirement</string>
                <string>\(escapeXML(requirement))</string>
                <string>--uid</string>
                <string>\(uid)</string>
                <string>--service</string>
                <string>\(layout.service.name)</string>
            </array>
            <key>MachServices</key>
            <dict>
                <key>\(layout.service.name)</key>
                <true/>
            </dict>
        </dict>
        </plist>

        """
    }

    /// What the administrator dialog runs, in plain words for the person reading it.
    static let installExplanation = """
        Names for connections come from the first packets of each one and from this Mac's DNS \
        lookups and their replies, which only a root process may read. Tattle installs a small \
        daemon that opens the capture device read-only and hands it only to a program carrying \
        Tattle's signature, which it checks for whoever asks. A program holding the device can \
        read every packet in full, on any network interface, including other machines' packets \
        that reach this Mac; Tattle reads only those packets. On a Mac that holds the key that \
        signed this build, any program you run can make that signature. The daemon has no \
        other function, keeps no descriptor, and is removed with one click here or from the \
        Startup tab. The packet devices themselves stay root-only.
        """

    /// The root half of install. Root reads the user's bundle once, to copy it where no
    /// process of the user can reach, and uses nothing but that copy and this text: it
    /// checks the copy against `identity`, which the app confirmed is the running code and
    /// whose seal fixes the bundled broker, then installs the broker from the copy and the
    /// plist from this text. Nothing on the system changes until the copy has passed, and a
    /// failure after the old broker was stopped removes what this install put in place.
    static func installScript(identity: BuildIdentity, bundle: URL, uid: uid_t, layout: Layout = .system) -> String {
        """
        set -eu
        umask 077
        launchctl=\(shell(layout.launchctl))
        helper=\(shell(layout.helperPath))
        plist=\(shell(layout.plistPath))
        /bin/mkdir -p -m 755 \(shell(layout.helperDirectory)) \(shell(layout.daemonsDirectory))
        \(purgeFunction)
        # An old stage that cannot be deleted must not stop this install.
        purge \(shell(layout.helperDirectory))/.\(label).* || true
        stage=$(/usr/bin/mktemp -d \(shell("\(layout.helperDirectory)/.\(label).XXXXXX")))
        replacing=0
        finish() {
            status=$?
            purge "$stage" || true
            if [ "$status" -ne 0 ] && [ "$replacing" -eq 1 ]; then
                "$launchctl" bootout system/\(label) 2>/dev/null || true
                /bin/rm -f "$plist" "$helper"
            fi
            exit "$status"
        }
        trap finish EXIT
        \(stoppedFunction)
        /usr/bin/ditto --noextattr --noqtn --norsrc --noacl \(shell(bundle.path)) "$stage/Tattle.app"
        if [ -n "$(/usr/bin/find "$stage/Tattle.app" ! -type f ! -type d -print)" ]; then
            echo 'This copy of Tattle contains links or special files, so it cannot be checked. Nothing was installed.' >&2
            exit 3
        fi
        # ditto keeps a Finder lock, and a locked file's owner cannot be changed, even by root.
        # The Finder sets only the user's flags; a system flag reaches chown and fails there.
        if [ -n "$(/usr/bin/find "$stage/Tattle.app" -flags +uchg,uappnd -print)" ]; then
            echo 'A file inside this copy of Tattle is locked in the Finder, so it cannot be checked. Download or build Tattle again. Nothing was installed.' >&2
            exit 3
        fi
        /usr/sbin/chown -R \(shell(layout.owner)) "$stage"
        # codesign checks every slice unless told one, and each slice has its own hash. The
        # running slice's pins the seal; root never runs the main executable, and the plist
        # names that slice alone, so another slice beside it gains nothing. With -a, --deep checks
        # the broker at that slice only; the check after this one covers every slice.
        if ! /usr/bin/codesign --verify --strict --deep -a \(shell(identity.architecture.name)) \(shell("-R=\(identity.buildRequirement)")) "$stage/Tattle.app" 2>/dev/null; then
            echo 'Tattle on disk is not the Tattle that is running. Quit Tattle, open it again, and try again. Nothing was installed.' >&2
            exit 3
        fi
        new="$stage/Tattle.app/\(helperInBundle)"
        /bin/test -f "$new"
        # --deep checked the broker only against the requirement the seal records beside it, which
        # with a team names no hash; the seal also records the broker's own code hash, of one
        # slice. Root runs whichever slice suits the Mac, so every slice is checked: one can
        # match while another is foreign.
        \(brokerRequirementFunction)
        codeResources="$stage/Tattle.app/Contents/_CodeSignature/CodeResources"
        sealed=$(/usr/bin/plutil -extract \(shell("files2.\(helperInBundle.dropFirst("Contents/".count)).cdhash")) raw -o - "$codeResources" 2>/dev/null | /usr/bin/base64 -D | /usr/bin/od -An -v -tx1 | /usr/bin/tr -d ' \\n')
        recorded=$(/usr/bin/plutil -extract \(shell("files2.\(helperInBundle.dropFirst("Contents/".count)).requirement")) raw -o - "$codeResources" 2>/dev/null || true)
        requirement=$(broker_requirement "$sealed" "$recorded")
        if [ ${#sealed} -ne 40 ] || ! /usr/bin/codesign --verify --strict -R="$requirement" "$new" 2>/dev/null; then
            echo 'The broker inside Tattle is not the one this build of Tattle was sealed with. Download or build Tattle again. Nothing was installed.' >&2
            exit 3
        fi
        /bin/chmod 755 "$new"
        /usr/bin/printf '%s' \(shell(plist(requirement: identity.callerRequirement, uid: uid, layout: layout))) > "$stage/plist"
        /usr/bin/plutil -lint -s "$stage/plist"
        /bin/chmod 644 "$stage/plist"
        "$launchctl" bootout system/\(label) 2>/dev/null || true
        if ! stopped; then
            echo 'The installed broker was told to stop and had not within two seconds, so its files were left as they are. Try again.' >&2
            exit 3
        fi
        replacing=1
        /bin/mv -f "$new" "$helper"
        /bin/mv -f "$stage/plist" "$plist"
        "$launchctl" bootstrap system "$plist"
        """
    }

    /// Stops the broker before anything is removed, and removes the plist first: without it
    /// the broker no longer reads as installed, whatever else a cut-short removal leaves.
    static func removeScript(layout: Layout = .system) -> String {
        """
        set -u
        launchctl=\(shell(layout.launchctl))
        \(stoppedFunction)
        "$launchctl" bootout system/\(label) 2>/dev/null || true
        if ! stopped; then
            echo 'The packet-access broker was told to stop and had not within two seconds, so its files were left in place. Try again.' >&2
            exit 3
        fi
        # Each removal is tried whatever the one before did; one that failed fails the script.
        status=0
        /bin/rm -f \(shell(layout.plistPath)) || status=1
        /bin/rm -f \(shell(layout.helperPath)) || status=1
        \(purgeFunction)
        purge \(shell(layout.helperDirectory))/.\(label).* || status=1
        exit "$status"
        """
    }

    /// Deletes stages. A file locked in Finder (uchg) is copied locked by ditto, and rm cannot
    /// delete it until the flag is cleared.
    private static let purgeFunction = """
        purge() {
            /usr/bin/chflags -R nouchg,nouappnd "$@" 2>/dev/null || true
            /bin/rm -rf "$@"
        }
        """

    /// Prints the requirement every slice of the broker must meet, given the code hash the seal
    /// records for the broker and the requirement it records beside it. Ad hoc, the recorded
    /// requirement names each slice's hash, and it is used only when it is hash clauses alone,
    /// on one line, naming the sealed hash: a clause besides would admit more than this build.
    /// Otherwise the sealed hash alone, which pins a broker of one slice and refuses a
    /// universal broker signed by a team, whose recorded requirement names no hash.
    static let brokerRequirementFunction = """
        broker_requirement() {
            recorded=$2
            case "$recorded" in
                *[![:print:]]*) recorded= ;;
                *"H\\"$1\\""*) ;;
                *) recorded= ;;
            esac
            if [ -n "$recorded" ] && /usr/bin/printf '%s\\n' "$recorded" | /usr/bin/grep -Eqx 'cdhash H"[0-9a-f]{40}"( or cdhash H"[0-9a-f]{40}")*'; then
                /usr/bin/printf '%s\\n' "$recorded"
            else
                /usr/bin/printf 'cdhash H"%s"\\n' "$1"
            fi
        }
        """

    /// True once launchd no longer knows the job: bootout can return before it has exited.
    private static let stoppedFunction = """
        stopped() {
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                "$launchctl" print system/\(label) >/dev/null 2>&1 || return 0
                /bin/sleep 0.2
            done
            return 1
        }
        """

    /// Installs the broker for this build and this user through the administrator dialog.
    /// Returns the plist text that was installed, which is the one Packet access showed.
    @discardableResult
    static func install(bundle: URL = Bundle.main.bundleURL, identity: () throws -> BuildIdentity = BuildIdentity.running, uid: uid_t = getuid(),
                        layout: Layout = .system, runPrivileged: (String) throws -> Void = runPrivileged) throws -> String {
        guard FileManager.default.fileExists(atPath: bundle.appending(path: helperInBundle).path) else { throw InstallError.noHelperInBundle }
        let identity = try identity()
        // The bundle's path can name the user's home folder, and so can the script's error,
        // which carries ditto's message about the copy: both stay private in the log.
        Log.sniffer.notice("installing the packet-access broker from \(bundle.path)")
        do {
            try runPrivileged(installScript(identity: identity, bundle: bundle, uid: uid, layout: layout))
        } catch {
            Log.sniffer.error("broker install failed: \(String(describing: error))")
            throw error
        }
        Log.sniffer.notice("packet-access broker installed")
        return plist(requirement: identity.callerRequirement, uid: uid, layout: layout)
    }

    static func remove(layout: Layout = .system, runPrivileged: (String) throws -> Void = runPrivileged) throws {
        Log.sniffer.notice("removing the packet-access broker")
        do {
            try runPrivileged(removeScript(layout: layout))
        } catch {
            Log.sniffer.error("broker removal failed: \(String(describing: error), privacy: .public)")
            throw error
        }
    }

    /// osascript, set up to run `script` as root after the administrator password dialog.
    /// It gets a fixed environment, not Tattle's: the user can set Tattle's (launchctl setenv
    /// reaches apps launched after it), and /bin/sh runs code from SHELLOPTS, PS4 and exported
    /// functions before the script's first line. Whether the root shell would inherit it is
    /// not something to rely on either way.
    static func privilegedProcess(_ script: String) -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "do shell script \(appleScript(script)) with administrator privileges"]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        return process
    }

    /// Runs a shell script as root after the administrator password dialog.
    static func runPrivileged(_ script: String) throws {
        let process = privilegedProcess(script)
        let err = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = err
        try process.run()
        let stderr = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw InstallError.failed(stderr.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    // MARK: Quoting

    static func shell(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    static func appleScript(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func escapeXML(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
    }
}
