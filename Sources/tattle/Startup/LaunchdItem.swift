import Foundation

/// One launchd job read from a property list in an agents or daemons folder.
struct LaunchdItem: Equatable, Sendable {
    enum Scope: String, CaseIterable, Sendable {
        /// ~/Library/LaunchAgents: runs as this user, at login.
        case userAgent
        /// /Library/LaunchAgents: runs as whoever logs in.
        case globalAgent
        /// /Library/LaunchDaemons: runs as root at boot.
        case daemon

        var folder: URL {
            switch self {
            case .userAgent: FileManager.default.homeDirectoryForCurrentUser.appending(path: "Library/LaunchAgents")
            case .globalAgent: URL(fileURLWithPath: "/Library/LaunchAgents")
            case .daemon: URL(fileURLWithPath: "/Library/LaunchDaemons")
            }
        }

        var title: String {
            switch self {
            case .userAgent: "Your agents"
            case .globalAgent: "Agents for all users"
            case .daemon: "Daemons"
            }
        }
    }

    var label: String
    var scope: Scope
    var plistURL: URL
    /// The executable: `Program`, or the first of `ProgramArguments`.
    var program: String?
    /// Arguments after argv[0], the first of `ProgramArguments`.
    var arguments: [String]
    /// The PATH the plist sets for the job (`EnvironmentVariables`); nil when the job runs
    /// with launchd's own.
    var environmentPath: String? = nil
    /// The folder launchd changes the root to before it starts the job (`RootDirectory`).
    var rootDirectory: String? = nil
    var triggers: [Trigger]
    /// `LimitLoadToSessionType`: the sessions this agent loads in; empty for the default.
    var sessionTypes: [String] = []
    /// `Disabled` in the plist. launchd's own override state comes from launchctl.
    var disabled: Bool
    var associatedBundleIdentifiers: [String]
    /// An empty plist: launchd ignores it, nothing runs. Updaters leave these behind, or
    /// write them to block themselves.
    var isPlaceholder: Bool = false

    /// Where launchd loads this job: a daemon in the system domain, an agent in the GUI
    /// session unless its plist limits it. `Background` agents load in `user/<uid>`, as all
    /// of Apple's do; any other mix of session types is looked for in both.
    var domains: [LaunchDomain] {
        if scope == .daemon { return [.system] }
        if sessionTypes.isEmpty || sessionTypes == ["Aqua"] { return [.gui] }
        if sessionTypes == ["Background"] { return [.user] }
        return [.gui, .user]
    }

    enum ParseError: Error, Equatable {
        case notADictionary
        case noLabel
    }

    /// Reads one plist. Unknown keys are ignored; a plist without a label is rejected
    /// because launchd rejects it too.
    static func parse(_ data: Data, url: URL, scope: Scope) throws -> LaunchdItem {
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { throw ParseError.notADictionary }
        if plist.isEmpty {
            return LaunchdItem(
                label: url.deletingPathExtension().lastPathComponent, scope: scope, plistURL: url,
                program: nil, arguments: [], triggers: [], disabled: false,
                associatedBundleIdentifiers: [], isPlaceholder: true)
        }
        guard let label = plist["Label"] as? String, !label.isEmpty else { throw ParseError.noLabel }

        let programArguments = plist["ProgramArguments"] as? [String] ?? []
        let program = plist["Program"] as? String ?? programArguments.first
        // ProgramArguments[0] is argv[0] even when Program names the executable.
        let arguments = Array(programArguments.dropFirst())

        return LaunchdItem(
            label: label, scope: scope, plistURL: url, program: program, arguments: arguments,
            environmentPath: (plist["EnvironmentVariables"] as? [String: Any])?["PATH"] as? String,
            rootDirectory: plist["RootDirectory"] as? String,
            triggers: Trigger.triggers(in: plist),
            sessionTypes: plist["LimitLoadToSessionType"] as? [String] ?? (plist["LimitLoadToSessionType"] as? String).map { [$0] } ?? [],
            disabled: plist["Disabled"] as? Bool ?? false,
            associatedBundleIdentifiers: plist["AssociatedBundleIdentifiers"] as? [String]
                ?? (plist["AssociatedBundleIdentifiers"] as? String).map { [$0] } ?? [])
    }
}

/// When launchd starts a job. A job can have several.
enum Trigger: Equatable, Sendable {
    /// `RunAtLoad`: when the job is loaded, which for agents is login and for daemons boot.
    case atLoad
    /// `KeepAlive`: restarted whenever it exits.
    case keepAlive
    /// `StartInterval`.
    case interval(seconds: Int)
    /// `StartCalendarInterval`.
    case calendar([CalendarEntry])
    /// `WatchPaths` and `QueueDirectories`.
    case watchPaths([String])
    /// `MachServices`, `Sockets` or `LaunchEvents`: started when something asks for it.
    case onDemand

    struct CalendarEntry: Equatable, Sendable {
        var minute: Int?
        var hour: Int?
        var day: Int?
        var weekday: Int?
        var month: Int?
    }

    static func triggers(in plist: [String: Any]) -> [Trigger] {
        var triggers: [Trigger] = []
        if plist["RunAtLoad"] as? Bool == true { triggers.append(.atLoad) }
        if let keepAlive = plist["KeepAlive"], keepAlive as? Bool != false, !(keepAlive as? [String: Any] ?? [:]).isEmpty || keepAlive as? Bool == true {
            triggers.append(.keepAlive)
        }
        if let seconds = plist["StartInterval"] as? Int, seconds > 0 { triggers.append(.interval(seconds: seconds)) }
        let calendars = (plist["StartCalendarInterval"] as? [[String: Any]])
            ?? (plist["StartCalendarInterval"] as? [String: Any]).map { [$0] } ?? []
        if !calendars.isEmpty {
            triggers.append(.calendar(calendars.map { entry in
                CalendarEntry(
                    minute: entry["Minute"] as? Int, hour: entry["Hour"] as? Int, day: entry["Day"] as? Int,
                    weekday: entry["Weekday"] as? Int, month: entry["Month"] as? Int)
            }))
        }
        let paths = (plist["WatchPaths"] as? [String] ?? []) + (plist["QueueDirectories"] as? [String] ?? [])
        if !paths.isEmpty { triggers.append(.watchPaths(paths)) }
        if plist["MachServices"] != nil || plist["Sockets"] != nil || plist["LaunchEvents"] != nil {
            triggers.append(.onDemand)
        }
        if triggers.isEmpty { triggers.append(.onDemand) }
        return triggers
    }

    /// Plain words for the row: "at login", "every hour", "daily at 10:30".
    func description(scope: LaunchdItem.Scope) -> String {
        switch self {
        case .atLoad: scope == .daemon ? "at boot" : "at login"
        case .keepAlive: "kept running"
        case .interval(let seconds): "every " + Self.duration(seconds)
        case .calendar(let entries): entries.map(Self.describe).joined(separator: "; ")
        case .watchPaths: parts(scope: scope).map(\.text).joined()
        case .onDemand: "on demand"
        }
    }

    /// The same words in parts, with each watched path held whole.
    func parts(scope: LaunchdItem.Scope) -> [Fact.Part] {
        guard case .watchPaths(let paths) = self else { return [.text(description(scope: scope))] }
        return [.text("when ")] + paths.map { [Fact.Part.path($0)] }.joined(separator: [.text(", ")]) + [.text(paths.count == 1 ? " changes" : " change")]
    }

    static func duration(_ seconds: Int) -> String {
        switch seconds {
        case ..<60: "\(seconds) s"
        case 60: "minute"
        case ..<3600 where seconds % 60 == 0: "\(seconds / 60) min"
        case ..<3600: "\(seconds) s"
        case 3600: "hour"
        case ..<86_400 where seconds % 3600 == 0: "\(seconds / 3600) h"
        case ..<86_400: "\(seconds / 60) min"
        case 86_400: "day"
        default: seconds % 86_400 == 0 ? "\(seconds / 86_400) days" : "\(seconds / 3600) h"
        }
    }

    private static let weekdays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    static func describe(_ entry: CalendarEntry) -> String {
        let time: String
        if let hour = entry.hour {
            time = String(format: "at %02d:%02d", hour, entry.minute ?? 0)
        } else if let minute = entry.minute {
            time = String(format: "every hour at :%02d", minute)
        } else {
            time = "every minute"
        }
        if let month = entry.month, let day = entry.day {
            return "yearly on \(Calendar.current.monthSymbols[max(0, min(month - 1, 11))]) \(day) \(time)"
        }
        if let day = entry.day {
            return "monthly on day \(day) \(time)"
        }
        if let weekday = entry.weekday {
            return "every \(weekdays[max(0, min(weekday, 7))]) \(time)"
        }
        return entry.hour != nil ? "daily \(time)" : time
    }
}
