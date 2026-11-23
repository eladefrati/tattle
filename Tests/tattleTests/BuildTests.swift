import XCTest
@testable import tattle

/// Checks on how `make app` builds the bundle and `make release` checks it, read from make's
/// dry run, so make builds nothing.
final class BuildTests: XCTestCase {
    private var repository: URL { URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }

    private func recipe(_ variables: [String], target: String = "app", environment: [String: String] = [:], status: Int32 = 0) throws -> [String] {
        let process = Process()
        process.executableURL = URL(filePath: "/usr/bin/make")
        process.arguments = ["-n", "-C", repository.path, target] + variables
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { $1 }
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        if waitForExit(process) { XCTAssertEqual(process.terminationStatus, status, "make \(target) \(variables)") }
        return text.split(separator: "\n").map(String.init)
    }

    /// Without the hardened runtime, launching Tattle with DYLD_INSERT_LIBRARIES runs foreign
    /// code inside a process the broker accepts (ADR-0003), and the broker refuses such callers.
    /// The dry run prints the whole signing conditional, so this covers ad hoc and an Apple
    /// identity at once.
    func testEverySigningUsesTheHardenedRuntime() throws {
        let signing = try recipe(["SIGN_IDENTITY="]).filter { $0.contains("codesign --force") }
        XCTAssertEqual(signing.count, 4, "two signings in each branch")
        for line in signing {
            XCTAssertTrue(line.contains("--options runtime"), line)
        }
    }

    /// make app records the version and the commit under the keys Settings reads. The version
    /// is given here, as make release gives it: a clone without tags, such as CI's, has none.
    func testEveryBuildRecordsItsVersionAndCommitWhereTheAppReadsThem() throws {
        let lines = try recipe(["SIGN_IDENTITY=-", "VERSION=2026.11.17.1"])
        // The dry run prints a command's continued lines one by one.
        let start = try XCTUnwrap(lines.firstIndex { $0.contains("version='2026.11.17.1'") })
        let end = lines[start...].firstIndex { !$0.hasSuffix("\\") } ?? lines.endIndex - 1
        let command = lines[start...end].joined(separator: "\n")
        XCTAssertTrue(command.contains("plutil -replace \(AppVersion.versionKey) "), command)
        XCTAssertTrue(command.contains("plutil -replace \(AppVersion.sourceCommitKey) "), command)
    }

    /// One exported in the environment must not stamp a build.
    func testTheVersionIsTakenFromTheCommandLineOnly() throws {
        let lines = try recipe(["SIGN_IDENTITY=-"], environment: ["VERSION": "2026.11.17.9"])
        XCTAssertFalse(lines.contains { $0.contains("2026.11.17.9") })
    }

    func testAVersionOfAnotherFormIsRefused() throws {
        for version in ["2026.11.17", "2026.11.17.0", "v2026.11.17.1", "1.0"] {
            XCTAssertEqual(try recipe(["SIGN_IDENTITY=-", "VERSION=\(version)"], status: 2), [], version)
        }
    }

    /// Nothing committed says which release the code is: the source's Info.plist holds a
    /// placeholder the app reads as no version.
    func testTheSourceCarriesNoVersion() throws {
        let data = try Data(contentsOf: repository.appending(path: "Resources/Info.plist"))
        let info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        XCTAssertEqual(AppVersion.text(info: info), "Unknown")
        XCTAssertEqual(AppVersion.text(info: info.merging([AppVersion.sourceCommitKey: "abc1234"]) { $1 }), "abc1234")
    }

    /// What the ad-hoc signing line actually does, not just what it says: a copy of the
    /// broker probe signed with its options, launched with DYLD_INSERT_LIBRARIES, must not
    /// run the library. A copy signed without them must, or the library would prove nothing.
    func testAdHocSigningKeepsInjectedLibrariesOut() throws {
        let line = try XCTUnwrap(try recipe(["SIGN_IDENTITY="]).first { $0.contains("codesign --force") && $0.contains("--sign -") })
        let options = Array(line.split(separator: " ").map(String.init).drop { $0 != "codesign" }.dropFirst().prefix { !$0.contains("Tattle.app") })

        // With System Integrity Protection off, macOS loads the library into a hardened
        // program too (seen on a hosted CI runner), so the Mac cannot show what the options do.
        let csrutil = Process(), status = Pipe()
        csrutil.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        csrutil.arguments = ["status"]
        csrutil.standardOutput = status
        try csrutil.run()
        csrutil.waitUntilExit()
        let protection = String(decoding: status.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard protection.contains("enabled") else { throw XCTSkip("System Integrity Protection is not enabled: \(protection)") }

        let directory = FileManager.default.temporaryDirectory.appending(path: "inject-\(getpid())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appending(path: "inject.c")
        try #"""
            #include <stdio.h>
            #include <stdlib.h>
            __attribute__((constructor)) static void injected(void) {
                FILE *out = fopen(getenv("INJECT_MARKER"), "w");
                if (out) fclose(out);
            }
            """#.write(to: source, atomically: true, encoding: .utf8)
        let library = directory.appending(path: "inject.dylib")
        try run("/usr/bin/clang", ["-dynamiclib", source.path, "-o", library.path])

        let probe = Bundle(for: Self.self).bundleURL.deletingLastPathComponent().appending(path: "tattle-broker-probe")
        for (name, signing) in [("ad-hoc", options), ("plain", ["--force", "--sign", "-"])] {
            let copy = directory.appending(path: "probe-\(name)")
            try FileManager.default.copyItem(at: probe, to: copy)
            try run("/usr/bin/codesign", signing + [copy.path])
            let marker = directory.appending(path: "\(name).marker")
            // No arguments: the probe prints its usage and exits, after any library has loaded.
            try run(copy.path, [], environment: ["DYLD_INSERT_LIBRARIES": library.path, "INJECT_MARKER": marker.path], status: 2)
            XCTAssertEqual(FileManager.default.fileExists(atPath: marker.path), name == "plain", "\(name), signed with \(signing)")
        }
    }

    /// What the release's check for an account's path does, run as make prints it, over a
    /// folder standing in for the built app. A program stores a short string inside its
    /// instructions, in pieces; read as text, the instruction after the first piece of
    /// "/Users/Shared" would end the name of an account no file names.
    func testTheReleaseRefusesAnotherAccountsPathAndNotAProgramsInstructions() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "paths-\(getpid())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let dist = directory.appending(path: "dist")
        let lines = try recipe(["VERSION=2026.11.17.1", "DISTDIR=\(dist.path)"], target: "release")
        // The check is the command after the one that looks for the built app.
        let start = try XCTUnwrap(lines.firstIndex(of: "test -d \(dist.path)/Tattle.app")) + 1
        let end = lines[start...].firstIndex { !$0.hasSuffix("\\") } ?? lines.endIndex - 1
        let check = lines[start...end].joined(separator: "\n")

        // The instructions an Intel build makes of the string: a move of its first eight bytes,
        // then a conditional move, whose first byte is the letter H.
        let instructions = "0x48, 0xbf, 0x2f, 0x55, 0x73, 0x65, 0x72, 0x73, 0x2f, 0x53, 0x48, 0x0f, 0x45, 0xfa"
        func program(_ name: String, strings: [String]) throws -> URL {
            let source = directory.appending(path: "\(name).c")
            let held = strings.map { "\"\($0)\"" }.joined(separator: ", ")
            try """
                __asm__(".text\\n.byte \(instructions)\\n.p2align 4");
                const char *held[] = { \(held) };
                int main(void) { return 0; }
                """.write(to: source, atomically: true, encoding: .utf8)
            let program = directory.appending(path: name)
            try run("/usr/bin/clang", ["-arch", "arm64", "-arch", "x86_64", source.path, "-o", program.path])
            return program
        }
        let text = directory.appending(path: "text")
        try Data("<string>/Users/other</string>\n".utf8).write(to: text)

        let cases: [(file: URL, refused: String?)] = [
            (try program("instructions", strings: ["/Users/runner/work/x", "/Users/Shared"]), nil),
            (try program("under", strings: ["/Users/other/Library/x"]), "/Users/other"),
            (try program("whole", strings: ["/Users/Other User"]), "/Users/Other"),
            (try program("near", strings: ["/Users/runner2/x"]), "/Users/runner2"),
            (text, "/Users/other"),
        ]
        for (file, refused) in cases {
            let contents = dist.appending(path: "Tattle.app/Contents/MacOS")
            try? FileManager.default.removeItem(at: dist)
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: file, to: contents.appending(path: "tattle"))

            let process = Process(), errors = Pipe()
            process.executableURL = URL(filePath: "/bin/sh")
            process.arguments = ["-c", check]
            process.currentDirectoryURL = repository
            process.standardOutput = FileHandle.nullDevice
            process.standardError = errors
            try process.run()
            let message = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            guard waitForExit(process) else { continue }
            XCTAssertEqual(process.terminationStatus, refused == nil ? 0 : 1, "\(file.lastPathComponent): \(message)")
            if let refused { XCTAssertTrue(message.hasSuffix(": \(refused)\n"), "\(file.lastPathComponent): \(message)") }
        }
    }

    private func run(_ path: String, _ arguments: [String], environment: [String: String]? = nil, status: Int32 = 0) throws {
        let process = Process()
        process.executableURL = URL(filePath: path)
        process.arguments = arguments
        if let environment { process.environment = environment }
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        if waitForExit(process) { XCTAssertEqual(process.terminationStatus, status, "\(path) \(arguments)") }
    }
}
