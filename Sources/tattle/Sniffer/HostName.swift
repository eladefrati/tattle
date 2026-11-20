import Foundation

/// A host name read off the wire, checked before it names a flow. The sender chooses every
/// byte of an SNI, a Host header or a DNS label, and the name goes on to row titles, history,
/// rule keys and the LLM prompt, so anything but a plain host name is refused.
struct HostName: Hashable, Sendable {
    /// Lowercase ASCII labels joined by dots, with no trailing dot.
    let text: String

    static let maxLength = 253
    static let maxLabelLength = 63

    private static let dot = UInt8(ascii: "."), hyphen = UInt8(ascii: "-"), colon = UInt8(ascii: ":")

    /// Labels of letters, digits, hyphens and underscores, 1 to 63 bytes each and 253 in all,
    /// no label starting or ending with a hyphen. Uppercase is lowered, one trailing dot (the
    /// root) is dropped. `allowingPort` drops a trailing `:port`, which only a Host header has.
    ///
    /// A name whose last label is a number, in decimal or in hexadecimal after `0x`, is
    /// refused: no top-level domain is one, and it is what makes a host read as an IPv4
    /// address (the URL standard's "ends in a number"), so `17.253.144.10` in an SNI or a
    /// Host header would title a row with an address the connection may not go to.
    init?(_ bytes: some Collection<UInt8>, allowingPort: Bool = false) {
        var name = Array(bytes)
        if allowingPort, let colon = name.lastIndex(of: Self.colon) {
            let port = name[(colon + 1)...]
            guard (1...5).contains(port.count), port.allSatisfy({ (0x30...0x39).contains($0) }) else { return nil }
            name.removeSubrange(colon...)
        }
        if name.last == Self.dot { name.removeLast() }
        guard name.count <= Self.maxLength else { return nil }
        for label in name.split(separator: Self.dot, omittingEmptySubsequences: false) {
            guard (1...Self.maxLabelLength).contains(label.count),
                  label.first != Self.hyphen, label.last != Self.hyphen else { return nil }
        }
        var lowered: [UInt8] = []
        lowered.reserveCapacity(name.count)
        for byte in name {
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
                 Self.hyphen, UInt8(ascii: "_"), Self.dot:
                lowered.append(byte)
            case UInt8(ascii: "A")...UInt8(ascii: "Z"):
                lowered.append(byte + 0x20)
            default:
                return nil
            }
        }
        let lastLabel = lowered[(lowered.lastIndex(of: Self.dot).map { $0 + 1 } ?? 0)...]
        guard !Self.isNumber(lastLabel) else { return nil }
        text = String(decoding: lowered, as: UTF8.self)
    }

    /// Digits only, or `0x` and then hexadecimal digits only, none included; lowercase.
    private static func isNumber(_ label: ArraySlice<UInt8>) -> Bool {
        let digits = UInt8(ascii: "0")...UInt8(ascii: "9")
        if label.starts(with: [UInt8(ascii: "0"), UInt8(ascii: "x")]) {
            return label.dropFirst(2).allSatisfy { digits.contains($0) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0) }
        }
        return !label.isEmpty && label.allSatisfy { digits.contains($0) }
    }
}
