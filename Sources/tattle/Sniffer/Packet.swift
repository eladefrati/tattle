import Foundation

struct IPAddress: Hashable {
    let bytes: [UInt8]  // 4 or 16

    var isV4: Bool { bytes.count == 4 }

    /// From the text form; a zone suffix (`fe80::1%en0`) is dropped.
    init?(text: String) {
        let address = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
        } else if inet_pton(AF_INET6, address, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
        } else {
            return nil
        }
    }

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var text: String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBufferPointer { p in
            _ = inet_ntop(isV4 ? AF_INET : AF_INET6, p.baseAddress, &buf, socklen_t(buf.count))
        }
        return String(cBuffer: buf)
    }

    /// A loopback address, which no link carries: 127/8, ::1.
    var isLoopback: Bool {
        isV4 ? bytes[0] == 127 : bytes[0..<15].allSatisfy { $0 == 0 } && bytes[15] == 1
    }

    // Destinations that never need a public name: private, loopback, link-local, multicast.
    var isLocalScope: Bool {
        if isV4 {
            let a = bytes[0], b = bytes[1]
            return a == 10 || a == 127 || a == 0
                || (a == 172 && (16...31).contains(b))
                || (a == 192 && b == 168)
                || (a == 169 && b == 254)
                || a >= 224
        }
        let a = bytes[0]
        if a == 0xff || (a & 0xfe) == 0xfc || (a == 0xfe && (bytes[1] & 0xc0) == 0x80) { return true }
        if bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] <= 1 { return true }
        return false
    }
}

struct Packet {
    enum Proto { case tcp, udp }

    let src: IPAddress
    let dst: IPAddress
    let srcPort: UInt16
    let dstPort: UInt16
    let proto: Proto
    let tcpFlags: UInt8
    let tcpSeq: UInt32
    let payload: ArraySlice<UInt8>
    /// Payload bytes the packet carried past the capture's snap length.
    var uncaptured = 0
    /// The hardware address the frame came from, on a link whose frames carry one.
    var linkSource: ArraySlice<UInt8>?
    /// The hardware address the frame is addressed to, on the same links.
    var linkDestination: ArraySlice<UInt8>?

    static func parse(_ bytes: [UInt8], dlt: UInt32) -> Packet? {
        var r = ByteReader(bytes)
        do {
            var linkSource: ArraySlice<UInt8>?
            var linkDestination: ArraySlice<UInt8>?
            switch dlt {
            case 1:  // DLT_EN10MB
                linkDestination = try r.take(6)
                linkSource = try r.take(6)
                let type = try r.u16()
                guard type == 0x0800 || type == 0x86DD else { return nil }
            case 0:  // DLT_NULL (lo0, utun): 4-byte address family in host order
                try r.skip(4)
            case 12:  // DLT_RAW
                break
            default:
                return nil
            }
            var packet = try parseIP(&r)
            packet?.linkSource = linkSource
            packet?.linkDestination = linkDestination
            return packet
        } catch {
            return nil
        }
    }

    private static func parseIP(_ r: inout ByteReader) throws -> Packet? {
        let start = r.pos
        let first = try r.u8()
        let proto: UInt8
        let src: IPAddress
        let dst: IPAddress
        let declaredEnd: Int  // where the packet ends by its header, captured or not
        switch first >> 4 {
        case 4:
            let headerLength = Int(first & 0x0f) * 4
            // A length short of the fixed header would move the cursor back into it.
            guard headerLength >= 20 else { return nil }
            try r.skip(1)
            let total = Int(try r.u16())
            try r.skip(2)
            let fragment = try r.u16()
            guard fragment & 0x1fff == 0 else { return nil }  // only the first fragment carries headers
            try r.skip(1)
            proto = try r.u8()
            try r.skip(2)
            src = IPAddress(bytes: Array(try r.take(4)))
            dst = IPAddress(bytes: Array(try r.take(4)))
            r.pos = start + headerLength
            declaredEnd = start + total
            r.end = min(r.end, declaredEnd)
        case 6:
            try r.skip(3)
            let payloadLength = Int(try r.u16())
            proto = try r.u8()
            try r.skip(1)
            src = IPAddress(bytes: Array(try r.take(16)))
            dst = IPAddress(bytes: Array(try r.take(16)))
            declaredEnd = start + 40 + payloadLength
            r.end = min(r.end, declaredEnd)
        default:
            return nil
        }
        guard r.pos <= r.end else { return nil }

        switch proto {
        case 6:
            let transportStart = r.pos
            let sport = try r.u16()
            let dport = try r.u16()
            let seq = try r.u32()
            try r.skip(4)
            let dataOffset = Int(try r.u8() >> 4) * 4
            let flags = try r.u8()
            guard dataOffset >= 20, transportStart + dataOffset <= r.end else { return nil }
            r.pos = transportStart + dataOffset
            return Packet(src: src, dst: dst, srcPort: sport, dstPort: dport,
                          proto: .tcp, tcpFlags: flags, tcpSeq: seq, payload: r.rest, uncaptured: max(0, declaredEnd - r.end))
        case 17:
            let sport = try r.u16()
            let dport = try r.u16()
            try r.skip(4)
            return Packet(src: src, dst: dst, srcPort: sport, dstPort: dport,
                          proto: .udp, tcpFlags: 0, tcpSeq: 0, payload: r.rest)
        default:
            return nil
        }
    }
}

// One interface's addresses: the ones a packet captured on it can carry as this machine's.
func localAddresses(of interface: String) -> Set<IPAddress> {
    var result = Set<IPAddress>()
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0 else { return result }
    defer { freeifaddrs(list) }
    var cursor = list
    while let entry = cursor {
        if let sa = entry.pointee.ifa_addr, String(cString: entry.pointee.ifa_name) == interface {
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                var addr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
                result.insert(IPAddress(bytes: withUnsafeBytes(of: &addr) { Array($0) }))
            case AF_INET6:
                var addr = UnsafeRawPointer(sa).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                result.insert(IPAddress(bytes: withUnsafeBytes(of: &addr) { Array($0) }))
            default:
                break
            }
        }
        cursor = entry.pointee.ifa_next
    }
    return result
}

func systemResolvers() -> Set<IPAddress> {
    SystemDNS.current.servers
}
