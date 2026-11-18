import CSocketTable
import Foundation

struct SocketEntry: Equatable, Sendable {
    enum Proto: String, Sendable { case tcp, udp }

    var proto: Proto
    var isIPv6: Bool
    var localAddress: String
    var localPort: UInt16
    var remoteAddress: String
    var remotePort: UInt16
    /// TCP state (netinet/tcp_fsm.h); nil for UDP.
    var tcpState: Int32?
    /// The process that last used the socket; what netstat and lsof report as the owner.
    var pid: Int32
    /// The process on whose behalf it was opened, when a system daemon proxies.
    var effectivePid: Int32
    var uid: UInt32
    /// An IPv6 socket that takes IPv4 peers too: netstat's tcp46.
    var isDualStack = false

    static let tcpListen: Int32 = 1
    static let tcpEstablished: Int32 = 4

    var isListening: Bool {
        switch proto {
        case .tcp: tcpState == Self.tcpListen
        case .udp: localPort != 0 && remotePort == 0
        }
    }

    /// Unspecified address: reachable on every interface, including from the network.
    var isBoundToAllInterfaces: Bool { localAddress == "0.0.0.0" || localAddress == "::" }
    var isLoopback: Bool { Self.isLoopback(localAddress) }

    var acceptsIPv4: Bool { !isIPv6 || isDualStack }
    var acceptsIPv6: Bool { isIPv6 }
}

/// Reads both tables through the pcblist_n sysctls. No privileges needed, and the owning
/// pid comes with each socket, which the per-process libproc route cannot give for other
/// users' processes. macOS 27 withholds the records from an ordinary process; the table is
/// then what `ProcessSockets` gives, the user's own processes only.
enum SocketTable {
    enum ReadError: Error, Equatable, CustomStringConvertible {
        case sysctl(name: String, errno: Int32)

        /// What the panel shows.
        var description: String {
            switch self {
            case .sysctl(let name, let errno): "The socket table (\(name)) could not be read: \(String(cString: strerror(errno)))."
            }
        }
    }

    static func read() throws -> [SocketEntry] {
        let tcp = try read(name: "net.inet.tcp.pcblist_n", proto: .tcp)
        let udp = try read(name: "net.inet.udp.pcblist_n", proto: .udp)
        if let tcp, let udp { return tcp + udp }
        _ = saidWithheld
        let held = ProcessSockets.read()
        return (tcp ?? held.filter { $0.proto == .tcp }) + (udp ?? held.filter { $0.proto == .udp })
    }

    /// Nil when the kernel withholds the table's records.
    private static func read(name: String, proto: SocketEntry.Proto) throws -> [SocketEntry]? {
        var buffer: UnsafeMutableRawPointer?
        var length = 0
        let status = tattle_read_pcblist(name, &buffer, &length)
        guard status == 0, let buffer else { throw ReadError.sysctl(name: name, errno: status) }
        defer { free(buffer) }
        let data = UnsafeRawBufferPointer(start: buffer, count: length)
        return isWithheld(data) ? nil : parse(data, proto: proto)
    }

    /// Logged once: the reading that follows has no sockets of root or of other users.
    private static let saidWithheld: Void = Log.app.notice(
        "the kernel withholds the socket table's records; reading the user's own processes' sockets instead")

    /// The kernel counts sockets and returns none of their records: only the leading and
    /// the trailing tattle_xinpgen. macOS 27 answers a process without Apple's
    /// network-statistics entitlement this way, with no error.
    static func isWithheld(_ data: UnsafeRawBufferPointer) -> Bool {
        guard data.count >= MemoryLayout<tattle_xinpgen>.size, let base = data.baseAddress else { return false }
        let header = base.loadUnaligned(as: tattle_xinpgen.self)
        return header.xig_count > 0 && data.count <= roundUp8(Int(header.xig_len)) + MemoryLayout<tattle_xinpgen>.size
    }

    /// The kernel may return records shorter than the current XNU headers (fields are
    /// appended over time), so a record only has to reach the last field read from it.
    private static let socketRecordMinimum = MemoryLayout<tattle_xsocket_n>.offset(of: \.so_e_pid)! + MemoryLayout<pid_t>.size
    private static let pcbRecordMinimum = MemoryLayout<tattle_xinpcb_n>.offset(of: \.inp_depend4)!
    private static let tcpRecordMinimum = MemoryLayout<tattle_xtcpcb_n_head>.offset(of: \.t_state)! + MemoryLayout<Int32>.size

    /// Walks the records. A socket's records are consecutive, INPCB first; the entry is
    /// emitted once the socket record and, for TCP, the TCP record have followed.
    static func parse(_ data: UnsafeRawBufferPointer, proto: SocketEntry.Proto) -> [SocketEntry] {
        guard data.count >= MemoryLayout<tattle_xinpgen>.size, let base = data.baseAddress else { return [] }
        let header = base.loadUnaligned(as: tattle_xinpgen.self)
        var entries: [SocketEntry] = []
        var offset = roundUp8(Int(header.xig_len))
        var socket: tattle_xsocket_n?
        var inpcb: tattle_xinpcb_n?
        var tcpState: Int32?

        while offset + MemoryLayout<tattle_xgen_n>.size <= data.count {
            let generic = (base + offset).loadUnaligned(as: tattle_xgen_n.self)
            let length = Int(generic.xgn_len)
            // The list ends with a trailing tattle_xinpgen, which is shorter than any record.
            if length <= MemoryLayout<tattle_xinpgen>.size || offset + length > data.count { break }
            // The kind is unsigned; one past Int32.max matches no case rather than trapping.
            switch Int32(bitPattern: generic.xgn_kind) {
            case XSO_INPCB where length >= pcbRecordMinimum:
                inpcb = load(tattle_xinpcb_n.self, from: base + offset, length: length)
                socket = nil
                tcpState = nil
            case XSO_SOCKET where length >= socketRecordMinimum:
                socket = load(tattle_xsocket_n.self, from: base + offset, length: length)
            case XSO_TCPCB where length >= tcpRecordMinimum:
                tcpState = load(tattle_xtcpcb_n_head.self, from: base + offset, length: length).t_state
            default:
                break
            }
            if let so = socket, let inp = inpcb, proto == .udp || tcpState != nil {
                entries.append(entry(socket: so, inpcb: inp, tcpState: tcpState, proto: proto))
                socket = nil
                inpcb = nil
                tcpState = nil
            }
            offset += roundUp8(length)
        }
        return entries
    }

    private static func roundUp8(_ value: Int) -> Int { (value + 7) & ~7 }

    /// Loads a record into a struct that may be longer than the record; the tail is zero.
    private static func load<T>(_ type: T.Type, from pointer: UnsafeRawPointer, length: Int) -> T {
        let value = UnsafeMutablePointer<T>.allocate(capacity: 1)
        defer { value.deallocate() }
        let raw = UnsafeMutableRawPointer(value)
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: MemoryLayout<T>.size)
        raw.copyMemory(from: pointer, byteCount: min(length, MemoryLayout<T>.size))
        return value.pointee
    }

    private static func entry(socket: tattle_xsocket_n, inpcb: tattle_xinpcb_n, tcpState: Int32?, proto: SocketEntry.Proto) -> SocketEntry {
        let isIPv6 = Int32(inpcb.inp_vflag) & INP_IPV6 != 0
        let isDualStack = isIPv6 && Int32(inpcb.inp_vflag) & INP_IPV4 != 0
        let local: String, remote: String
        if isIPv6 {
            local = ipv6(inpcb.inp_dependladdr.inp6_local)
            remote = ipv6(inpcb.inp_dependfaddr.inp6_foreign)
        } else {
            local = ipv4(inpcb.inp_dependladdr.inp46_local.ia46_addr4)
            remote = ipv4(inpcb.inp_dependfaddr.inp46_foreign.ia46_addr4)
        }
        return SocketEntry(
            proto: proto, isIPv6: isIPv6,
            localAddress: local, localPort: UInt16(bigEndian: inpcb.inp_lport),
            remoteAddress: remote, remotePort: UInt16(bigEndian: inpcb.inp_fport),
            tcpState: tcpState, pid: socket.so_last_pid, effectivePid: socket.so_e_pid, uid: socket.so_uid, isDualStack: isDualStack)
    }

    static func ipv4(_ address: in_addr) -> String {
        var address = address
        var text = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address, &text, socklen_t(text.count))
        return String(cBuffer: text)
    }

    static func ipv6(_ address: in6_addr) -> String {
        var address = address
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &address, &text, socklen_t(text.count))
        return String(cBuffer: text)
    }
}
