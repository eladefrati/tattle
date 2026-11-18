import CSocketTable
import Darwin
import Foundation

/// The socket table read one process at a time through libproc, the way lsof reads it.
/// What is left when the kernel withholds the pcblist_n records (`SocketTable.isWithheld`):
/// libproc answers an unprivileged caller only for the user's own processes, so sockets of
/// root and of other users are not in it.
enum ProcessSockets {
    /// A socket as one process holds it.
    struct Held {
        /// The kernel's handle for the socket: the same in every process that holds it.
        var socket: UInt64
        /// When the holding process started, in microseconds.
        var started: UInt64
        var entry: SocketEntry
    }

    static func read() -> [SocketEntry] {
        merge(pids().flatMap(held(pid:)))
    }

    /// One entry per socket, in the order first met. A process may hold a socket on several
    /// descriptors, and a parent and the child it forked both hold it; the entry names the
    /// process that started first, which stays the same from one reading to the next.
    static func merge(_ held: [Held]) -> [SocketEntry] {
        var bySocket: [UInt64: Held] = [:]
        var order: [UInt64] = []
        for item in held {
            guard let existing = bySocket[item.socket] else {
                bySocket[item.socket] = item
                order.append(item.socket)
                continue
            }
            if (item.started, item.entry.pid) < (existing.started, existing.entry.pid) { bySocket[item.socket] = item }
        }
        return order.compactMap { bySocket[$0]?.entry }
    }

    private static func pids() -> [Int32] {
        // The list can grow between the count and the read; ask with headroom.
        var pids = [Int32](repeating: 0, count: Int(max(proc_listallpids(nil, 0), 0)) + 64)
        let count = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<Int32>.stride))
        return pids.prefix(Int(max(count, 0))).filter { $0 > 0 }
    }

    /// The internet sockets a process holds; none for a process libproc will not describe.
    private static func held(pid: Int32) -> [Held] {
        let stride = MemoryLayout<proc_fdinfo>.stride
        let needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard needed > 0 else { return [] }
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(needed) / stride + 16)
        let used = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &descriptors, Int32(descriptors.count * stride))
        guard used > 0 else { return [] }

        var process: (uid: UInt32, started: UInt64)?
        var held: [Held] = []
        for descriptor in descriptors.prefix(Int(used) / stride) where descriptor.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var info = socket_fdinfo()
            let size = Int32(MemoryLayout<socket_fdinfo>.size)
            guard proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDSOCKETINFO, &info, size) == size else { continue }
            let socket = info.psi
            guard socket.soi_family == AF_INET || socket.soi_family == AF_INET6 else { continue }

            let proto: SocketEntry.Proto, endpoints: in_sockinfo, tcpState: Int32?
            if Int(socket.soi_kind) == Int(SOCKINFO_TCP) {
                (proto, endpoints, tcpState) = (.tcp, socket.soi_proto.pri_tcp.tcpsi_ini, socket.soi_proto.pri_tcp.tcpsi_state)
            } else if Int(socket.soi_kind) == Int(SOCKINFO_IN), socket.soi_protocol == IPPROTO_UDP {
                (proto, endpoints, tcpState) = (.udp, socket.soi_proto.pri_in, nil)
            } else {
                continue
            }
            if process == nil { process = Self.process(pid) }
            guard let process else { return [] }

            // insi_vflag carries the kernel's inp_vflag, as the pcblist_n record does.
            let isIPv6 = Int32(endpoints.insi_vflag) & INP_IPV6 != 0
            let local: String, remote: String
            if isIPv6 {
                local = SocketTable.ipv6(endpoints.insi_laddr.ina_6)
                remote = SocketTable.ipv6(endpoints.insi_faddr.ina_6)
            } else {
                local = SocketTable.ipv4(endpoints.insi_laddr.ina_46.i46a_addr4)
                remote = SocketTable.ipv4(endpoints.insi_faddr.ina_46.i46a_addr4)
            }
            held.append(Held(socket: socket.soi_so, started: process.started, entry: SocketEntry(
                proto: proto, isIPv6: isIPv6,
                localAddress: local, localPort: port(endpoints.insi_lport),
                remoteAddress: remote, remotePort: port(endpoints.insi_fport),
                tcpState: tcpState, pid: pid, effectivePid: pid, uid: process.uid,
                isDualStack: isIPv6 && Int32(endpoints.insi_vflag) & INP_IPV4 != 0)))
        }
        return held
    }

    /// The port is the kernel's 16 bits in network order, widened to an int.
    private static func port(_ value: Int32) -> UInt16 {
        UInt16(bigEndian: UInt16(truncatingIfNeeded: value))
    }

    private static func process(_ pid: Int32) -> (uid: UInt32, started: UInt64)? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return (info.pbi_uid, info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }
}
