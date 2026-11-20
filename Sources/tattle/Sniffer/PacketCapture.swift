import CPacketCapture
import Foundation
import SystemConfiguration

enum CaptureError: Error, Equatable {
    /// `/dev/bpf*` could not be opened. The devices are root-only, so this is the state
    /// without the broker (ADR-0003).
    case open(errno: Int32)
    case prepare(errno: Int32)
    case filterRejected(errno: Int32)
    case read(errno: Int32)
    case noInterface
    /// The broker is installed but did not hand over a descriptor.
    case broker(CaptureBroker.RequestError)

    var text: String {
        switch self {
        case .open(let code): "cannot open the packet capture device: \(Self.describe(code))"
        case .prepare(let code): "cannot set up the packet capture device: \(Self.describe(code))"
        case .filterRejected(let code): "the kernel rejected the packet filter: \(Self.describe(code))"
        case .read(let code): "packet capture read failed: \(Self.describe(code))"
        case .noInterface: "no network interface carries the default route"
        case .broker(let error): error.text
        }
    }

    private static func describe(_ code: Int32) -> String { String(cString: strerror(code)) }
}

/// What the sniffer's loop uses of a capture: a PacketCapture, or a stand-in in tests.
protocol CaptureSource: AnyObject {
    var dataLinkType: UInt32 { get }
    func install(_ filter: CaptureFilter) throws
    /// One read; `handle` gets each packet's capture timestamp and bytes.
    func readPackets(_ handle: (Double, [UInt8]) -> Void) throws
    /// Whether the broker supplied the descriptor.
    var isFromBroker: Bool { get }
}

extension CaptureSource {
    var isFromBroker: Bool { false }
}

/// One BPF descriptor, bound to an interface and read in a loop. Takes the descriptor as
/// input so the broker can supply it; opening the device directly is for readable
/// devices only.
final class PacketCapture: CaptureSource {
    let fd: Int32
    let bufferLength: Int
    let dataLinkType: UInt32
    let isFromBroker: Bool
    private let buffer: UnsafeMutableRawPointer

    /// Link types this capture understands (net/bpf.h).
    static let linkEthernet: UInt32 = 1
    static let linkNull: UInt32 = 0
    static let linkRaw: UInt32 = 12

    /// Prepares a bound descriptor for reading and takes ownership of it: it is closed
    /// when the capture goes away. `timeout` bounds each read so the loop can stop.
    init(descriptor: Int32, timeout: Duration = .seconds(1), isFromBroker: Bool = false) throws {
        self.isFromBroker = isFromBroker
        var length: UInt32 = 0
        var dlt: UInt32 = 0
        let milliseconds = Int32(clamping: timeout.components.seconds * 1000 + timeout.components.attoseconds / 1_000_000_000_000_000)
        guard tattle_capture_prepare(descriptor, milliseconds, &length, &dlt) == 0 else {
            let code = errno
            close(descriptor)
            throw CaptureError.prepare(errno: code)
        }
        fd = descriptor
        bufferLength = Int(length)
        dataLinkType = dlt
        buffer = UnsafeMutableRawPointer.allocate(byteCount: Int(length), alignment: 16)
    }

    /// Opens a device on `interface` directly. Needs the devices readable.
    static func open(interface: String, timeout: Duration = .seconds(1)) throws -> PacketCapture {
        let fd = tattle_capture_open(interface)
        guard fd >= 0 else { throw CaptureError.open(errno: errno) }
        return try PacketCapture(descriptor: fd, timeout: timeout)
    }

    /// A capture on `interface` from the broker when it is installed, else from the
    /// device itself, which works only while the devices are readable.
    static func obtain(interface: String, timeout: Duration = .seconds(1)) throws -> PacketCapture {
        let broker = { try PacketCapture(descriptor: try CaptureBroker.request(interface: interface), timeout: timeout, isFromBroker: true) }
        return try obtain(broker: CaptureBroker.isReachable ? broker : nil, device: { try open(interface: interface, timeout: timeout) })
    }

    /// The broker's capture when there is a broker; the device's when there is none, or when
    /// the broker gave none and the devices are readable all the same. When they are not,
    /// what the broker said is why there are no packets.
    static func obtain<Capture>(broker: (() throws -> Capture)?, device: () throws -> Capture) throws -> Capture {
        guard let broker else { return try device() }
        do {
            return try broker()
        } catch let error as CaptureBroker.RequestError {
            if let capture = try? device() { return capture }
            throw CaptureError.broker(error)
        }
    }

    deinit {
        close(fd)
        buffer.deallocate()
    }

    func install(_ filter: CaptureFilter) throws {
        let insns = filter.instructions.map { tattle_filter_insn(code: $0.code, jt: $0.jt, jf: $0.jf, k: $0.k) }
        let status = insns.withUnsafeBufferPointer { tattle_capture_set_filter(fd, $0.baseAddress, UInt32($0.count)) }
        guard status == 0 else { throw CaptureError.filterRejected(errno: errno) }
    }

    /// One read(2); `handle` gets each packet's capture timestamp and bytes. Returns
    /// without calling it on timeout.
    func readPackets(_ handle: (Double, [UInt8]) -> Void) throws {
        let n = read(fd, buffer, bufferLength)
        if n < 0 {
            if errno == EINTR { return }
            throw CaptureError.read(errno: errno)
        }
        var offset = 0
        var timestamp = 0.0
        var dataOffset = 0
        var caplen: UInt32 = 0
        var next = 0
        while tattle_capture_next(buffer, n, offset, &timestamp, &dataOffset, &caplen, &next) == 1 {
            let bytes = Array(UnsafeRawBufferPointer(start: buffer + dataOffset, count: Int(caplen)))
            handle(timestamp, bytes)
            offset = next
        }
    }

    /// The hardware address of an interface; nil for one without (a tunnel).
    static func hardwareAddress(of interface: String) -> [UInt8]? {
        var mac = [UInt8](repeating: 0, count: 6)
        guard tattle_interface_mac(interface, &mac) == 0 else { return nil }
        return mac
    }

    /// The hardware addresses the interface's gateways answer at, IPv4's then IPv6's: of each
    /// family whose default route is on the interface, the router's entry in the system's
    /// neighbour table. A gateway with no resolved entry is left out.
    static func gatewayHardwareAddresses(of interface: String) -> [[UInt8]] {
        gatewayHardwareAddresses(of: interface, store: { SCDynamicStoreCopyValue(nil, $0 as CFString) as? [String: Any] }) { address, interface in
            var mac = [UInt8](repeating: 0, count: 6)
            guard tattle_neighbor_mac(interface, address.bytes, address.bytes.count, &mac) == 0 else { return nil }
            return mac
        }
    }

    /// The same, from a store lookup by key and a neighbour table lookup by address and interface.
    static func gatewayHardwareAddresses(of interface: String, store: (String) -> [String: Any]?,
                                         neighbour: (IPAddress, String) -> [UInt8]?) -> [[UInt8]] {
        ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"].compactMap { key in
            guard let global = store(key), global["PrimaryInterface"] as? String == interface,
                  let router = (global["Router"] as? String).flatMap(IPAddress.init(text:)) else { return nil }
            return neighbour(router, interface)
        }
    }

    /// The interface carrying the default route, from the system configuration store: what
    /// `route get default` reports, or `route get -inet6 default` on an IPv6-only network.
    static func primaryInterface() -> String? {
        primaryInterface { SCDynamicStoreCopyValue(nil, $0 as CFString) as? [String: Any] }
    }

    /// The same, from a store lookup by key.
    static func primaryInterface(store: (String) -> [String: Any]?) -> String? {
        for key in ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] {
            if let name = store(key)?["PrimaryInterface"] as? String, !name.isEmpty { return name }
        }
        return nil
    }
}
