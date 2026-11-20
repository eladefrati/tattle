import Foundation

enum TLS {
    enum HelloResult {
        case needMore
        case notClientHello
        case hello(sni: String?)
    }

    // Parses a handshake-message stream (no record layer) that should start with a
    // ClientHello and returns its server_name extension, if any. The stream may stop short
    // of the hello's end: a hello can outgrow one segment or one Initial, and the capture
    // cuts a segment at its snap length. The name is returned as soon as its extension is
    // in hand, and "no name" only once nothing still to come could hold one, so a prefix
    // never says anything the whole hello would not.
    static func clientHello(_ data: [UInt8]) -> HelloResult {
        guard data.count >= 4 else { return .needMore }
        guard data[0] == 1 else { return .notClientHello }
        let length = Int(data[1]) << 16 | Int(data[2]) << 8 | Int(data[3])
        // Where the hello ends by its own header; the reader ends there or where the bytes do.
        let helloEnd = 4 + length
        // What running out of bytes means: a malformed hello when it is all here, else wait.
        let short: HelloResult = data.count >= helloEnd ? .hello(sni: nil) : .needMore
        var r = ByteReader(data, from: 4, to: helloEnd)
        do {
            try r.skip(2 + 32)  // legacy version, random
            try r.skip(Int(try r.u8()))  // session id
            try r.skip(Int(try r.u16()))  // cipher suites
            try r.skip(Int(try r.u8()))  // compression methods
            guard r.remaining >= 2 else { return short }
            let extensionsLength = Int(try r.u16())
            let extensionsEnd = min(helloEnd, r.pos + extensionsLength)
            r.end = min(r.end, extensionsEnd)
            while r.remaining >= 4 {
                let type = try r.u16()
                let length = Int(try r.u16())
                if type == 0 {
                    let end = min(extensionsEnd, r.pos + length)
                    guard end <= data.count else { return .needMore }
                    // The whole extension is here: what it says, the rest cannot change.
                    var e = ByteReader(data, from: r.pos, to: end)
                    do {
                        try e.skip(2)  // list length
                        let nameType = try e.u8()
                        let name = try e.take(Int(try e.u16()))
                        guard nameType == 0 else { return .hello(sni: nil) }
                        return .hello(sni: HostName(name)?.text)
                    } catch {
                        return .hello(sni: nil)
                    }
                }
                try r.skip(length)
            }
            // Fewer than four bytes left of the extensions block, or of what has come of it.
            return r.end == extensionsEnd ? .hello(sni: nil) : .needMore
        } catch {
            return short
        }
    }

    // Strips the TLS record layer from a TCP byte stream and hands the concatenated
    // handshake fragments to clientHello. A partial trailing record is included; clientHello
    // decides whether more bytes are needed.
    static func clientHelloFromRecords(_ stream: [UInt8]) -> HelloResult {
        guard !stream.isEmpty else { return .needMore }
        guard stream[0] == 0x16 else { return .notClientHello }
        var r = ByteReader(stream)
        var handshake: [UInt8] = []
        do {
            while r.remaining >= 5 {
                let type = try r.u8()
                guard type == 0x16 else { break }
                try r.skip(2)
                let length = Int(try r.u16())
                let fragment = try r.take(min(length, r.remaining))
                handshake.append(contentsOf: fragment)
            }
        } catch {
            return .needMore
        }
        return clientHello(handshake)
    }
}

enum HTTP {
    /// A plaintext HTTP/1.x request, and the name its Host header gives the destination:
    /// nil when there is no Host header or its value is not a host name.
    struct Request {
        let host: String?
    }

    static func request(_ payload: ArraySlice<UInt8>) -> Request? {
        let head = Array(payload.prefix(2048))
        let text = String(decoding: head, as: UTF8.self)
        let methods = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "]
        guard methods.contains(where: { text.hasPrefix($0) }) else { return nil }
        for line in text.split(separator: "\r\n", omittingEmptySubsequences: false).dropFirst() {
            if line.isEmpty { break }
            if line.lowercased().hasPrefix("host:") {
                let value = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                return Request(host: HostName(value.utf8, allowingPort: true)?.text)
            }
        }
        return Request(host: nil)
    }
}
