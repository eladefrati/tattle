import Foundation

enum DNS {
    /// What a query asks, and what its reply repeats.
    struct Question: Equatable, Sendable {
        let name: String
        let type: UInt16
        let qclass: UInt16
    }

    struct Query {
        let id: UInt16
        let question: Question
    }

    struct Reply {
        let id: UInt16
        let question: Question
        var name: String { question.name }  // the question name: what the application asked for
        /// Addresses of records owned by the question name or by a CNAME target reached
        /// from it. Records for other names are dropped: a server answering for its own name
        /// can add records for anyone else's.
        let addresses: [IPAddress]
    }

    /// The labels and pointers one reply may walk, over all its names. Compression lets every
    /// name point into one run of labels, so names within 255 bytes each can still make a
    /// 1,472-byte reply walk about 12,700; 122 A records for a six-label name, as many as the
    /// capture holds, walk 860.
    private static let walkLimit = 1024

    /// The transaction id, which a reply repeats from its query: enough to tell a reply
    /// nobody is waiting for without reading the rest of it.
    static func transactionID(_ payload: ArraySlice<UInt8>) -> UInt16? {
        guard payload.count >= 2 else { return nil }
        return UInt16(payload[payload.startIndex]) << 8 | UInt16(payload[payload.startIndex + 1])
    }

    /// A standard query with one question, as a resolver's client sends it. Whatever
    /// follows the question (an EDNS record) is not read.
    static func parseQuery(_ payload: ArraySlice<UInt8>) -> Query? {
        let bytes = Array(payload)
        var r = ByteReader(bytes)
        var walk = walkLimit
        do {
            let id = try r.u16()
            let flags = try r.u16()
            guard flags & 0xf800 == 0 else { return nil }  // a query, and a standard one
            guard try r.u16() == 1 else { return nil }
            try r.skip(6)
            guard let name = try readName(bytes, &r, &walk) else { return nil }
            return Query(id: id, question: Question(name: name.text, type: try r.u16(), qclass: try r.u16()))
        } catch {
            return nil
        }
    }

    static func parseReply(_ payload: ArraySlice<UInt8>) -> Reply? {
        let bytes = Array(payload)
        var r = ByteReader(bytes)
        var walk = walkLimit
        do {
            let id = try r.u16()
            let flags = try r.u16()
            guard flags & 0x8000 != 0 else { return nil }  // responses only
            let questions = Int(try r.u16())
            let answers = Int(try r.u16())
            try r.skip(4)
            // A resolver answers one question, and RFC 9619 makes more a malformed message.
            guard questions == 1 else { return nil }
            guard let qname = try readName(bytes, &r, &walk) else { return nil }
            let question = Question(name: qname.text, type: try r.u16(), qclass: try r.u16())
            var records: [(owner: String, address: IPAddress)] = []
            var aliases: [String: [String]] = [:]
            for _ in 0..<answers {
                let owner = try readName(bytes, &r, &walk)
                let type = try r.u16()
                try r.skip(6)
                let rdlen = Int(try r.u16())
                let start = r.pos
                let rdata = try r.take(rdlen)
                guard let owner else { continue }
                if (type == 1 && rdlen == 4) || (type == 28 && rdlen == 16) {
                    records.append((owner.text, IPAddress(bytes: Array(rdata))))
                } else if type == 5 {
                    var target = ByteReader(bytes, from: start, to: start + rdlen)
                    // A target that runs past its RDATA is no alias; the rest of the reply stands.
                    do {
                        if let alias = try readName(bytes, &target, &walk) { aliases[owner.text, default: []].append(alias.text) }
                    } catch NameError.pastRecord {}
                }
            }
            // Every name the question reaches through CNAMEs, each visited once.
            var reached: Set<String> = [qname.text]
            var queue = [qname.text]
            while let name = queue.popLast() {
                for alias in aliases[name] ?? [] where reached.insert(alias).inserted { queue.append(alias) }
            }
            return Reply(id: id, question: question, addresses: records.filter { reached.contains($0.owner) }.map(\.address))
        } catch {
            return nil
        }
    }

    /// A name whose bytes in the stream run past the reader's end, inside the reply.
    private enum NameError: Error { case pastRecord }

    // Reads a name with RFC 1035 compression; the reader advances past the name as it
    // appears in the sequential stream, not past any pointer target. That part of the name
    // lies within the reader's end, a record's RDATA for a CNAME; a pointer can lead anywhere
    // in the reply. A name that runs past that end throws `NameError.pastRecord`. Nil for a name that is
    // not a host name; a label holding a dot is one, since joining would hide it. Each label
    // and pointer spends one of the reply's `walk`. Throws for a name past RFC 1035's 255
    // bytes or a walk past the reply's limit: the walk stops inside the name, so where it
    // ends in the stream is unknown.
    private static func readName(_ bytes: [UInt8], _ r: inout ByteReader, _ walk: inout Int) throws -> HostName? {
        var labels: [ArraySlice<UInt8>] = []
        var length = 1  // on the wire, the root's zero byte included
        var pos = r.pos
        var jumped = false
        var hops = 0
        while true {
            let end = jumped ? bytes.count : r.end
            // Past a record's end but inside the reply: the record is wrong, not the reply.
            func short(_ inReply: Bool) -> Error { inReply ? NameError.pastRecord : ByteReader.ParseError.short }
            guard pos < end else { throw short(pos < bytes.count) }
            let len = Int(bytes[pos])
            if len == 0 {
                pos += 1
                if !jumped { r.pos = pos }
                break
            }
            walk -= 1
            guard walk >= 0 else { throw ByteReader.ParseError.short }
            if len & 0xc0 == 0xc0 {
                guard pos + 1 < end else { throw short(pos + 1 < bytes.count) }
                let target = ((len & 0x3f) << 8) | Int(bytes[pos + 1])
                if !jumped { r.pos = pos + 2 }
                jumped = true
                pos = target
                hops += 1
                guard hops < 64 else { throw ByteReader.ParseError.short }
                continue
            }
            guard pos + 1 + len <= end else { throw short(pos + 1 + len <= bytes.count) }
            length += 1 + len
            guard length <= 255 else { throw ByteReader.ParseError.short }
            labels.append(bytes[(pos + 1)..<(pos + 1 + len)])
            pos += 1 + len
        }
        guard !labels.contains(where: { $0.contains(UInt8(ascii: ".")) }) else { return nil }
        return HostName(Array(labels.joined(separator: [UInt8(ascii: ".")])))
    }
}
