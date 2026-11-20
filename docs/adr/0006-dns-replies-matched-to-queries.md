---
title: "ADR-0006: A DNS reply names an address only when it answers this Mac's query"
status: Accepted
date: 2026-11-19
---

# ADR-0006: A DNS reply names an address only when it answers this Mac's query

**Status:** Accepted. Supersedes, in [ADR-0001](0001-sniffer-coverage.md) decision 2, which
DNS replies build the map.

## Context

[ADR-0001](0001-sniffer-coverage.md) made the map built from port-53 replies a fallback for
connections nothing else named. As built, the map took a reply on its addresses alone: sent
from a resolver this Mac asks, to this Mac. Every host on the link can write both, so one
that saw none of this Mac's traffic could put a name of its choosing on any address, shown
on a row marked "from DNS", and could keep the capture busy parsing replies nobody asked
for. The sniffer read no outgoing DNS: the kernel filter dropped this Mac's port-53 queries,
so nothing told a reply that answers a query from one that answers none.

## Decision

1. A reply enters the map only when it answers a query this Mac sent: its resolver, port,
   transaction id and question are those of a query still waiting.
2. The sniffer therefore reads this Mac's outgoing port-53 queries to its resolvers, which
   it did not read before.
3. The namer holds a query for that match and nothing else: its resolver, port, id and
   question, and never more than 1,024 of them. Its question is dropped when its reply is
   taken. A query ten seconds old is answered by no reply, and it, and the resolver, port
   and id of one already answered, are dropped at the namer's next pass over its tables,
   which it makes about once a second while the sniffer captures. Beside the namer, the
   capture's read buffer holds the packets last read, queries among them, until a later
   read overwrites them. A query never names a connection, and is never shown, logged or
   written to the database.

What ADR-0001 decision 2 says of the map's use stands: it is a fallback, never shown when a
wire name exists, and marked "from DNS".

## Consequences

- A reply alone names nothing: one that answers no query is dropped on its transaction id,
  before it is parsed. A forger now has to be believed about a query too.
- A query is taken for this Mac's by its frame: from the interface's own hardware address,
  and addressed to another host's. Any host on the link can write this Mac's hardware
  address as a frame's source, but such a frame reaches this Mac only when it is addressed
  to this Mac's own address or to a broadcast or multicast one, and a frame addressed so is
  not read as sent. The same test stands before every packet read as sent, a connection's
  first packets included.
- A network whose gateway answers at a broadcast or multicast hardware address keeps its
  names and loses this protection. Everything this Mac sends past such a link is addressed
  so, and the test would leave every connection unnamed. The sniffer therefore reads the
  gateway's hardware address from the system's neighbour table when it builds its filter,
  and where that is a group address it reads a frame addressed to one as sent; a frame
  addressed to this Mac's own address is still not. A host able to rewrite this Mac's entry
  for the gateway turns the test off the same way, and then receives this Mac's traffic in
  any case. While the gateway's address cannot be read, the test stays.
- That test does not cover a link whose frames carry no hardware address (a tunnel), where
  a query is known as this Mac's by its IP source alone, nor an interface in promiscuous
  mode, which also receives a forged frame addressed to a third host. A resolver on the
  link that is not the gateway and answers at a group address has its queries left unread,
  so its replies name nothing.
- A host that sees a real query, on a shared network or as the resolver itself, and
  answers first is not stopped either: that is the reply the Mac's own resolver takes too,
  so the name shown is the one the Mac was told.
- A reply to a query sent before the capture began names nothing, and a lookup answered
  from the system's cache sends no query, as it sent none before.
- What Tattle reads off the network grows by this Mac's DNS queries; the
  [design](../design.md) and the README say so.

## Alternatives

- Taking every reply from a resolver's address to this Mac's, without reading the queries,
  as first built. Reads less, and lets one forged reply name any address. Rejected.
