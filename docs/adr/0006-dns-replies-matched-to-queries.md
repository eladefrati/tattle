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
3. A query is held in memory for that match and nothing else: its resolver, port, id and
   question, and never more than 1,024 of them. Its question is dropped when its reply is
   taken. A query ten seconds old is answered by no reply, and it, and the resolver, port
   and id of one already answered, are dropped at the sniffer's next pass over its tables,
   which it makes about once a second while it captures. A query never names a connection,
   and is never shown, logged or written to the database.

What ADR-0001 decision 2 says of the map's use stands: it is a fallback, never shown when a
wire name exists, and marked "from DNS".

## Consequences

- A reply forged blind names nothing, and is dropped on its transaction id, before it is
  parsed. A host that sees the query, on a shared network or as the resolver itself, and
  answers first is not stopped: that is the reply the Mac's own resolver takes too, so the
  name shown is the one the Mac was told. On a link whose frames carry no hardware address
  (a tunnel) a query is known as this Mac's by its IP source alone.
- A reply to a query sent before the capture began names nothing, and a lookup answered
  from the system's cache sends no query, as it sent none before.
- What Tattle reads off the network grows by this Mac's DNS queries; the
  [design](../design.md) and the README say so.

## Alternatives

- Taking every reply from a resolver's address to this Mac's, without reading the queries,
  as first built. Reads less, and lets any host on the link name any address. Rejected.
