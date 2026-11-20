---
title: "ADR-0001: Sniffer coverage"
status: Accepted; decision 2 superseded in part by ADR-0006
date: 2026-10-19
---

# ADR-0001: Sniffer coverage

**Status:** Accepted. Decision 2 is superseded by
[ADR-0006](0006-dns-replies-matched-to-queries.md) in which DNS replies build the map.

## Context

The [PRD](../PRD.md) makes the Network tab's value depend on a BPF sniffer
naming outbound connections from DNS replies, TLS SNI and QUIC Initial packets, and asks
for that coverage to be measured before anything is built on it (build order step 0).

`tools/sniff-spike` ran on the development machine (macOS 26, en0, iCloud Private Relay on,
IPv4 only; the interface had no routable IPv6 address) for 24 hours from 2026-10-18 16:56,
through an evening, a night of sleep and a work day. New outbound connections: 27,358, of
which 17,915 to public addresses, 9,413 to local scope, and 30 UDP flows first seen
mid-connection (18 open when capture started, 12 idle QUIC connections re-counted by the
spike's 120-second gap rule).

Of the 17,915 public connections:

| Outcome | Count | Share |
|---|---|---|
| TLS SNI (TCP), real destination | 10,437 | 58.3% |
| QUIC Initial (UDP), real destination | 6,962 | 38.9% |
| DNS reply only | 75 | 0.4% |
| HTTP Host header | 35 | 0.2% |
| Relay ingress named, destination hidden | 353 | 2.0% |
| Encrypted Client Hello cover name, destination hidden | 13 | 0.07% |
| No name | 27 | 0.15% |

Real destination named: 17,509, or 97.7%.

The relay row is what the spike counted as relay ingress: iCloud Private Relay
(`mask.icloud.com` 319, `mask-api.icloud.com` 20), the `apple-relay.*` hosts (14), which Apple
lists for Private Cloud Compute and Apple Intelligence Extensions, and hosts named for
Oblivious HTTP (`ohttp-relay*` 13). The sniffer read those names correctly; they are the
relay, not where the traffic goes, and one Private Relay connection carries many Safari
destinations, so the per-connection share understates what is hidden.
The 13 ECH connections carried the outer name `cloudflare-ech.com`.

No QUIC Initial sent to a public address failed to decrypt. The 27 unnamed were SSH to
GitHub (15), STUN (2), and ten TCP connections on ports 443 and 80 with no handshake seen
within the spike's 20-second window; four of those ten fall in the first seconds after the
overnight wake, so they are most likely SYNs sent before the network was back. The spike
does not record whether any payload arrived, so "unparseable" and "never answered" cannot
be told apart in this data.

A port-53 DNS reply had, at some earlier point in the day, named the address of 34% of
public connections. Where both a DNS name and a wire name exist (6,073 connections), they
name different registrable domains 40% of the time (`bridge.claudeusercontent.com` against
`api.anthropic.com` on one shared address, for instance): an address-keyed DNS map is
ambiguous wherever a CDN serves many names from one address. That 34% is therefore an upper
bound on what DNS alone could have named correctly. The rest of the lookups did not pass
on port 53; Private Relay's encrypted DNS and browser DNS-over-HTTPS are the likely reasons,
not verified here.

The spike also confirmed, as a side effect, what the product is for: one audio plugin
contacted its version server 1,108 times in a day (every instantiation, driven by a test
harness creating tracks that carry it), and Claude Code sessions posted 1,156 batches of
logs to a third-party log intake.

## Decision

1. The Network tab names a connection from the connection itself first: TLS SNI on TCP,
   the ClientHello inside QUIC Initial packets on UDP, the Host header on plaintext HTTP.
   QUIC Initial parsing is in the first version, not deferred: it names 39% of connections
   on this machine.
2. The DNS map built from port-53 replies is a fallback for what the above misses, and
   only when nothing else named the connection. It is never shown as the name when a wire
   name exists, and it is marked as "from DNS" when shown, because an address-keyed map
   disagreed with the wire name 40% of the time here. How much it covers on a Mac without
   Private Relay is unmeasured. Which replies build the map is decided in
   [ADR-0006](0006-dns-replies-matched-to-queries.md).
3. A server name that is a known relay ingress (`mask*.icloud.com`, `ohttp-relay*` on
   Cloudflare and Fastly, and `apple-relay.cloudflare.com` and `apple-relay.fastly-edge.com`,
   which Apple lists for Private Cloud Compute, each anchored to its operator's domain) is
   shown as "relayed", and a known Encrypted Client Hello cover name (`cloudflare-ech.com`)
   as "name hidden". Neither is ever shown as the destination. The lists live in the seed
   knowledge base so they can grow without a code change; a pattern never leaves the
   registrable domain open, since anyone can register `apple-relay.example`. A name that
   came only from the DNS fallback is never classified this way: it stays a destination
   marked "from DNS", whatever the knowledge base says of it.
4. Whether a connection existed before Tattle started looking is decided from the socket
   table, which the app holds, not from the sniffer; the spike's pre-existing bucket was a
   measurement rule only.
5. The spike stays in the repo under `tools/` as the reference parser until the app's own
   sniffer replaces it. It was removed in `4a791a2`; `git show 4a791a2^:tools/sniff-spike/`
   lists it.

## Consequences

- The Network tab can promise a real destination name for about 98% of new connections on
  this class of machine, with the remaining 2% shown as relayed, hidden, or unnamed rather
  than filled in from DNS.
- The number is one machine, one day, one set of apps, IPv4 only. ECH was 0.07% of
  connections and will grow as browsers and CDNs adopt it; the tab shows the share of
  relayed and hidden connections rather than hiding it.
- Private Relay also means the system resolver is not where most names pass; a design that
  started from DNS would have offered a name for a third of connections on this machine,
  and a wrong one for a large share of those.
- Browser connections are still attributed to the browser, not the page (PRD, Future:
  per-page browser attribution).
- Two spike defects found in review do not affect this result but go into the reference
  parser before the app inherits it: TCP ClientHello reassembly ignores sequence numbers,
  and the local address set is read once at start.

## Alternatives

- DNS-only naming. Simplest parser, no decryption; at most a third of connections here,
  with a 40% disagreement rate against the wire name. Rejected as the primary source.
- Deferring QUIC. Would have left 39% of connections to the DNS fallback, which with
  Private Relay means mostly unnamed. Rejected.
- Network Extension. Not available without a paid developer account, and would not supply
  hostnames for browser or Electron traffic anyway (PRD, Future).
