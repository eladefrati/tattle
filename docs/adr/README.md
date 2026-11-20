# Architecture decision records

Each record states one decision and the context it was made in. The [PRD](../PRD.md)
and the [design](../design.md) are kept current with them.

| ADR | Decision | Sections it changes |
|---|---|---|
| [0001](0001-sniffer-coverage.md) | Name a connection from the connection itself first: TLS SNI, the QUIC Initial, the HTTP Host header. A name from DNS replies is a fallback, marked "from DNS". | design: Network; PRD: Network |
| [0002](0002-login-items-full-disk-access.md) | Read the login-items database with Full Disk Access, asked for from the Startup tab. Sign builds with a stable identity so the grant survives rebuilds. | design: Startup; PRD: Startup, Distribution |
| [0003](0003-bpf-descriptor-broker.md) | Keep `/dev/bpf*` root-only. A root launch daemon checks the caller and hands it one capture descriptor over XPC. | design: Privileges; PRD: Non-goals (root beyond packet access), Network, Startup, Distribution |
| [0004](0004-process-responsibility-private-calls.md) | Use two private libquarantine calls, resolved at run time in one file: read which app a launchd service works for, and start Explain's command answering for itself, so it does not hold Tattle's privacy grants. | design: Processes |
| [0005](0005-shipped-rules-from-the-app.md) | Read the shipped rules from the app bundle at launch, never from the database. Read only a model's answers from the database, and only for the exact item. | design: Knowledge base, Storage; PRD: Explanation pipeline, Future |
| [0006](0006-dns-replies-matched-to-queries.md) | Take a DNS reply into the name map only when it answers a query this Mac sent. Read this Mac's outgoing port-53 queries for that match, and hold each only until its reply. Supersedes part of ADR-0001's decision 2. | design: Network |
