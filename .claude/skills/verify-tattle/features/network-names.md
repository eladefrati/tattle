# Network names and unnamed reasons

The Network tab lists open connections grouped by app. With packet access, each
connection to the internet gets the name it went to, from its TLS or QUIC handshake, its
HTTP request, or a DNS reply. When none of those work, the connection's detail says why
there is no name. History keeps the outcome: `name` and `nameSource` (`sni`, `quic`,
`http`, `dns`), or no name and `nameSource` `none:<reason>`.

## Sub-features

- `net-header`: a summary line, `N open from M apps`, then the already open and `K named` /
  `from DNS` / `relayed` / `with the name hidden` counts. Connections to addresses this Mac
  has not reached before are listed first, under `First contact`, each `<app> to <name or
  address>`; the rest are grouped by app under `Seen before`. `named`
  counts names from the connection's own packets; DNS names are counted apart.
- `net-dns`: a name that came only from a DNS reply carries a grey `from DNS` tag after it
  in the row, and the detail says `Name from a DNS reply for the address`.
- `net-group`: a group row per app, opening a detail with facts and its connections.
- `net-named`: a connection detail with `Destination`, `Address`, and `Name from` (for
  example `what the program asked for in its HTTP request`): a name off the wire is the
  program's word, which nothing checks against the address.
- `net-unnamed`: a connection detail with `No name` and the reason: `the connection did
  not start with a TLS or HTTP handshake`, `no complete handshake came in the connection's
  first 20 seconds`, `part of the handshake was missed`, `the handshake carried no server name`,
  `the HTTP request's Host header was not a host name`,
  `the QUIC handshake could not be read`, `a QUIC version Tattle cannot read`, `too many
  connections opened at once for Tattle to follow this one`, `the packet capture stopped or
  restarted before this connection's handshake was read`.
- `net-signers`: a connection's detail names who signed the process that made it (`Signed
  by`), and the app it is filed under apart when that differs (`App signed by`, `App team`).
  A script reads `Signed by script, not signed`, with `Runs with` and `Interpreter signed
  by`; one of Apple's developer tools reads `Signed by unnamed code`. History keeps both, in
  `signer` and `appSigner`. A row whose connections have different signers names none. A
  process that replaces itself with another program is read again for its next connections,
  even when that program then deletes its file.
- `net-foreign`: a file in an app's bundle that the app's signer did not sign keeps the row
  from naming that signer and from holding any answer given for the app; what the app only
  launches does not. A row whose reading names no signer (`ad hoc signed`, `unsigned`) keeps
  it.
- `net-direction`: a connection states a direction on the first of these that holds. Outbound:
  this Mac's SYN or QUIC Initial was seen leaving, which needs packet access and a destination
  the sniffer follows; the detail is headed `<app> to <name>`, with `Destination` and `First
  contact`. Inbound: the socket sits on a listener's endpoint of its own family; a grey
  `incoming` tag, `<app> from <peer>`, `From` and `To port`. Outbound again: a local port of
  49152 or above, macOS's ephemeral range, which needs no packet access. Otherwise neither is
  claimed: `<app> with <peer>`, `Peer` and `Local port`, no `new`, no `First contact`, and the
  address does not count as reached. A group row says `N to`, `N from` or `N with the
  internet`. The model is told none of `Destination`, `First contact`, `From`, `To port`,
  `Peer` and `Local port`, since its answer is kept for the host. History keeps it in
  `direction`.
- `net-reach`: `Reach` reads `this network` for private, link-local and shared (100.64/10,
  Tailscale's) addresses.
- `net-history`: the same outcome in the `connection` table, written even when the
  connection closed before the outcome arrived. The database is written ahead, with
  `tattle.sqlite-wal` and `tattle.sqlite-shm` beside it, and an outcome finds its row by the
  whole flow, through the `connection_flow` index.
- `net-names-off`: without packet access, the summary says `Destinations are addresses:
  names need packet access, which Tattle does not have yet`.

## How to get to it (user POV)

- Click the eye in the menu bar; the panel opens on the Network tab.
- Choose an app's row, then a connection row.

## Driving it with tattle-verify

Preconditions:

- Open run; doctor all `ok`, capture `through the broker`.
- example.com reachable on port 80 and github.com on port 22.

- **Known connections.** Run `$V connect named`, `$V connect garbage`, `$V connect
  silent`, each printing its local port. Wait 25 s so the silent one passes the 20 s
  timeout.
- **List.** Run `$V tab Network` and `$V save network-list`. The summary starts `N open from M
  apps` and includes `K named`; a `<terminal>, ...` row is there
  (the `nc` connections file under the terminal app that started them; SKILL.md, Gotchas).
- **Group.** Run `$V ax press --prefix "<terminal>,"` and `$V ax text`. Connection rows read
  `example.com, new, <ip>:80 · TCP · connected · nc, ...` for the named one and
  `<github ip>:22, new, TCP · connected · nc, ...` for the other two. Use `$V ax scroll
  down` if they are below the fold.
- **Named.** Press `--prefix "example.com, "`, `$V ax wait "Name from"`, `$V save
  named-detail`. Facts: `Destination example.com`, `Name from what the program asked for in
  its HTTP request`, `Process nc (pid <pid>)`, `App <terminal>`.
- **Unnamed, not a handshake.** `Back`, press `--prefix "<github ip>:22, "`, check the
  `Process nc (pid ...)` fact against the garbage pid (else `Back` and open the other
  row with `$V ax dump` to find it), `$V save garbage-detail`. Facts: `No name
  the connection did not start with a TLS or HTTP handshake`.
- **Unnamed, timeout.** The same for the silent connection, `$V save silent-detail`. Facts:
  `No name no complete handshake came in the connection's first 20 seconds`.
- **From DNS.** Look github.com up over UDP from the gateway, `dig +short github.com A
  @<gateway>`, then `$V connect garbage` and the same lookup once more, in case the answer
  moved. The group's row reads `github.com, from DNS, <ip>:22 · TCP · connected · nc, ...`;
  its detail has `Destination github.com` and `Name from a DNS reply for the address`, and
  history `github.com | dns`. The sniffer saw this Mac's query and took the reply to it.
- **History.** `$V db "select localPort, pid, processName, remoteAddress, remotePort,
  name, nameSource from connection where localPort in (<three ports>)"`: `example.com |
  http`, `| none:not-handshake`, `| none:timeout`.
- **Log.** `$V log "<port1>|<port2>|<port3>"`: `no name for tcp/<port>><ip>:22:
  notHandshake` and `...: timeout` lines.
- **History database.** doctor's migration is `v1-schema`. `$V db "pragma
  journal_mode"`: `wal`, with `tattle.sqlite-wal` and `tattle.sqlite-shm` in the data folder.
  `$V db "explain query plan select * from connection where proto = 'tcp' and localPort = 1
  and remotePort = 80 and (remoteAddress = 'x' or remoteAddress = '::ffff:' || 'x') order by id
  desc"`: `SEARCH connection USING INDEX connection_flow (remoteAddress=? AND localPort=? AND
  remotePort=? AND proto=?)`, the lookup a name makes. For a name on the newest row of a reused
  four-tuple: once the named connection has closed and 30 s have passed, `$V connect named
  --port <its port>`; the history query by that port shows the new row named too.

- **A connection's own signer.** Every connection here goes to the Mac's own LAN address,
  so nothing leaves it and no packet access is needed. With `IP=$(ipconfig getifaddr en0)`,
  run from a script in a terminal app (Ghostty here): a listener on each of three ports,
  `sleep 317 | nc -l $IP <port> > /dev/null &`, then:
  - `sleep 317 | nc $IP 18081 > /dev/null &`. Detail: `Process nc`, `App Ghostty`, `Signed
    by Apple`, `App signed by Mitchell Hashimoto`, `App team 24VZTF6M5V`.
  - A renamed copy of Apple's interpreter: `cp <tools>/usr/bin/swift-frontend
    <dir>/bin/updater`, `ln -s <tools>/usr/lib <dir>/lib`, then `<dir>/bin/updater -frontend
    -sdk <sdk> <dir>/job.swift -interpret &`, where `<tools>` is
    `/Library/Developer/CommandLineTools` and `job.swift` connects to `$IP:18082` and sleeps;
    allow 30 s to compile. Detail: `Process job.swift`, `Runs with updater
    (<dir>/bin/updater)`, `Signed by script, not signed`, `Interpreter signed by Apple,
    outside macOS`, `Interpreter team 59GAB85EFG`, and the terminal's `App signed by`.
  - One of Apple's developer tools: with an Apple-signed Xcode, `<Xcode>/Contents/Developer/
    usr/bin/git ls-remote http://$IP:18083/x &`, which waits for a reply that does not come.
    Detail: `Process git-remote-http`, `App Ghostty` (not Xcode), `Signed by unnamed code`,
    `Interpreter signed by Apple, outside macOS`.

  Press `Ghostty,` (its subtitle is the app's signer), then `--prefix "$IP:<port>,"`. `$V db
  "select processName, appName, signer, appSigner from connection where remotePort in
  (18081, 18082, 18083)"`: `nc | Ghostty | Apple | Mitchell Hashimoto`, `job.swift | Ghostty
  | script, not signed | Mitchell Hashimoto`, `git-remote-http | Ghostty | unnamed code |
  Mitchell Hashimoto`.
- **A row whose connections differ.** From launch agents, so no app takes them: one running
  your own program named `nc` to `$IP:18092`, then `/bin/sh -c "sleep 200 | /usr/bin/nc $IP
  18091"`. The row reads `nc, 2 on this network, 2` with no signer, and its detail has no
  `Signed by`. Each connection's detail has its own: `Apple` and `unsigned`.
- **A file put in a bundle.** Build `Tool.app` with your own `Contents/MacOS/Tool`, `codesign
  -s - Tool.app`, then copy another program to `Contents/MacOS/dropper` and start it from a
  launch agent. Row `Tool, 1 on this network · ad hoc signed`; `Explain` shows the answer with
  no `Confirm` and stores nothing. With `Tool` itself running instead, and the dropper's
  connection gone, `Explain` offers `Confirm` and stores `ad-hoc:<hash>:<path of Tool.app>`.
- **An Apple-signed file outside macOS.** On the test Mac, with no need of the broker: a launch
  agent's own program, at a path outside macOS's folders, that waits and then holds a
  connection to `example.com:80`; move a copy of `/usr/bin/nc` over its path before it
  connects. The connection's detail has `Signed by Apple, outside macOS`. Moved over once the
  connection is open, the detail keeps its first reading: an owner is read when its connection
  is first seen.
- **A process that replaces itself.** A launch agent running `/bin/bash exec.sh $IP`, which
  does `exec 3<>/dev/tcp/$1/18095; sleep 12; exec /usr/bin/nc $1 18096 < <(sleep 300)`. `$V db
  "select pid, processName, signer, remotePort from connection where remotePort in (18095,
  18096)"`: one pid, `exec.sh | script, not signed | 18095` and `nc | Apple | 18096`.
- **One whose new program deletes its file.** The same agent with `exec <dir>/dropper $1 18096`
  in place of `nc`, where `dropper` is your own program that unlinks `argv[0]`, then connects
  and sleeps. The same query: one pid, `exec.sh | script, not signed | 18095` and `dropper | |
  18096`, with no signer. Row `dropper, 1 on this network, 1`, with no signer either.

- **A connection's direction.** With the broker. `$V connect named`, then its row: detail
  headed `<terminal> to example.com`, with `Destination` and `First contact`. A row open since
  before the copy started, from a local port of 49152 or above: `already open`, headed `<app>
  to <address>`, with `Destination` and `First contact`. On a lower local port with no
  listener: no tag, headed `<app> with <address>`, `Peer`, `Local port`, no `First contact`.
  `$V db "select direction, scope, count(*) from connection where ended is null group by
  direction, scope"`.
- **Owners of short-lived connections.** With the broker and the panel never opened. Run the
  `connect named` bytes with no hold (`{ printf '<its GET>'; sleep 0; } | nc -G 5 -p <port> <ip>
  80`) from a script, every 4 s for 120 s; `nc` lives 47 to 140 ms. Count the rows opened in
  the window with no owner: `select count(*) from connection where firstSeen >= '<start>' and
  firstSeen < '<end>' and (processName like 'pid %' or processName = 'unknown process')`, with
  and without `localPort in (<the ports>)`. `firstSeen` is UTC. An `nc` outlives the reading
  that names it, so this cannot show an owner lost by a process that exits while a reading
  resolves it: that rests on `testOwnersKeepTheirLinesWhenTheyExitWhileTheReadingResolvesThem`.
- **Incoming connections and a Tailscale peer.** On the test Mac, with `IP` its `inet 100.` address:
  `sleep 1700 | nc -lk $IP 18091 > /dev/null &` and `sleep 1700 | nc $IP 18091 > /dev/null &`,
  from a script in a terminal app. `-k` keeps the listener, which is what tells the accepted
  socket. Press the terminal's row: `$IP:<port>, incoming, TCP · connected · this network ·
  nc` is headed `<terminal> from $IP:<port>`, with `From`, `To port 18091`, `Reach this
  network` and no `First contact`. An `ssh` held from another Mac over Tailscale reads the
  same in the row `sshd-session: <login>@notty`: `incoming`, `To port 22`, `Reach this network`.

## Gotchas

- `nc` quits at the end of its standard input, and a background job in a script has none:
  feed it from `sleep`, or the connection is gone before the panel is read.
- Copies of macOS's own programs are killed at launch. Apple's programs with a team
  identifier run from anywhere, given the libraries their load paths expect: hence the
  `lib` link for `swift-frontend`.
- A process whose file is not the code it runs proven 2026-11-15 on the test Mac (commit
  `65af67a`): after Apple's binary was renamed over a running ad hoc signed program, a
  connection it opened from a pid with none open before showed no signer, and a pid that had
  a connection open before the swap kept `ad hoc signed`.
- Xcode Service holds no connection, so its row in this tab rests on the unit test
  (`testAnAppAmongApplesDeveloperToolsReadsAsUnnamedCode` in `NetworkSnapshotTests`).
- A foreign executable inside a copy of a publisher's bundle rests on the unit tests
  (`testAConnectionIsSignedByItsOwnProcessAndItsAppApart`,
  `testAFileInABundleItsSignerDidNotSignTakesAwayTheRowsIdentity`, and for the row that names no
  signer `testARowHoldingAFileItsAppsSignerDidNotSignNamesNoSigner`): on the test Mac a new binary put
  in a copy of `Calculator.app`, unsigned or ad hoc, sat held at launch (state `S`, no CPU,
  and a program that only returns never returned), with macOS's `"Calculator" is damaged and
  can't be opened` alert on the screen, so it never opened a connection to read. Started by
  its path, one ran for about two seconds before macOS killed it (2026-11-15): its row in
  Processes was read (processes.md), none in this tab.
  One put in a bundle built on the machine runs, which is the recipe above.
- An Apple-signed file outside macOS proven 2026-11-15 on the test Mac (commit `482f034`),
  without the broker; no run folder was kept. Running a copy of `nc` itself is not the way:
  the copy is killed as it starts. The `Interpreter signed by Apple, outside macOS` lines
  above have not been read in the app since they changed, and rest on the unit tests in
  `ApplesProgramTests`.
- Incoming connections and the Tailscale peer's reach proven 2026-11-08 on the test Mac, run
  `2026-11-08T210232` (commit `353c9b6`); copy in the development Mac's
  `build/verify/runs/test-mac-2026-11-08/`. `from the internet` needs a public peer, so it rests
  on the unit test (`testAnInboundConnectionReadsAsInbound`).
- Direction proven 2026-11-08 on the development Mac with the broker. Run `2026-11-08T222028`
  (commit `1e7f3b8`): a seen opening, `Ghostty to example.com`, `direction` `outbound`. Run
  `2026-11-08T223300` (commit `c968854`), a fresh launch: all 64 internet rows were already
  open and read outbound from their local ports, none unknown. `Herdr Core to
  160.79.104.10:443`, `First contact no`; `Google Chrome to 18.97.36.51:443`, `First contact
  yes`; `identityservicesd with [fe80:17::f86b:c51e:57bf:33c]:1024`, on a port below the range;
  `rapportd from 192.168.x.y:55421`, on a high port, among 128 sockets its listener claims.
  Listeners by family and a seen opening arriving after the row rest on unit tests. The `nc`
  pair over Tailscale does not connect on the development Mac.
- A host's prompt with no direction proven 2026-11-08 on the test Mac, run `2026-11-08T232714`
  (commit `ace1ec6`): `Ghostty to 100.x.y.z:18091` shows `Destination` and `First contact`,
  and the recorded prompt's `facts` are `Protocol`, `Reach` and `Since`. Copy in the development
  Mac's `build/verify/runs/test-mac-2026-11-08/`. An opening seen while a reading resolves owners
  rests on the unit test (`testAnOpeningSeenWhileAReadingResolvesOwnersReachesTheRowAndItsHistory`).
- The two unnamed rows look alike in the list; tell them apart by the `Process nc (pid
  ...)` fact against the pids `connect` printed.
- The panel lists open connections only, and a closed connection's detail keeps the state
  from when it was opened. A connection that closes before its outcome arrives shows the
  outcome in history and the log, never in the panel. example.com closed garbage and
  silent connections after 3 s and 14 s, so the unnamed cases use GitHub's SSH port,
  which holds them about two minutes. Time an open connection with `lsof -iTCP:<port>
  -sTCP:ESTABLISHED`, not with how long `nc` runs.
- The sniffer's DNS fallback names a connection from a UDP DNS reply it captured for
  that address in the last hour (the newest 4096 answers at most), if one of the Mac's resolvers sent it to this Mac
  in answer to a query the sniffer saw this Mac send it in the ten seconds before (same port, id and question), and the
  address's record is for the question name or a CNAME target reached from it. A reply with
  more than one question, a name past 255 bytes, or more than 1,024 labels and pointers to
  walk names nothing. `connect` looks its host up over TCP so the fallback
  cannot name the garbage and silent connections; looking github.com up any other way first (a
  browser, `curl`, `ssh`) turns their outcome into `dns`.
- A name as the program's word and a reply matched to its query, proven 2026-11-19 on the
  development Mac with the broker, dev copy built with both changes,
  run `2026-11-19T223658`: `nc` to example.com shows `Name from what the program asked for in
  its HTTP request`; after `dig github.com` through the system's resolver, which Tailscale
  forwards to the router over the capture interface, `nc` to `140.82.114.4:22` shows
  `github.com, from DNS` and `Name from a DNS reply for the address`, history `github.com |
  dns`. The same after a lookup sent straight to the router (run `2026-11-19T221639`), as
  before the change at `526aa39` (run `2026-11-19T220344`). The log has no `kernel filter rejected`, so the kernel took the program that
  passes this Mac's queries; `testKernelAcceptsTheProgram` skips where `/dev/bpf*` is root-only.
  A reply that answers no query cannot be sent to the Mac on demand: that rests on
  `testADNSReplyThatAnswersNoQueryOfThisMacsIsIgnored` and
  `testAQueryIsHeldOnlyUntilItsReplyOrTenSeconds`. On the test Mac, debug build, CPU time,
  5,000 replies of 88 A records in 1,462 bytes, five runs a side, `526aa39` against the change: one
  nobody asked for 2.35 to 2.89 ms and 88 addresses named, to 0.002 to 0.003 ms and none; one
  that answers a query, with its query, 2.55 to 2.80 ms to 2.60 to 2.78 ms (3.19 in the first
  run), 88 addresses named on both.
- How large real ClientHellos are, measured 2026-11-19 on the development Mac: a debug line
  per segment of each TLS flow over TCP, 12 minutes of the Mac's own traffic a side. At
  `526aa39`, 110 flows: 104 hellos larger than their first segment (median 1,733 bytes,
  largest 2,469, no segment over 1,448), 6 named from the first segment, all 110 named. With
  the change, 120 flows: 108 larger than their first segment, 103 named from the first
  segment, 91 of them before the hello was whole, all 120 named. No segment was cut by the
  snap length on either side, and none ended as `gap`: on this link a segment reaches the
  capture no longer than 1,448 bytes. A name read from a cut segment
  (`testASegmentCutByTheSnapLengthEndsBuffering`), a handshake in a SYN
  (`testAHelloInTheSYNNamesTheFlow`), an address for a name
  (`testNamesThatFailValidationLeaveTheFlowUnnamed`) and the wait after a failed read
  (`testAFailedReadWaitsLongerEachTimeBeforeReopening`) rest on the unit tests: none can be
  made to happen on demand with the hosts and bytes `connect` may send.
- DNS replies bounded, proven 2026-11-10 on the development Mac with the broker, dev copy at
  `c8d4028`, run `2026-11-10T163829`: `nc` to example.com shows `Name from the HTTP request`,
  and with no traffic made for it an `ssh` to `140.82.113.3:22` was logged `notHandshake` and
  kept as `github.com | dns`. It closed in 0.1 s, so the panel never showed it. A refused reply
  cannot be sent to the Mac on demand: the refusals rest on
  `testDNSRefusesAReplyWithMoreThanOneQuestion`, `testDNSRefusesANameLongerThan255Bytes` and
  `testDNSRefusesAReplyThatWalksTooManyLabels`, full-sized replies on
  `testDNSReadsFullRepliesWithCompressedNames`. Parse times on the test Mac, release build, median of
  7 alternating runs a side against `5620662`: the fuzz review's 121-question reply 2.45 to
  0.0001 ms; 99 answers pointing at one 127-label name 1.26 to 0.095 ms; 99 answers pointing at
  one 255-byte name of four labels 0.26 ms on both, since the bound counts labels and pointers,
  not bytes;
  88 A records in 1,462 bytes 0.18 ms on both; the 63-byte reply 4.7 µs on both (15 runs a
  side). The fuzz review's 20 frames from the resolver through `FlowNamer` under ASan: 246 to
  0.11 ms, against 0.08 ms from another host. Scripts, inputs and runs in the chat
  `2026-11-10--fix-13-dns-name-bound--ea8fcbfb`, `artifacts/2026-11-10-dns-bound/`.
- `outcome ... arrived with no live connection` debug lines are normal: the sniffer often
  names a flow before the socket table shows it.
- The single schema proven 2026-11-11 on the test Mac, dev copy at `0ddb3ad`, a fresh data
  folder, run `2026-11-11T115236`: doctor read `v1-schema` as the database's one migration,
  the three tables and four `connection` indexes were there, and `connect named` wrote its row
  (`nc`, port 80, `outbound`). Copy in this Mac's `build/verify/runs/test-mac-2026-11-11/`.
- The history database proven 2026-11-10 on the development Mac with the broker. At `c5cb5ec`,
  run `2026-11-10T151852`, the dev copy's own data as main left it (20,034 rows, rollback
  journal): the first launch switched it to WAL and ran `v8-connection-flow-index`, the rows
  kept, the index on its four columns, the lookup's plan on `connection_flow`, and a named
  connection's row `example.com | http`. `Quit Tattle` left 3.9 MB in `tattle.sqlite-wal` and
  `tattle.sqlite` as it was at launch: the app does not close the database on quit, so the log
  is not folded in at exit. The rest is from the first version of `c5cb5ec`, whose
  index also listed `id`, a commit no longer in the history. Run `2026-11-10T105220`, with a copy of the release build's history
  (211,609 rows) in place of the dev copy's data: the first launch switched it to WAL and ran
  `v8-connection-flow-index`, 507 ms from process start to the startup log line against 296 ms
  for `1f33215` on the same data (run `2026-11-10T104816`), one launch each. doctor read it with
  `sqlite3 -readonly` while the copy ran, and a read after cleanup worked too. `Herdr Core to
  example.com`, `Name from the HTTP request`, history row 211865 `example.com | http`; on the
  same four-tuple after it closed, the new row 211918 `example.com | http`. A 120-second Time
  Profiler trace in each run, panel closed, `trace-summary.txt` in each folder:
  `ConnectionStore.record` 471 of 788 main-thread ms for 50 outcomes, 30 of them to addresses
  holding 2,547 and 26,873 rows, against 20 of 213 ms for 22 outcomes to light addresses, most
  of it GRDB preparing the statement; `open` 108 ms for 57 rows against 13 for 23, `close` 64
  for 35 against 22 for 32, `fsync` on the main thread 43 ms against none.
- History write volume measured 2026-11-10 on the test Mac, dev copy with its own data and no broker,
  panel never opened, 90 minutes each after 2 minutes' warm-up: `1f33215` 573 row changes
  (opens and closes), the first version of `c5cb5ec` (the index with `id`) 665. Logical bytes written 41.85 against
  18.02 MB, 0.073 against 0.027 MB a row change (15-minute slices 0.067 to 0.080 and 0.023 to
  0.030). `tattle.sqlite` changed 279 times against 4 checkpoints, about 25 minutes apart after
  the first. The app's charged disk writes read 32.56 against 1.44 MB, but they leave out the
  kernel's background writeback, which is how the log reaches the disk: 720 commits 250 ms
  apart wrote 8.8 MB and were charged none. Compare logical bytes.
- `sqlite3 -readonly` needs `tattle.sqlite-wal` and `tattle.sqlite-shm` beside the file. macOS's
  SQLite keeps both after the app quits, so `$V db` works with the copy stopped. A copy of
  `tattle.sqlite` alone misses the changes still in the log, fails opened read-only with `unable
  to open database file (14)`, and put back beside another state's `-wal` reads as malformed.
  Move the folder whole, as `--fresh` does, or copy with `.backup`.
- Connections already open when the dev copy started have no name (`open since before
  Tattle started`).
- An owner and its app read with the socket table, its line walked through one reading of every
  process's record, with no sweep of the process table: shown 2026-11-09 on the development Mac
  with the broker, dev copy at `5a2cb87`, run `2026-11-09T234833`: `Herdr Core to example.com`,
  `Process nc (pid 18853)`, `App Herdr Core`, `Signed by Apple`, `App signed by Herdr, Inc.`, and
  in history `nc | example.com | http | Herdr Core | Apple | Herdr, Inc.`; the same at `d92575d`,
  run `2026-11-09T192354`. A 120-second Time Profiler trace of `4661443` with the panel never
  opened, 26 new connections, summary in the development Mac's
  `build/verify/runs/2026-11-10T004954-trace/`: no `ProcessTable.list`; `ProcessTable.records`
  46 ms in all, 34 of them the kernel's table; `ProcessTable.lines` 3 ms; `URL(fileURLWithPath:)`
  only under `AppBundle.name`, 2 ms. Its one `pid <n>` row was `ssh` to the test Mac's port 22, as were
  all six in the trace of `5a2cb87`. The short-lived recipe above, five alternating 120-second windows per side:
  driven connections with no owner 1 of 150 at `45b8658` and 0 of 149 at `d92575d` (one `nc`
  exited with an error and left no row); all new rows with no owner 10 of 303 and 9 of 273,
  the rest TCP to the router's port 53, one per window as the driver's `dig +tcp` is, and to
  the test Mac's port 22. That shows no difference for processes that live 47 ms or more, and nothing
  about ones that exit sooner.
- Owners of processes that exit within a reading, simulated on the test Mac (debug build, not the app):
  a helper connects to a loopback listener and exits 26 to 42 ms later; 20 ms after the accept
  one reading is taken, with the helper's socket rewritten to a private address. The simulation
  is `QuickExitSimulationTests`, which runs only when `TATTLE_SIM_HELPER` names the helper built
  from `Tests/quick-exit-helper.c`; compare two revisions in copies of each (`git archive`),
  alternating which runs first. Main had no reading seam at `45b8658`, so its side ran the same
  test with that commit's reading (the socket table and the whole process list in one task,
  then `fold`) in place of `poll()`. The reading by owner is not detectably worse than that sweep. The runs, newest
  first, each against `45b8658`:
  - 2026-11-10, `4661443`, 1,440 runs per side in twelve rounds alternating which ran first,
    counting apart the owners named without a path (read after the helper exited, by the
    kernel's name alone): `pid <n>` 228 and 226, a paired difference of 0.17 a round (standard
    deviation 5.9, so about −3.6 to +3.9 a round of 120); named without a path 42 and 138; no
    `unknown process`, missing row or failed helper.
  - 2026-11-10, `5a2cb87`, a review's rerun, the same design, an owner named without a path
    counted as named: `pid <n>` 214 and 219, −0.4 a round (standard deviation 7.3).
  - 2026-11-10, `5a2cb87`, the same design and counting: `pid <n>` 162 and 192, −2.5 a round
    (standard deviation 5.3).
  - 2026-11-09, 720 runs per side in rotating order: 112 at `45b8658`, 126 at `475eee3` and 174
    at `d92575d`, which read owners after the table. Whether a side ran first or last in a
    round moved its count more than which side it was: two fixed-order sets of 480 gave 55 and
    58 at `45b8658`, 68 (run second) and 44 (run first) at `475eee3`.
- What a flood of new flows costs behind the namer, simulated on the test Mac (release build
  of the tests, not the app): a stand-in capture delivers new TCP flows at a fixed rate, each a
  SYN and a ClientHello with a name and an address of its own, to a `NetworkObserver` with an
  empty socket table and a database on disk. The simulation is `CaptureFloodSimulationTests`,
  which runs only when `TATTLE_FLOOD_RATE` gives the flows a second (`TATTLE_FLOOD_SECONDS`
  how long, 30): `TATTLE_FLOOD_RATE=1000 swift test -c release -Xswiftc -enable-testing
  --filter CaptureFloodSimulationTests`. Each second it prints what the observer holds, the
  process's footprint, how long a block queued on the main thread waited (`lag`) and how late
  a 100 ms timer on its run loop fired (`timer`); the lines stop while the main thread is
  held. 2026-11-15, `845a497` (nothing capped) against `e1a4f83` (the kinds, the pending names
  and the events on their way to the main actor capped), one run each, taken before the
  branch was rebased onto `0da26f4`, when a name's kind was still read from the database:
  - 1,000 flows a second for 330 s: outcomes and openings held 300,000 each against 4,089,
    kinds 330,000 against 4,075, footprint 124 against 11 MB, `lag` up to 734 against 32 ms.
    No event dropped.
  - 10,000 a second for 30 s: outcomes, openings and kinds held 300,000 each against 4,089
    (kinds 4,058), footprint 116 against 11 MB, `lag` up to 50 s against 27 ms, `timer` 48 s
    against 26 ms, the main thread caught up 68 s after the last flow against 1 s. With the
    caps 422,668 of the 600,000 events were dropped: about 3,000 flows a second were handled.
  - 100 a second for 30 s: 3,000 of each held, 8 and 7 MB, no `lag`, on both.
  - After the rebase, at `a7db41f`, with a name's kind read from memory, one run each: 10,000
    a second for 30 s held 4,063 outcomes and openings and 3,848 kinds, 11 MB, `lag` up to
    38 ms, `timer` 24 ms, 484,016 of the 600,000 events dropped, so about 1,900 flows a second
    handled; 1,000 a second for 30 s dropped none, with `lag` up to 19 ms.
- A process's own name for itself proven 2026-11-09 at `d92575d`, run `2026-11-09T192510`:
  `exec -a` with `.`, `..` and `~` read as that text in the row and in `processName`, with no
  dependence on the app's working directory or home. A home folder (`~`, `~user`) or a relative
  path ending in `.` or `..` now reads as the program's file, and an absolute path keeps its last
  component as before; that rests on `testTheNameAProcessStartedUnderIsNotAPathToResolve`. At `d92575d` an empty `argv[0]` did not
  reach the naming: `ProcessTable.parseArguments` took it for the padding after the executable's
  path, so the process was named after its next argument (`G` for `nc -G 5 ...`), or after its
  first environment string when it had none, and that string joined its arguments. The parser
  now skips the padding by its length; a real process with an empty `argv[0]` rests on
  `testAnEmptyFirstArgumentIsReadAsOne`, not yet on a run in the app.
- A connection's own signer proven 2026-11-08 on the test Mac, dev copy at `8d52901`, run
  `2026-11-08T105543`, copied to `build/verify/runs/test-mac-2026-11-08/`.
- The relay and OHTTP rules read from the `rule` table at `5c51a9e` on the test Mac, run
  `2026-11-08T122412`; no traffic to those hosts can be made on demand.
- A row whose connections differ, a file put in a bundle and a process that replaces itself
  proven 2026-11-08 on the test Mac, dev copy at `5c51a9e`, run `2026-11-08T122412`; the bundle's own
  executable in run `2026-11-08T122957`. Copied to `build/verify/runs/test-mac-2026-11-08/`.
- A process whose new program deletes its file proven 2026-11-08 on the test Mac, dev copy at
  `b35ef02`, run `2026-11-08T141229`, copied to `build/verify/runs/test-mac-2026-11-08/`.
- The three known connections after the review fixes of 2026-11-10, proven that day on the
  development Mac with the broker, dev copy at `06f366f`, run `2026-11-10T192212`: `capturing on
  en0, link type 1, through the broker`; `nc | Herdr Core | example.com | http`, `none:not-handshake`
  and `none:timeout` in history, all `outbound`; the details read `No name the connection did
  not start with a TLS or HTTP handshake` and `No name no complete handshake came in the
  connection's first 20 seconds`. A QUIC flow, a socket two processes share and an IPv4-mapped
  peer rest on unit tests (`testAQUICStreamThatIsNoClientHelloEndsAtOnceAsOverTCP`,
  `testASocketAnotherProcessUsedLastIsTheSameConnection`,
  `testFirstContactCountsOnlyThisMacReachingOut`).
- A CNAME read only inside its RDATA cannot be seen in the panel: it rests on
  `testDNSReadsACNAMETargetOnlyInsideItsRecord` and `testDNSDropsOnlyACNAMEThatRunsPastItsRecord`
  (2026-11-15).
- The namer's own addresses as the capture interface's alone, and the caps behind it, proven
  2026-11-15 on the test Mac with the broker, dev copy at `d977ff6`: doctor read every check
  `ok`, capture through the broker. `connect named` read example.com from the HTTP request,
  `outbound`; `connect garbage` read `none:not-handshake`; `connect silent` read
  `none:timeout`, with its `no name for` log line. After an ordinary lookup of github.com, a
  nameless connection to it read github.com from DNS, and the list said `3 named, 1 from DNS`:
  the resolver's real reply is read under the interface-only rule. The log had `capturing on`
  once and none of the lines the run must not show. The resolvers there were 100.100.100.100,
  then 192.168.1.1, so a router at `fe80::1` was not seen in the app; it rests on
  `testARouterAtLoopbacksLinkLocalAddressNamesAFlowByDNS`. A frame another host sends under
  this Mac's address, a hardware-address change and a move between networks rest on unit
  tests (`testAFrameFromAnotherHostUnderThisMacsAddressIsNotReadAsSent`,
  `testTheFirstFrameFromANewHardwareAddressOpensItsFlow`,
  `testTheNamerFollowsTheInterfacesAddresses`), and a flood on the simulation above.
