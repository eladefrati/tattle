---
title: "ADR-0003: Packet access through a descriptor broker"
status: Accepted
date: 2026-10-20
---

# ADR-0003: Packet access through a descriptor broker

**Status:** Accepted

## Context

The [design](../design.md) (Privileges) gives the sniffer its packets by making
`/dev/bpf*` readable to the user's group through a ChmodBPF-style launch daemon, and the
[PRD](../PRD.md) (Non-goals) rules out a privileged helper because "without a stable signing identity a root helper
cannot verify who is talking to it". Both statements were made against an ad-hoc signed
build.

Readable devices expose the network metadata of every process on the Mac, including
root's daemons, to every process running as the user, for as long as the grant stands.
The grant stands at every boot, whether Tattle runs or not. The data is hostnames,
addresses and DNS answers, since nearly all payloads are encrypted. A process already
running as the user can read far more elsewhere. Still, readable devices hand a new
capability to any such process, and that is the price of the Network tab's names, which
are the tab's core.

Since ADR-0002 the build is signed with a free Apple Development identity, which carries
a team identifier. Checked on 2026-10-20: `codesign --verify` accepts the requirement
`anchor apple generic and certificate leaf[subject.OU] = "<team>"` on the built app and
rejects a wrong team. A root process can therefore verify that its caller is Tattle
without a paid account. Ad-hoc signed builds have no team but do have a code hash that
a requirement can pin.

A paid account would add the Network Extension. A content filter sees every socket
flow in the kernel, browsers and Electron apps included, with the owning process
attributed for free, and can ask for the first outbound bytes of each flow, which are
the TLS ClientHello on TCP and the QUIC Initial on UDP: the same bytes the sniffer
parses. It would replace the sniffer and the broker both, and allow blocking. The
PRD's "no paid account" non-goal is what rules it out, not a technical limit.

## Decision

1. `/dev/bpf*` stays root-only. The BPF daemon installer of build order step 5 becomes a
   descriptor broker, not a ChmodBPF-style daemon. The broker is a small root launch
   daemon. On a request over XPC, it opens one BPF device read-only, binds it to the
   requested interface, returns the descriptor in the reply to that request, and keeps no
   descriptor. launchd holds its Mach service in the system domain, where only root can
   register a name. launchd starts the broker on the first request, and starts it again
   after it exits a minute after it started or after the last request it accepted, whichever
   is later: a refused request, from any account, does not keep it running. The broker is written in C and does no parsing. Between
   requests it holds only the connections it has answered and not yet closed, each until
   the close described in 2.
2. The broker answers a request only when three conditions hold for the process that sent
   it. It never judges the sender from a pid. It judges the sender's code from the
   request's own audit token (`SecCodeCreateWithXPCMessage`). The token names the sending
   process as it was when it sent, and after an exec it names no code at all. The broker
   checks the conditions before it acts on anything in the request, although libxpc
   decodes every message, from any account, before the broker sees it.
   - **The sender runs as the user who installed the broker.** The plist records that
     uid. The broker reads the sender's uid from the connection
     (`xpc_connection_get_euid`). That uid is fixed when the connection is made. The
     broker answers only the first message on a connection and closes the connection on a
     second, so the connection's uid is the uid of the request it answers. Otherwise the
     caller closes it, or the broker does 5 seconds after its answer, the client's own
     deadline. At most 256 answered connections stay open among those whose caller passed
     the checks and 256 among those refused, the oldest of each closed first, so a flood of
     refused connections, which any process can send, closes only refused ones. The
     broker does not close a connection as it answers: a close while the caller waits can
     make the caller drop a reply already delivered and see the connection interrupted.
     Under load on an Apple silicon Mac, closing at once lost 73 answers in 32,000 asks; with
     the caller closing, none in 20,000. On the hosted CI runner it failed 8 of 13 test runs.
   - **The sender's code satisfies the requirement recorded at install time.** With an
     Apple identity, the requirement is the app's team plus its identifier or the dev
     copy's (the same identifier with `.dev` appended, which `make run` builds). Ad hoc,
     it is the code hash of the build's slice that installed it: each slice of a universal
     build has its own. The running code must still match its file.
   - **No other process of that user can steer the sender.** The kernel reports the
     sender valid, running under the hardened runtime, and not debugged. Its code carries
     no get-task-allow and no entitlement that re-enables dyld environment variables or
     unsigned libraries.

   The reply, and with it the descriptor, goes to the request's reply port, which belongs
   to the sender. A forked child inherits no XPC connection.

   Whoever launched the caller has two levers left. It hands the caller its bootstrap
   port, so it can answer for the broker's name itself; that can only keep the caller from
   the real broker, and gets the launcher no descriptor. And it hands the caller its task
   exception ports, which the broker cannot see. A trap would hand the caller's task to
   those ports, and the code it then runs is Tattle, which the broker accepts. The launcher
   can force that trap, as a small inherited stack limit did during Tattle's startup. So
   Tattle drops its own exception ports at launch, in an initializer of its own
   executable, before any of its other code runs, the crash port included. A test runner
   that loads the same code in a bundle keeps its ports. The corpse-notification port
   stays, because macOS's crash reports arrive through it. Whoever holds it receives the
   dead process: no descriptor and no way to run code in it, but all of its memory can be
   read, and that holds the last packets Tattle read and the names it had. A launcher that
   holds the port can choose that moment by killing Tattle. Crash reports are worth that.

   What runs before that initializer, the dynamic loader and the system libraries'
   initializers, still runs with the launcher's ports, and a trap there still hands the
   launcher a task it can run code in. An inherited stack limit was one way to force it:
   at 64 KB and below on Apple silicon, 56 KB and below on Intel, Tattle's startup ran out
   of stack in the dynamic loader. So the app's binary fixes its main thread's stack size
   (`make app`), and the kernel uses that size instead of the inherited limit. Checked on
   2026-11-08 with the dev copy on Apple silicon (macOS 26.7.2) and on Intel (macOS
   26.7.1): under each of 23 inherited stack limits from 8 KB to 1 MB, the launcher received
   nothing. Other traps in the dynamic loader or a system library's initializer stay open.

   Every build of Tattle and of the broker, ad hoc included, is signed with the hardened
   runtime. An ad-hoc build changes its code hash on every rebuild, so it must install the
   broker again. The app says when the installed broker is not this build's.
3. All parsing runs in the app as the user, exactly as it would have with readable
   devices. A parser fault is a user-level crash.
4. Installing and removing the broker goes through the administrator password dialog. The
   Packet access screen shows the exact plist first, as the design already required for
   the daemon; the Startup tab's Remove does not. Before asking, the app explains in plain words what the grant does. The Startup tab
   lists the broker like any other daemon, and removal is one click in Tattle. Tattle
   refuses to install from a build the broker would refuse.

   The script the dialog runs carries everything root needs in its own text: the plist,
   the installing uid, and the code hash and architecture of the running slice. The app
   confirms that hash against the code the kernel loaded, not against the file on disk. The
   architecture is the one the app was compiled for, never read at run time, and only
   `arm64` or `x86_64` reaches the script. The dialog's shell
   gets a fixed environment, not Tattle's.

   Root reads nothing that a process of the user can write without verifying it first.
   The script:
   1. Copies the app bundle into a directory only root can enter.
   2. Refuses the copy if it holds links or special files.
   3. Checks the copy's running slice against the code hash with `codesign --deep -a`.
      That slice's signature pins the seal, `CodeResources`. The other slices of the main
      executable are not checked: root never runs it, and the plist names the running
      slice alone.
   4. Checks every slice of the copy's broker against the code hashes the seal records for
      it. With a team, `--deep` alone is not enough, because it checks nested code only
      against the requirement recorded beside it, and with a team that requirement names no
      hash; with `-a` it also checks only the running slice. Ad hoc, the recorded
      requirement names each slice's hash and nothing else, and is used when it is exactly
      that. Otherwise the one hash the seal records stands, which pins a broker of one slice
      and refuses a universal broker signed by a team.

      Every slice is checked because root runs whichever slice suits the Mac, and one
      matching slice says nothing about another. Checked on 2026-11-15 on the test Mac: two
      files with the same x86_64 slice, one beside its own arm64e slice and one beside
      another program's, each signed ad hoc. Against the first file's requirement, the
      second passed a check of its x86_64 slice and failed a check of every slice.
   5. Stops the old broker and waits for it to exit.
   6. Replaces the broker's files: the helper from the copy, and the plist from the
      script's own text.

   A failed install removes what it put in place.
5. Without the broker the Network tab works from the socket table alone, shows
   addresses instead of names, and says why, unless other software has made `/dev/bpf*`
   readable; the app then opens a device itself.

This supersedes the "no privileged helper" sentence of the design's Privileges
section for this one piece. Everything else there stands: no `sudo`, nothing else runs
as root.

## Consequences

- Through the broker, packets go only to a process that runs as the installing user,
  carries Tattle's signature, and cannot be steered by another process of that user.
  Other accounts on the Mac are refused. This guarantee claims nothing about:
  - root
  - software that makes `/dev/bpf*` readable, such as Wireshark's ChmodBPF
  - with an Apple identity, any process of the installing user on a Mac that holds the
    signing key (below)
  - a launcher that makes Tattle trap before its own initializer runs, in the dynamic
    loader or a system library's initializer
  - an app replaced before the user first opened it, which is the user installing
    someone else's app
- What "Tattle's signature" means depends on how the build is signed. Ad hoc, it means
  this exact build's slice that installed the broker. A universal build run under Rosetta
  runs its other slice, which the broker reads as another build: the Packet access screen
  asks to install again, and the same holds back from Rosetta to native (reasoned from the
  requirement, not run). With an Apple identity, it means any binary the team signed with
  Tattle's identifier or the dev copy's, older builds included. So on a Mac that holds the
  signing key, any process of the user can obtain a descriptor: it signs a hardened program
  of its own with that identity, and the broker accepts it. On the development Mac that
  took no password, because the key's access list names `codesign` (whether by default or
  from an earlier grant is unverified). The team requirement stays: pinning the code hash
  in team mode would cost an administrator dialog on every rebuild. Admitting the dev copy
  widens nothing, because whoever can sign as the team can already sign with Tattle's own
  identifier. It lets a dev copy capture beside a running release build.
- The guarantee covers packets, not what Tattle makes of them. The connection history is an
  unencrypted file in the user's Application Support folder, holding the server names of
  every process on the Mac, root's daemons included, for the retention period (PRD, Privacy
  and retention). Every process of the user can read it, and so can learn from it what the
  broker would refuse it. That is accepted; the history stays unencrypted.
- Install pins the running slice of the exact running build, and through its seal every
  slice of the exact bundled broker, in both signing modes, so swapping the bundle or the
  broker inside it during the dialog, for an altered build or an older signed one, installs
  nothing. A broker with one of its sealed slices beside a foreign one installs nothing
  either. A broker cut down to one of its sealed slices installs: it is the build's own code.
- A universal build signed with a team cannot install the broker: the seal pins only one of
  its broker's slices by hash, and its requirement would admit any slice the team signed,
  run as root. No such build is made: `make app` builds one architecture unless given both, and
  `make release` signs ad hoc.
- Install has root parse the user's bundle (`ditto`, `codesign --verify`) before the
  verdict. The alternative was running its broker unchecked.
- The broker must be installed again when its code or its plist changes, and for another
  account. The Packet access screen says which. A build the broker refuses, such as the
  test runner, cannot use it, so tests call it through a signed fixture, and run the
  broker as an agent in the user's own launchd domain, which takes the same XPC path
  without root.
- `SecCodeCreateWithXPCMessage` is public. The SDK header states no availability for it,
  but the macOS 12.1 through 15.4 SDKs export it, so every release Tattle supports has it.
  The broker is checked on macOS 26 only.
- The broker does not use XPC's own peer requirements, for two reasons. A peer they refuse
  sees only an interrupted connection, which the app could not tell from a crashed broker.
  And their lightweight form cannot say "no get-task-allow".
- Tattle handles no exceptions of its own, so dropping its exception ports loses nothing
  but an inherited handler for resource-limit reports. Crash reports come through the
  corpse-notification port, which Tattle keeps as it inherited it. A launcher that put its
  own port there gets the dead process instead, and macOS writes no report.
- A debugger that launches a debuggable build (`swift build`'s, which carries get-task-allow)
  loses it at the first breakpoint: the launch drop removes the ports the debugger set, and
  the process dies there (signal 11). Attaching to a running build works, since the debugger
  sets its ports after the drop. The dev copy and the release build are hardened without
  get-task-allow, so lldb cannot debug them either way. Instruments' Time Profiler records
  every build, launched or attached. Checked on 2026-11-08 on the test Mac.
- The sniffer code is the same as planned. It receives a descriptor instead of opening
  the file.
- The broker is a second signed artifact to build, install and update. It is small
  enough to review in full, which is the point.
- The Apple Development certificate expires yearly. A renewed one keeps the team, so the
  requirement holds across renewal.
- Blocking, and with it the paid account, remains a Future item (PRD, Network
  Extension) and would be its own ADR.

## Alternatives

- A local socket whose peer is checked through `LOCAL_PEERTOKEN`, as first built.
  Rejected: the token describes whatever program the connecting pid runs when the broker
  asks, not the process that wrote the request, so the identity it checks need not be
  the one that receives the descriptor. Re-reading it later does not help.
- ChmodBPF-style readable devices, as proposed. Same install cost, strictly more
  exposure. Rejected once caller verification turned out to be available for free.
- A root helper that captures and parses, handing names to the app. Puts the parsers in
  a root process for no gain over the broker. Privilege could be dropped after the
  open, which is the broker with extra steps. Rejected.
- Verify the bundled broker on its own: by team requirement in team mode, by a code hash
  read from the bundle ad hoc. Rejected: the team check accepts an older broker the same
  team signed, and the ad-hoc hash comes from the very file being checked.
- Write the broker's code hash into the app at build time. Rejected: the app's own seal
  already records it, and builds without the step could not install.
- Paid account and Network Extension. Would replace the sniffer and the broker with
  one sandboxed extension and allow blocking, at 99 USD a year plus System Settings
  approvals. Ruled out by the PRD's non-goal. It is the one alternative that would
  make this ADR unnecessary if that non-goal is ever dropped.
