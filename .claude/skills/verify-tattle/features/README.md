# Tattle verification map

The maintained list of Tattle's user-facing features and how to prove each in the run's
copy (the dev copy unless the run was launched with `--release`). Read this index, then
the feature's file.

## Baseline preconditions

- Repo at `~/dev/tattle`; commands run from its root with
  `V=.claude/skills/verify-tattle/scripts/tattle-verify`.
- A run is open: `$V launch` (or `--fresh`) succeeded and `$V doctor` is all `ok`.
- The run's copy (Tattle Dev, `io.github.eladefrati.tattle.dev`, or the release build,
  `io.github.eladefrati.tattle`) was launched by this run.
- The packet-access broker is installed and serves the run's copy (doctor's capture line
  says `through the broker`) for anything about names; otherwise the Network journeys
  fail on that precondition.

## Driving conventions

- Start each recipe with `$V tab <Tab>`, which opens the panel and leaves any detail.
- Press by label (`$V ax press`, `--prefix` for rows); read with `$V ax text`; never
  click by position.
- Rows are `"<name>, <subtitle>, <count>"`; connection rows are
  `"<name>, [from DNS,] [incoming,] [new,] <address:port> · <PROTO> · <state> · <process>, <age>"`.
- Mutations (packet access, Load/Unload, Quit) follow SKILL.md's Stop and ask.

## Proof and skip reporting

- Panel proof: `$V save <name>` before and after the action.
- Data proof: `$V db` for history, `$V log` for the subsystem's lines.
- Cite the run folder `build/verify/runs/<run-id>/` and the `commands.txt` times.
- Report an unreached entry point with the command tried and the unmet precondition;
  never report it as verified through another path.

## Feature entry contract

Each file: an H1 and a paragraph on the user-visible behaviour, then `Sub-features`, `How
to get to it (user POV)`, `Driving it with tattle-verify` (starting with
`Preconditions:`), `Gotchas`.

## Features

- [Network names and unnamed reasons](./network-names.md): who each connection goes to, or
  why Tattle could not tell, and who signed the process and its app. Proven 2026-10-25; a
  connection's own signer, rows with differing signers, a file put in a bundle and a process
  that replaces itself, incoming connections and a Tailscale peer's reach 2026-11-08; an
  owner and its app read with the socket table and a process's own name for itself 2026-11-09;
  the history database written ahead and a name found by its flow, and DNS replies bounded,
  2026-11-10; an Apple-signed file outside macOS 2026-11-15; a name as the program's word
  and a DNS reply matched to its query 2026-11-19.
- [Packet access](./packet-access.md): installing and removing the broker that gives the
  sniffer packets; the password step is the user's. Remove and Install proven 2026-10-25 on
  both copies, Remove from Startup and the refused callers on the release build; a
  launcher's crash port, the drop at launch and the fixed stack 2026-11-08; Install and
  Remove on an ad-hoc release, and a locked file in the bundle, 2026-11-15; the downloaded
  release installed by hand and its broker installed 2026-11-16.
- [Resources line](./resources.md): CPU, memory and the network rate above the tabs, and
  which interfaces the rate counts. Proven 2026-11-08.
- [Startup items](./startup.md): what starts at login and boot, grouped, with details.
  Proven 2026-10-25; a command line's signer 2026-11-07; Apple's developer tools, copies
  of them, `open`'s long options, xcrun, registered items and launch items running Apple's
  programs, a loaded job's state, plists that cannot be read and a daemon's controls
  2026-11-08; an item gone under its open detail 2026-11-10; arch, a long wrapper chain, a
  label with a space and an agent's PATH 2026-11-15; two agents sharing a label, its job
  given only to the plist it was loaded from, and Unload's check of that plist 2026-11-16.
- [Processes](./processes.md): running apps and programs with their helpers, memory and
  CPU, and Quit. Proven 2026-10-25; the macOS row, a script started by launchd, standard
  input under launchd, Python (with the Command Line Tools, with Xcode, and a Tk window),
  Swift (its frontend and its tools) and a package by its folder 2026-11-07; a compile job,
  with the Command Line Tools and with Xcode, a copy of clang, an app among Xcode's
  developer tools, a developer tool reading standard input, an Apple-signed Xcode, Quit on
  an app with a helper and another account's process 2026-11-08; an Apple binary moved over a
  running program, Safari from its cryptex, a file put in a copy of one of Apple's apps and
  an app's files changed while it runs 2026-11-15.
- [Ports](./ports.md): what is listening, read by the code it runs. A script listening, its
  answer kept, and another account's listener proven 2026-11-08.
- [Explain](./explain.md): the explanation at the end of every detail, the Apple gate on
  shipped rules, and what the prompt sends, through a local fake provider. Proven
  2026-10-27; an answer going with its code and one version of it, the shipped `claude` rule
  a host's prompt, a command that holds none of Tattle's grants and the Claude Code preset
  2026-11-08; rows another process wrote into the rule table, for processes and ports, and a
  command that leaves its process group, 2026-11-15.
- [Panel open and closed](./panel.md): closing the panel keeps its views and stops their
  work, and what reopening shows. Proven 2026-11-09; the glass look seen 2026-11-16 and
  2026-11-22.
- [App icon and menu bar glyph](./icon.md): the bundle's icon and the menu bar eye, running
  and after a failed start. Proven 2026-11-12 on the test Mac.
