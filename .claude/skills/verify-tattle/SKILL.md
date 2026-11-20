---
name: verify-tattle
description: Verify Tattle (~/dev/tattle), the macOS menu bar app, in the real running app - launch the dev copy (build/TattleDev.app) from the repo's dev target, or the release build (build/Tattle.app) when the proof needs the build that ships, drive its panel through the accessibility API, and prove behaviour from the panel, the copy's history database and the app's log. Use when a Tattle change needs proof in the app (Network names and unnamed reasons, packet access, Startup, Processes, Ports, Resources, Explain, the panel) instead of asking the user to click through it, and before calling a Tattle change fixed.
---

# Verify Tattle

Tattle is a menu bar app: a status item that drops down a 480-point panel with four tabs
(Network, Processes, Ports, Startup). There is no web or CLI surface; the panel is the
user surface. A run drives one copy, chosen at launch, and every later command acts on
it:

- the **dev copy** (default): `build/TattleDev.app`, bundle id
  `io.github.eladefrati.tattle.dev`, data in `~/Library/Application Support/Tattle Dev/`,
  log subsystem `io.github.eladefrati.tattle.dev`;
- the **release build** (`launch --release`): `build/Tattle.app`, bundle id
  `io.github.eladefrati.tattle`, data in `~/Library/Application Support/Tattle/`, log
  subsystem `io.github.eladefrati.tattle`. Use it when the proof must be on the build that
  ships, such as the broker's install and refusals before a push. A running release build
  is replaced without asking.

Use the dev copy otherwise: it runs beside the release build without stopping it.

## Where it runs

Which machine a run goes on is set in the session's memory, outside this repo.

A proof that needs a signed build runs on the development Mac: the test Mac has no signing identity.

- Bring the test Mac's checkout to the commit under test first (tattle `memory.md`, Machines).
- The accessibility tool needs the test Mac's GUI session, not an ssh one. Put the `$V` commands
  in a script that writes its output to files, start it with
  `ssh <test-mac> 'open -na Ghostty --args -e /bin/zsh <script>'`, and read the files and the
  run folder over ssh.
- The test Mac's display must be awake or the terminal never starts the script: run `caffeinate -di
  -t <seconds>` over ssh, and `caffeinate -u -t 3` to wake it, before `open`. Use ssh for this:
  a background job started through `hc exec` ends with the call.
- Answer a dialog on the test Mac through the accessibility API. `osascript` with System Events from
  a script raises macOS's automation prompt on its screen and then times out.
- Copy the run folder back to this Mac's `build/verify/runs/test-mac-<date>/`.

All commands run from the repo root through one helper:

    V=.claude/skills/verify-tattle/scripts/tattle-verify

It builds its accessibility tool (`scripts/tattle-ax.swift`) into
`build/verify-tools/tattle-ax` on first use. Feature recipes are in
[features/README.md](features/README.md); read the index, then the feature's file.

## Launch

    $V launch            # the dev copy, keeping its existing data
    $V launch --fresh    # moves the copy's data folder into the run folder first; cleanup puts it back
    $V launch --release  # the release build instead, replacing a running one; combines with --fresh

`launch` refuses when the dev copy is already running and no open run started it: another
session may be driving it. Check with the other sessions (ListAgents), then rerun with
`--replace`, which quits it. It refuses while a run is open.

What it does: starts `log stream --level debug` for the copy's subsystem (unnamed reasons
are debug lines, which `log show` cannot read back later), builds and opens the copy (the
dev copy through `make run`, which stops a running dev copy by its exact path; the
release build by stopping it by its exact path, then `make app`, which deletes and
rebuilds the bundle, then `open`), waits for the
sniffer's `capturing on` or `packet capture unavailable` line, then opens the panel and
waits for the Network tab's `N open from M apps` summary. Ready means that
summary, not just a process. It prints the run id, copy, commit, pid and capture line. A build
takes seconds when nothing changed and a minute or two after a source change.

Teardown is `$V cleanup` (below).

## Doctor

    $V doctor

Read-only. Run it after launch and whenever anything looks off. Every line must be `ok`:
Accessibility permission for this terminal (the terminal app the session runs in, such
as iTerm or Ghostty, granted in Privacy & Security on each Mac); exactly one copy of the run's kind; started by the open run;
bundle id; the running code hash equals the bundle on disk; the menu bar item is
reachable; the bundle is newer than every file in `Sources/`, `Resources/` and
`Package.swift` (otherwise relaunch: the app is not the code under test); the database has
its migrations; this run's log has `capturing on`. `info` lines report the commit and
uncommitted paths, whether the packet-access broker is installed, and the pid of any other
copy running, which the run does not drive.

## Drive

The panel is driven through the accessibility API by label, never by screen position.
SwiftUI exposes a row's or button's words as its description and a text's words as its
value; `ax dump` shows both.

    $V tab Network                    # opens the panel, backs out of any detail, picks the tab
    $V ax press "Packet access on"    # exact label
    $V ax press --prefix "Safari,"    # rows read "<name>, <subtitle>, <count>"; match the start
    $V ax press Back                  # the detail's back button
    $V ax wait "Name from" 10         # waits for any label containing the text
    $V ax scroll down                 # long lists only expose rows on screen
    $V ax text                        # every label, one per line
    $V ax dump                        # the tree with roles and [press] marks
    $V ax open | close | status

Stable handles: the tabs `Network`, `Processes`, `Ports`, `Startup`; the buttons
`Settings…`, `Quit Tattle`, `Back`, `Explain`, `Reveal in Finder`; the packet-access
link in the panel's footer on the Network tab (`Packet access on`, `Allow packet access`, `Packet
access off`, or `Packet access: install again`); the Network list's summary, which starts
`N open from M apps`.

To give the Network tab a connection with a known outcome:

    $V connect named      # example.com:80, HTTP request with Host: example.com -> name example.com, source http
    $V connect garbage    # github.com:22, "tattle-verify", no line ending      -> none:not-handshake
    $V connect silent     # github.com:22, connects and sends nothing           -> none:timeout after 20 s

Each opens one TCP connection with `nc`, held 90 s (`--hold <s>` to change), from a local
port it prints with the matching `db` query (`--port <n>` reuses one, with the address
the run last used from it, for a second connection on the same four-tuple; wait 30 s after
the first closes, its TIME_WAIT). The user
approved these hosts and these bytes on 2026-10-25. Do not point it at another host or send other bytes without asking them.

## Evidence

Each run writes to `build/verify/runs/<run-id>/`, which cleanup never deletes:

- `run.txt`: run id, copy, commit (and whether sources were uncommitted), pid, capture
  line. `copy` holds `dev` or `release` for the helper.
- `commands.txt`: every helper command with its time, which ties actions to states.
- `$V save <name>`: `<name>.txt` (labels), `<name>.ax.txt` (tree) and `<name>.png`
  (screenshot of the panel window). The user set the dev copy's item to always show in the
  menu bar (2026-10-25), so the panel opens on screen. If that setting is lost and the
  menu bar is too full, macOS puts the item and its panel off every display; `shot` then
  moves the panel onto the main display for the capture and says so. The `.png` needs
  Screen Recording permission for the terminal app; without it `save` warns and the
  `.txt` and `.ax.txt` files are the evidence.
- `$V db "<sql>"`: read-only query on the run's copy's history database, appended to `db.txt`.
  Tables: `connection` (one row per connection: `proto`, `localPort`, `pid`, `processName`,
  `appName`, `signer`, `appSigner`, `remoteAddress`, `remotePort`, `scope`, `direction`,
  `name`, `nameSource`, `firstSeen`, `ended`), `rule`, `setting`, `grdb_migrations`.
- `log.txt`: the copy's subsystem's log at debug level for the whole run; `$V log "<regex>"`
  greps it.
- `previous-data/` during a `--fresh` run; after cleanup `fresh-data/` holds the run's
  own database.

Proof standards:

- Drive the user's path: the status item, the tabs, the rows and buttons a person
  presses. The database and log are second views of the same event, not a substitute for
  the panel.
- Save the state before and after the action, and cite `commands.txt` times.
- Check the side effect too: a history row, a log line, a file under `/Library`, a
  process gone.
- A journey whose precondition the machine lacks fails and says which precondition; never
  weaken it to pass. Record the reason in the feature's Gotchas.
- `connect` is real traffic on the real network through the real sniffer, not a test
  hook. The panel and history are driven by it exactly as by any app.

## Stop and ask

- **Administrator password.** Installing or removing packet access opens macOS's
  administrator dialog. Press the button, then stop: tell the user the dialog is up and what
  it will do, and wait for them to type the password into the dialog themselves (on the test Mac,
  over Screen Sharing). Never type, script or ask for the password in the terminal.
- **Changes outside the run's copy.** Startup's `Load`, `Unload` and `Remove`, and
  Processes' `Quit` and `Force Quit`, act on the user's real system. Use them only on
  something the run created, or with their yes.
- **Outward traffic** other than `connect`'s approved cases (example.com:80 and github.com:22).

## Cleanup

    $V cleanup

Stops what the run started and only that: the `nc` connections, the run's copy (by the
pid it launched, checked against the copy's executable path) and the log stream. After a
`--fresh` run it moves the run's data folder into `fresh-data/` and puts the previous one
back. It prints the evidence folder and its contents. Run it after every failed attempt
too, before launching again. It never kills by process name and never touches the other
copy or the broker. After a release run the release build stays quit; `open
build/Tattle.app` starts it again.

## Gotchas

- Opening the panel makes the run's copy the active app and takes focus from whatever the user is
  using; a click outside closes the panel, and focus taken without a click leaves it on screen
  ([panel](features/panel.md)). Say so before a long drive if they are at the Mac. Reopen with
  `$V ax open` and check where it is with `$V ax text`.
- The panel keeps its navigation while closed; `$V tab` backs out first.
- In every detail, the answer's row (`Explain`, `Ask again`, `Confirm`, `Forget…`) ignores a
  press sent straight after its buttons change: pause a second first
  ([explain](features/explain.md), Gotchas).
- The sniffer skips local-network destinations (`Sources/tattle/Sniffer/FlowNamer.swift`),
  so a connection to the router or another LAN device never gets a name or a reason.
- A connection is filed under its responsible app: `nc` started by `connect` is filed under
  the terminal app the command ran in (`Herdr Core` for a session on the development Mac,
  `Ghostty` for a script started there), with `nc` in the connection row's subtitle. The
  recipes write that app as `<terminal>`. A process that exits before Tattle reads it shows
  as `pid <n>`.
- Packet access (the broker) is one launch daemon shared by the dev and release copies;
  removing it stops names in every copy running.
- Each copy has its own permission grants. Without Full Disk Access the Startup tab
  shows `Login items need Full Disk Access` instead of the login items.
- A session whose terminal app has no Accessibility permission (Herdr Core on the development
  Mac, seen 2026-11-08) cannot drive the panel: `launch` stops at `this terminal has no
  Accessibility permission`. Put the `$V` commands in a script that writes its output to a
  file and start it with `open -na Ghostty --args -e /bin/zsh <script>`, as on the test Mac.
