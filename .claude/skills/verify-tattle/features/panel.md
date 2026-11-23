# Panel open and closed

Closing the panel keeps its views, so an open detail or a running Explain is still there when
it reopens, and stops their work: Processes and Ports stop reading, and the sampler and the
network readings, which keep running for the menu bar label and the history, stop reaching
the panel. On reopening, the resources line and the Network tab show the latest readings at
once; Processes and Ports show what they last read until their first sweep lands, a fraction
of a second later. Whether the panel is showing follows its window being on screen, not its
key status.

## Sub-features

- `pv-stop`: with the panel closed, a Time Profiler trace has no `PortsObserver.refresh`,
  `ProcessesObserver.refresh`, `ProcessUsageFallback`, `PanelView.body` or `ResourcesLine.body`.
- `pv-reopen`: a connection opened or a port bound while the panel was closed is in the panel
  on reopening.
- `pv-baseline`: the first Processes reading after the list was off screen, from a close or
  another tab, shows CPU as `–`, in the rows and as a `CPU –` row in a detail, so the detail
  keeps its layout. A list sorted by CPU keeps its order. The next reading follows about a
  second later and shows CPU again. A reading more than ten seconds after the previous one,
  as after a real sleep, shows `–` too.
- `pv-detail`: a detail open at the close is still open on reopening.

## How to get to it (user POV)

- Click the eye to open the panel; click the eye again or click outside the panel to close it.

## Driving it with tattle-verify

Preconditions:

- Open run; doctor all `ok`. `pv-reopen`'s connection needs packet access only for its name.

- **Baseline.** `$V tab Processes`, `$V ax wait "apps and programs" 20`, `$V ax press CPU`, wait
  8 s, `$V save before`. `$V ax close`, wait 10 s, `$V ax open`, and read at once: the rows read
  `..., <memory>, –`, in the order they had. About two seconds after opening they carry a
  percentage again. `$V ax text` is slow for this: sample the accessibility tree in a loop to
  see the `–` reading land.
- **Detail.** On Processes, `$V ax press --prefix "macOS,"`, `$V ax close`, wait, `$V ax open`:
  `$V ax text` still has `Back` and the row's name.
- **Network on reopening.** `$V tab Network`, `$V ax close`, `$V connect named --hold 30`, wait 4 s,
  `$V ax open`. The heading's count has risen. The connection is under the terminal's app row
  (`Herdr Core` on the development Mac), as `example.com, <address>:80 · TCP · connected · nc`.
- **Ports on reopening.** `$V tab Ports`, `$V ax close`, `nc -l 49917 &`, wait 7 s, `$V ax open`,
  `$V ax wait 49917 4`. Kill that `nc` by its pid afterwards.
- **Work stops.** Close the panel on Processes, on Ports and on Network, at the tab's root and
  with a detail pushed. For each, `xctrace record
  --template 'Time Profiler' --attach <pid> --time-limit 30s --output t.trace`, export with
  `xctrace export --input t.trace --xpath
  '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]'`, and search the XML for
  the symbols in `pv-stop`: none is there.

## Gotchas

- Proven 2026-11-09. On the development Mac, commit `cfe9a63`: the reopening journeys in run
  `2026-11-09T131240`, and `pv-stop` in six closed traces (Ports and Processes, three runs). On
  the test Mac, commit `a6cf0e0`, runs `2026-11-09T161254` and `2026-11-09T162043`: every path below,
  `pv-stop` closed on a Processes or Ports detail and on Network's root and a detail, the menu
  bar label moving while closed, and an Explain answered while closed or reopened mid-answer
  (one prompt each, the answer shown). On the test Mac, commit `3ff2933`, run `2026-11-09T164024`:
  `pv-baseline` by a timeline of the accessibility tree and a 30-second `pv-stop` trace closed on
  Processes. Copies in this Mac's `build/verify/runs/test-mac-2026-11-09/`.
- Key status does not follow the panel: another app activated without a click (`open -a Finder`)
  or Settings opened over the panel with Command-comma takes key from the panel and leaves it on
  screen, while the window's occlusion state stays visible. A click outside closes it. Escape
  does nothing. Opening and closing through the status item (accessibility press and a real
  click), a click outside, the `Settings...` button and five rapid cycles matched occlusion and
  `tattle-ax status`.
- On the test Mac a real Command-Tab and the administrator dialog, up and cancelled, leave the panel
  on screen and updating. Display sleep with the session locked and a move to a full-screen
  Space take it off screen; it comes back by itself, updating, on wake and on the move back.
- Not driven: a real system sleep (the test Mac's is off) and a swipe between ordinary desktops.
  The ten-second limit rests on `testAReadingLongAfterThePreviousHasNoCPU`.
  Nothing can force a missed occlusion change, so the re-read on attach and on becoming key is
  proven only not to disturb the paths above.
- `PanelVisibilityTests` covers the two read accessors, not the views; the reader and the
  loops' wiring rest on the runs above.
- The first click on the eye while the Settings window is open does not open the panel; the
  next one does. Seen on `main` too.
- What each view says, seen 2026-11-12 on the development Mac in the dev copy, runs
  `2026-11-12T105819` to `2026-11-12T113852` (from `2026-11-12T112604` at `58b901e` or later),
  in the opaque look the panel had then, which is removed, so the runs do not show how a view
  is drawn now: in dark, the Network list, an app's page, a connection's page, the Processes
  list, an app's process page with `Force Quit…` armed, the Ports list, a port's page with and
  without an explanation, the Startup list, a login item's page and Packet access; in light, the
  Processes list and an app's process page; a first contact with no explanation as one line,
  and as `No name seen` when it has no name. On a listener the run started (`nc -l 127.0.0.1
  54999`), with the fake provider behind `sleep 6`: the spinner while asking, the answer with
  `Ask again` and `Confirm`, `Model answer, confirmed by you`, and `No longer listening` with
  the sentence in the past tense once the listener was killed; with `/usr/bin/false` as the
  provider, `The provider failed (exit 1).` under the questions. A `connect named` connection
  read `Closed` on its page once it ended. `Reading processes` showed before the first
  reading. With a file that is not a database in the copy's data folder, the panel is `Tattle
  could not start.` with SQLite's error and `Quit Tattle` (`2026-11-12-failed-start/`). Not
  driven: the lists without packet access or Full Disk Access, and a process, an app's
  connections or a startup item gone under its open page.
- The panel draws on the system's glass: the lists' rows lie on the window and light up under
  the pointer, which also shows their arrow; the tabs are one capsule; the readings have no
  boxes (resources.md); Processes sorts by its column titles (processes.md); the Back button
  is a chevron, labelled `Back`. Seen 2026-11-16 on the development Mac in the dev copy at
  `93f6151`, run `2026-11-16T174432`: the four tabs, Processes sorted by Memory and by CPU,
  the macOS row's page, a port's page and Packet access, in dark, and the same views captured
  in light. Seen again 2026-11-22 on the test Mac (macOS 26.7.1) in the dev copy, once the
  look before macOS 26 was removed: the four tabs, Processes sorted by Memory and by CPU, the
  macOS row's page, Back from it and Packet access, in dark, at `ca1112d` before the removal
  (run `2026-11-22T192204`) and at `d6c5505` after it (run `2026-11-22T192404`). The
  accessibility trees have the same elements, but for one connection that had closed, and the
  screenshots differ only in what the Mac was doing: the readings, a row's figures, and the
  order of the Network and Processes rows; Packet access is the same pixel for pixel. Copies
  in this Mac's `build/verify/runs/test-mac-2026-11-22/`. Not captured again in light.
