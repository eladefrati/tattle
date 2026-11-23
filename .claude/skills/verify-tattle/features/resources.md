# Resources line

The line at the top of the panel shows CPU, memory and the network rate, read once a second.
The rate is the bytes moved over the interfaces that carry their own traffic, compared one
interface at a time between two readings.

## Sub-features

- `res-line`: `CPU`, `Memory`, `In` and `Out`, each followed by its value (`5 kB/s`).
- `res-glass`: the readings lie on the glass with no box. Each label sits above
  its 20 pt numeral, `In` and `Out` with a down and an up arrow, and CPU and Memory have a
  meter under it. `In` and `Out` are each as wide as their widest reading, `999.9 MB/s`, and
  sit at the right edge; CPU and Memory share the rest. Memory reads `<used> of <total> GB`,
  or `<used> /<total> GB` when the total is 1,000 GB or more. Hovering CPU shows `All N cores
  together. 100% is every core fully used.` Each reading is one static text to accessibility,
  `Memory, 11.2 of 16 GB`.
- `res-rate`: loopback, tunnels (`utun`, `ipsec`, `gif`, `stf`), bridges and the VM interfaces
  that join them (`bridge`, `vmenet`), VLANs (`vlan`), link aggregates (`bond`) and virtual
  Ethernet pairs (`feth`) are not counted. Every other interface is.

## How to get to it (user POV)

- Click the eye; the line is above the tabs.

## Driving it with tattle-verify

Preconditions:

- Open run; doctor all `ok`. Packet access is not needed.

- **Read.** `$V tab Network`, then repeat `$V ax text | grep -E 'B/s'` once a second. Beside it,
  take two readings of `netstat -ibn` ten seconds apart and divide the difference on each
  interface that counts. The line follows their sum, within a reading's noise.

## Gotchas

- `netstat` is exact and 64-bit. What Tattle can read (`getifaddrs`, and `NET_RT_IFLIST2` too) is
  rounded down to 1 KiB and wraps at 32 bits, so a single reading moves in steps of 1 KiB.
- On an Intel Mac with a T2 chip the link to that chip (`en5` on the test Mac, MTU 16000, ether
  `ac:de:48:00:11:22`) counts: about 3 kB/s each way at rest.
- Proven in the dev copy: the line against `netstat` on the test Mac, run
  `test-mac-2026-11-08/2026-11-08T145520` (twelve readings of 2 to 9 kB/s in and 3 to 9 kB/s out;
  `netstat` over ten seconds gave `en0` 1.4 and 1.0 kB/s and `en5` 3.2 and 3.7 kB/s).
- Not driven in the app: an interface disappearing while the copy runs, which needs a dock or
  adapter to unplug; a VM's interfaces would not show it, since they are not counted.
  `ResourceSampleTests` covers it.
- The glass readings seen 2026-11-16 in the dev copy at `93f6151`, run `2026-11-16T174432`
  (panel.md), and the layout since `3be24b4` (In and Out at the right edge) by the user in the
  dev copy on the development Mac, no run folder. Not driven in the app: In and Out at their
  widest and the `/<total> GB` form, checked only in offscreen renders of the line at set
  readings (no Mac at hand has 1,000 GB); the CPU tooltip, which a scripted pointer did not
  bring up and the user's own pointer did, in the dev copy.
