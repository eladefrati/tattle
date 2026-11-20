# Tattle

What Tattle is for, who it serves, and how it behaves. How it is built is in
[design.md](design.md).

Status: kept current. It changes only with a decision: an [ADR](adr/) in the same commit, or
the author's instruction.

## Overview

Tattle is a macOS menu bar app that shows what the Mac is doing and explains it in plain
language. It watches network connections, processes, listening ports, and startup items,
and for each answers the same four questions: what is this, who vouches for it, why is it
probably here, and should I care. A later version adds devices on the local network.

It is an explainer, not a firewall and not a system monitor. Little Snitch blocks and, with
its Research Assistant, explains connections from an online database it owns. KnockKnock
lists persistent items and checks them against VirusTotal. Stats and iStat Menus graph
resource use. Tattle is none of these and overlaps with all of them. What it does that they
don't:

- **Offline first.** The app makes no network call of its own. No telemetry, no update
  check, no cloud lookup.
- **Open source.** The knowledge base is data files in the repo; anyone can read, correct,
  or extend them.
- **A pluggable explainer.** When the built-in knowledge runs out, an "explain" button sends
  one item to an LLM the user already has, through a command the user configured, and the
  answer is kept locally so the question is never asked twice.
- **What changed.** First contact with a destination, a new listening port, a new startup
  item: diffs across every surface, which is what a privacy-minded user is actually
  looking for.
- **One place.** The same engine and the same question on every surface, so the user
  installs one app instead of three.

## Goals

- Live view of every connection in either direction, and history within the retention
  period, attributed to the process that holds it, with the hostname the process asked for
  wherever that can be observed.
- Every process, listening port, and persistent startup item on the machine, each with its
  code signer and the app responsible for it.
- A shared explanation pipeline that resolves names deterministically first, from a
  knowledge base second, and from a user-chosen LLM last, on click only.
- "What's new" on every surface.
- Open source from the first commit: license, CI on a clean runner, and the user's data
  kept out of the repo.

## Non-goals

- Blocking of any kind in the first version. Per-app, per-connection control needs a
  Network Extension and a paid Apple Developer account; machine-wide host blocking through
  `pf` resolves names at rule load, goes stale, and does not survive a reboot. See
  "Future".
- Resource history: graphs, temperatures, fans. A live resources line is in scope; iStat's
  job is not.
- Notarized or App Store distribution.
- Any network call the app makes on its own.
- Malware detection. Tattle says what something is; it does not score it.
- Root beyond packet access. The packet-access broker
  ([ADR-0003](adr/0003-bpf-descriptor-broker.md)) is the one piece that runs as root;
  there is no `sudo`.

## Audience

One user on their own Mac: privacy-curious, comfortable reading a hostname, not interested in
maintaining firewall rules. Published on GitHub for people like that.

## Behaviour

Every surface answers the same question with the same engine
([design](design.md#one-engine-one-question)).

The menu bar icon shows live in/out throughput. Clicking opens a panel with a resources
line (CPU, memory, network in/out; GPU has no public per-process source on Apple Silicon,
so it is left out until one exists) and four tabs.

### Network

Sources: [design](design.md#network).

A connection is named from the connection itself first: the TLS Server Name Indication,
the ClientHello inside a QUIC Initial, the HTTP Host header. A name from DNS replies is a
fallback, used only when nothing else named the connection, and marked "from DNS"
([ADR-0001](adr/0001-sniffer-coverage.md)). A server name that is a known relay ingress is
shown as "relayed", and a known Encrypted Client Hello cover name as "name hidden";
neither is shown as the destination.

Packets come through a broker the user installs from Tattle, through the administrator
password dialog, after the app explains what the grant does
([ADR-0003](adr/0003-bpf-descriptor-broker.md)). Without it the tab works from the socket
table alone, shows addresses instead of names, and says why, unless other software such as
Wireshark's ChmodBPF has made the capture devices readable; Tattle then opens one itself.

What the sniffer cannot see, stated plainly in the UI: names hidden by Encrypted Client
Hello (default in Firefox with DNS over HTTPS, in Chrome when Secure DNS returns one), DNS
done over HTTPS by browsers rather than the system resolver, and Safari traffic routed
through iCloud Private Relay. Those flows show the address and are labelled "name hidden"
or "relayed". macOS daemons use the system resolver, so they stay visible. Browser traffic
shows every destination the browser contacted, but not which page caused it: a browser is
one process, so a connection reads "Chrome to doubleclick.net", not "Chrome, nytimes.com
tab, to doubleclick.net". Attributing to a page would need a browser extension; the UI says
so rather than pretending.

Identify: the name and how it was learned, the address, whether it is on this network or the
internet, and the process, its app and their signers. What a host is comes from the
knowledge base.

Views: connections to addresses this Mac has not reached before, listed first; the rest of
the live connections grouped by app.

Actions: explain; reveal the app.

### Processes

What is running right now, which neither Ports nor Startup shows. Sources:
[design](design.md#processes).

Identify: code signer (Apple, a Team ID with its organization name, or unsigned), and the
app a helper belongs to. A built-in glossary covers macOS daemons: `nsurlsessiond`,
`trustd`, `apsd`, `mDNSResponder`, and the rest.

Actions: explain; quit or force-quit; reveal in Finder.

### Ports

Listening TCP and UDP sockets. Sources: [design](design.md#ports).

Identify: process and signer; whether the socket is bound to loopback only or to all
interfaces, which is what decides "reachable from my LAN". Well-known port names.

Actions: explain; quit the owner.

### Startup

Launch agents and daemons, and login items. Sources: [design](design.md#startup). System
items under `/System/Library` are counted on one "Apple" line, not listed.

Identify: program path and arguments, trigger (at login, on a schedule, on demand, watching
a path), loaded or not, running or not with the last exit status when it was not zero, and
signer.

The login-items database needs Full Disk Access. Tattle asks for it once, from the Startup
tab, with a button to the System Settings pane and the reason stated there; there is no
dialog at launch. Without the grant the tab works from the plist folders and `launchctl`
alone, and says what is missing ([ADR-0002](adr/0002-login-items-full-disk-access.md)).
The packet-access broker is listed like any other daemon, and removing it is one click.

System Settings shows two lists of developer names with toggles. This tab shows what each
item runs, when, and why. Control stays where it already works: launch agents can be loaded
and unloaded here, each only as the job launchd loaded from that plist. A plist whose label
another plist's job holds offers no Load and says why, and Unload refuses when launchd's job
of that label did not come from that plist. Daemons need root and are not offered;
database-backed login items are toggled in System Settings via a deep link.

Actions: explain; load/unload; reveal the plist; open System Settings.

### Explanation pipeline

Resolution order for any item:

1. **Facts** the engine already has, such as the signer and the app responsible. Shown
   regardless.
2. **Knowledge base**: rules. The shipped ones are read from the app at launch; a model's
   answers are kept in the database, and nothing else is read from it
   ([ADR-0005](adr/0005-shipped-rules-from-the-app.md)). A rule has a `kind` (host, process, port,
   launch item), a `match` that is either an exact item or a glob pattern
   (`p*-caldav.icloud.com`, `com.apple.*`), `owner`, `purpose` (what the item is), `why`
   (why such an item is probably on a Mac), `care` (the reason the owner should care or not),
   `category`, `risk`, `confidence`, `source`, `identity` (what tells the code the rule was given for from other
   code of that name, empty for a rule about no one program), and `confirmed` (a timestamp,
   null until the user confirms). A rule about a process, a port's listener or a launch item,
   from any source, answers only for its identity (a port-wide rule, `*:udp/5353`, is about
   no one program); a shipped rule about one of Apple's programs answers only for Apple's program
   of that name. Sources in precedence order: `user`, `builtin`, `iap`, `apple-list`, `tracker-radar`,
   `llm`; a confirmed rule ranks with `user` whatever its source. No screen makes a `user`
   rule, and none is read from the database: a rule editor needs a storage decision of its
   own (ADR-0005).
3. **LLM**, on click only. The request carries the item and the facts from step 1 that say
   what it is, so the model explains known facts instead of guessing. Some facts stay out. A
   host's request leaves out the connection's direction and the process that made it,
   because the answer is shown on every connection to that host. A process's request leaves
   out its working directory and, of a title the process set for itself, all but the
   program, which is also the key its answer is kept under; a startup item's gives only
   the number of its arguments and
   leaves out what holds its label, and the account a process runs as reads `you` when it
   is the user's. The model returns
   structured JSON in the shape of a rule. The answer is stored as an **exact-item** rule with `source = llm`, shown as
   "unconfirmed" until the user has read it, judged it against the facts panel, and
   confirmed it. An answer is shown without being stored when nothing would tell a later
   item by its key from this one: code with no identity or whose file cannot be read, and
   a host whose key went out as a placeholder (a private address, or a name only the user's
   network resolves). There is no automatic check; confirmation is the user's. The source stays
   `llm` so provenance is never lost. The schema lets the model propose a pattern, and
   nothing uses it: a kept answer is read only for the exact item (ADR-0005). Unconfirmed
   LLM rules expire after 45 days.

Every detail page answers three questions. **What is this** is the rule's `purpose`. **Why
it is probably here** opens with a sentence the app builds from the facts (who opened the
connection, who started the process, who listens on the port, when macOS runs the startup
item), then the rule's `why`. A rule shown on every connection to a host never says which
program on this Mac opened it; the app's sentence does. **Should I care** opens with words
the app picks from the rule's `risk` (low: "Probably not.", medium: "Worth a look.", high:
"Yes."), left out when the rule has no risk or its confidence is low, then the rule's
`care`. The app picks the words so they never disagree with the risk shown under them. A
model answer without `why` or `care` is kept; that part shows only the app's words.

The seed knowledge base ships in the repo as data files, one per source
([design](design.md#knowledge-base)). Contributions are pull requests against those files.
LLM answers live in `~/Library/Application Support/Tattle/` and never touch the repo. Any
process of the user's can write that file, so nothing in it reads as Tattle's rule or the
user's own; a row written there can still read as a model's answer, confirmed or not
(ADR-0005).

### LLM provider

A shell command template, nothing else. The prompt goes to stdin; the answer is read from
stdout. Presets for `claude -p`, `codex exec`, and `ollama run`, plus a custom field. This
covers hosted and local models with no SDK dependency, and the user pays with an account
they already have. How each preset is run: [design](design.md#llm-presets).

Before anything is sent, the item and its facts are redacted: the user's home path and
username, private and local IP addresses, the Mac's names, Tailscale device names, other
accounts' folders, disk names, email addresses, and a public address a port is bound to are
replaced with placeholders. A path held whole (a program's, a plist's, a watched file's) that lies under
a home folder or on another disk goes out as its root, macOS's own folders at its start and
its last part; any other path goes out whole. A host name only the user's network resolves
(under a private ending such as `.local`, under a search domain, or with no dot) goes out
as a placeholder, whatever its address. A name is replaced only where it can be told
from an ordinary word, so some stay; the README lists which. The default instructions go out as written. Edited
instructions lose the home path in any case, the username, the Mac's names with either
apostrophe, and private or local addresses unless spelled with hyphens; a dotted name such
as `com.username.helper`, other accounts' folders, disk names, Tailscale names and email
addresses stay in them.
The item being explained is the only payload.

Settings shows:

- the provider command;
- the prompt instructions, editable, with reset to default;
- the output contract (the JSON schema), read-only, appended to every request, because
  editing it would silently break the knowledge base;
- the last prompt handed to the command since Tattle started, verbatim, after redaction; it
  is kept in memory only.

Nothing is sent until the user has chosen a provider and clicked explain on an item.

### Privacy and retention

- Connection history is kept in the local database for a configurable period, 30 days by
  default, then pruned. The database is excluded from Spotlight. The user decides whether
  Time Machine backs it up; the default leaves it included.
- Nothing leaves the machine except an explicit LLM request, redacted by Tattle. The command
  can add to it what Tattle cannot remove: Claude Code adds the email address it is signed
  in with.
- The app has no account, no identifier, no crash reporter.

### Distribution

Releases are versioned `YYYY.MM.DD.N` and tagged `v<version>`. Each is one universal build,
for Apple silicon and Intel, made by a GitHub Actions workflow that uploads it and its
checksum to a draft release; publishing the draft makes the tag.

Releases are ad-hoc signed. On current macOS a user opens one by allowing it under System
Settings, Privacy & Security, after the first blocked launch; the README says so. Ad-hoc
signatures do not carry a stable identity, so TCC permissions are asked again after every
new build. A build from source is signed with the first Apple Development identity in the
keychain, so grants survive rebuilds
([ADR-0002](adr/0002-login-items-full-disk-access.md)); without one it is ad hoc. An
ad-hoc build must install the packet-access broker again after each rebuild, and so a
downloaded release after each update; the app says when the installed broker is not this
build's ([ADR-0003](adr/0003-bpf-descriptor-broker.md)). Each release publishes a checksum.
Building from source is a first-class path. A Homebrew cask is possible; the user passes
`--no-quarantine` themselves.

## Future

- **LAN tab.** Devices on the local network: ARP sweep and cache, Bonjour browsing, MAC
  vendor, open ports, new and gone since last scan. Same engine, same question. Runs only
  on request, never in the background, and triggers the macOS Local Network permission
  prompt. Apple devices randomize their Wi-Fi MAC addresses, so the Bonjour name does the
  identifying.
- **Network Extension.** A content-filter system extension would give exact per-flow
  attribution and make per-app allow/block possible. It would not give hostnames: the
  extension's `remoteHostname` is populated only for flows opened through URLSession or
  the Network framework, so browsers and Electron apps still need the DNS map. It needs a
  paid Apple Developer account, Developer ID signing, notarization, and user approval in
  System Settings. The observe layer is the only part that changes.
- **Per-page browser attribution.** The OS knows only that the browser opened a socket;
  which tab caused it is known inside the browser alone. A browser extension using the
  `webRequest` API would report each request's host and tab URL to Tattle over native
  messaging, and Tattle would join that with the socket it saw at the same moment to the
  same host. One extension per browser; Safari's needs Xcode and ideally a developer
  account.
- **More for the Network tab.** Grouping an app's connections by service (forty Akamai hosts
  for one app collapse to "Apple CDN"), from built-in rules only, until a rule editor has
  its storage decision (ADR-0005): a model choosing `*.akamaiedge.net` as "Apple CDN" would
  otherwise mislabel every later match. History per
  app and per destination, and what talked while the screen was locked. A flag on plaintext
  connections. For each host, IP block owner (ASN data), country, domain category and owning
  company (Tracker Radar), Apple's published host list, and the app's own
  `InternetAccessPolicy.plist` on the rare occasions it ships one.
- **More for the Startup tab.** Cron and `periodic` entries, when an item last ran, and the
  installing app, matched by bundle identifier prefix and signer.
- **Patterns from answers.** The user promotes a model's proposed pattern to a glob rule at
  confirmation. Needs a storage decision of its own: a pattern in the database would be any
  process's to write (ADR-0005).
- **Blocking**, if ever, as a decision of its own: `/etc/hosts` for names, the extension
  for apps.
- **Resource history**, if wanted, as a decision of its own.
- Shared knowledge-base contributions: export confirmed local rules as a pull request.

## Open questions

None at the time of writing.
