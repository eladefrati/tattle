<p align="center">
  <img src="Resources/AppIcon.svg" width="128" height="128" alt="Tattle's icon: an eye">
</p>

<h1 align="center">Tattle</h1>

<p align="center">
  A macOS menu bar app that shows what your Mac is doing and explains it in plain language.
</p>

<p align="center">
  <img src="docs/images/network.png" width="480"
       alt="Tattle's panel on the Network tab: the resources line, the four tabs, three First contact connections each named by its host, and below them the connections seen before, grouped by app with how many go to the internet or this network and who signed it">
</p>

Tattle lists your Mac's network connections, running processes, listening ports and
startup items. For each one it shows who signed it and which app it belongs to and, where
it knows, what it is, why it is probably there and whether you should care.

It is an explainer, not a firewall and not a system monitor. It makes no network calls of
its own: no telemetry, no update check, no cloud lookups. When its built-in knowledge runs
out, **Explain** sends that one item, redacted, to an LLM you already use, through a
command you choose.

**Status:** the four tabs and Explain work. [Download a release](#download) or
[build from source](#build-from-source). What is missing is under
[Not yet built](#not-yet-built).

## What it shows

The eye in the menu bar shows network traffic in and out. Clicking it opens a panel with a
line for CPU, memory and network, and four tabs:

- **Network**: every open connection, grouped by app. A connection is named from the
  connection itself (the TLS server name, the QUIC handshake, the HTTP Host header), with
  DNS replies as a fallback marked "from DNS". A name from the connection is the one the
  program asked for, not proof of who answers at the address. Connections to an address this Mac has not
  reached before are listed first, under **First contact**.
- **Processes**: what is running, each with its code signer (Apple, a developer's Team ID
  and organization, or unsigned) and the app a helper belongs to.
- **Ports**: listening TCP and UDP sockets, who owns each, and whether it is reachable from
  your network or from this Mac only.
- **Startup**: launch agents, launch daemons and login items: what each runs, when, and
  who signed it. macOS's own items are counted on one Apple line.

<p align="center">
  <img src="docs/images/processes.png" width="32%"
       alt="The Processes tab: apps and programs sorted by memory, each with its process count, signer, memory and CPU, with everything that is part of macOS on one row">
  <img src="docs/images/ports.png" width="32%"
       alt="The Ports tab: sockets reachable from your network, each with its port, process, protocol, binding and signer">
  <img src="docs/images/startup.png" width="32%"
       alt="The Startup tab: apps that open at login and items apps registered to run in the background, each with when it runs, whether it is on and who signed it">
</p>

Every item opens to a page of facts and three answers: **What is this**, **Why it is
probably here**, and **Should I care**.

<p align="center">
  <img src="docs/images/process.png" width="360"
       alt="sharingd's page: signed by Apple, what it is, why it is probably here and whether to care, then its path, parent, account, start time and memory">
</p>

Some things the Mac's own traffic does not reveal. A name hidden by Encrypted Client Hello
or sent through iCloud Private Relay is labelled "name hidden" or "relayed", not shown as
the destination, and DNS done over HTTPS inside a browser is out of sight. A browser is one
process, so Tattle shows every host it contacted but not which tab caused it.

## Where the explanations come from

1. **Facts** Tattle reads for itself: the signer, the app responsible, a port's binding, a
   startup item's trigger.
2. **The knowledge base**: rules that ship with the app as JSON files in
   [`Resources/knowledge/`](Resources/knowledge/). It is small for now; corrections and
   additions are pull requests against those files.
3. **Your LLM**, only when you click **Explain** on an item. The answer is stored on your
   Mac as a rule for that item, marked unconfirmed until you click **Confirm**.
   Unconfirmed answers expire after 45 days and are deleted within the hour. **Forget…** deletes a stored answer, confirmed
   or not, and the item can be asked about again. Two kinds of answer are shown without being
   stored, and have no **Confirm**: one about code Tattle cannot tell from other code of
   the same name (unnamed code, or a file it cannot read), and one about a host that went
   out as a placeholder, since a private address or name is another device on another
   network. Asked again where an older unconfirmed answer is stored, such an answer is shown
   in its place while the item is open; the stored one stays until you forget it or it
   expires.

## Install

Tattle needs macOS 26 or later, on Apple silicon or Intel.

### Download

1. From the [latest release](https://github.com/eladefrati/tattle/releases/latest),
   download `Tattle-<version>.zip` and `Tattle-<version>.zip.sha256`.
2. Check the zip. In Terminal, in the folder that holds both files:

       shasum -a 256 -c Tattle-<version>.zip.sha256

   It prints `Tattle-<version>.zip: OK`. If it prints anything else, the zip is not the one
   released: delete it.
3. Open the zip to unzip Tattle, then open it as below.

### Opening a downloaded release

Releases are signed ad hoc, so macOS blocks a downloaded copy's first launch. To open
it:

1. Move Tattle to Applications in the Finder and open it. macOS says it was not opened;
   click Done.
2. Open System Settings, Privacy & Security, and scroll down to Security.
3. Click Open Anyway beside the message about Tattle. The button stays for about an hour
   after the blocked launch.
4. In the alert that follows, click Open Anyway again.
5. Enter an administrator's name and password. Tattle opens.

### Updating

To update, download and check the new release as above, and put it in Applications in place
of the old copy. Each release is signed ad hoc, so to macOS and to the packet-access broker
it is a different build:

- The installed broker recognises the build that installed it by its code hash, so it
  refuses the new one. Open the **Packet access** screen from the link at the bottom of the
  Network tab, click **Install again** and approve the administrator dialog. While Tattle is
  not capturing, the link reads **Packet access: install again**.
- Full Disk Access is lost, though its switch may still show on: the grant belongs to the
  build you replaced. In System Settings, turn Tattle's switch off; macOS might say Tattle
  keeps the access until it is quit and offer **Quit & Reopen** or **Later**: choose **Later**.
  Then quit Tattle, turn the switch on and open Tattle again. If Tattle is not in the list,
  add it as under [Full Disk Access](#full-disk-access).
- Your history and settings, in `~/Library/Application Support/Tattle/`, are kept.

### Build from source

You need Xcode 26 or its command line tools.

    git clone https://github.com/eladefrati/tattle.git
    cd tattle
    make install    # build, bundle and sign Tattle.app, then copy it to /Applications
    open /Applications/Tattle.app

`make app` builds `build/Tattle.app` without installing it.

`make app` signs ad hoc. With an Apple Development identity in your keychain, it signs
with that identity instead, which keeps permission grants and the packet-access broker's
approval across rebuilds. To choose the identity, pass `SIGN_IDENTITY=<name>` to `make`.

## Permissions

### Packet access

Connection names come from the first packets of each connection and, as a fallback, from
the replies to this Mac's DNS queries on port 53; only root may read them. A query is read
only to tell which replies answer one: what is kept of it for that goes when its reply
comes, or after about ten seconds, and none of it is stored. **Allow packet access** in the
Network tab installs the packet-access broker, a small
launch daemon that opens the capture device read-only and hands it to Tattle. The broker
answers only a process that runs as the user who installed it, carries Tattle's signature,
and runs with the hardened runtime. Without it, the Network tab shows addresses instead of
names.

The control is at the bottom of the panel on the Network tab: an orange dot and **Allow
packet access** until it is on, then a green dot and **Packet access on**; clicking it opens
the **Packet access** screen.

You install and remove the broker through the administrator password dialog, and the
**Packet access** screen shows the exact plist first. You can also remove it from the
Startup tab, which does not show the plist.
[ADR-0003](docs/adr/0003-bpf-descriptor-broker.md) gives the design and the reasoning.

<p align="center">
  <img src="docs/images/packet-access.png" width="480"
       alt="The Packet access screen: capturing through the broker, what the broker does, and the launch daemon plist it installed">
</p>

With an Apple Development identity, the broker recognises Tattle by its team and bundle
identifier, so it keeps accepting the release app and the dev copy after a rebuild. The
installed broker itself stays the code of the build that installed it until you install it
again from **Packet access**; when this build's broker differs, that screen says the
installed one is from another build and still serves this one. On a
Mac that holds that identity's signing key, any process you run can therefore obtain a
capture descriptor: it can sign a program of its own with the same identity, and the broker
accepts it. An ad-hoc build is recognised by its code hash, which changes with every
rebuild. After an ad-hoc rebuild, **Packet access** says the installed broker is from
another build and installs it again in one dialog.

Packet access is tested on macOS 26 only.

### Full Disk Access

The Startup tab reads the login-items database, which macOS puts behind Full Disk Access.
Without the grant, the tab lists launchd jobs only and says what is missing. To grant it,
click **Open Full Disk Access Settings** in the Startup tab and turn Tattle on. If Tattle
is not in the list, click **+**, choose Tattle in Applications and turn it on. Nothing
else in the app needs the grant. An ad-hoc build loses it on every rebuild.
[ADR-0002](docs/adr/0002-login-items-full-disk-access.md) explains why.

## Explain

Nothing is sent until you choose a command and click **Explain** on an item.

1. Click **Settings…** in the panel.
2. Under **Explain with**, pick a preset: Claude Code (`claude -p`), Codex (`codex exec`),
   or Ollama (`ollama run llama3.2`). The tool must be installed and signed in.

<p align="center">
  <img src="docs/images/settings.png" width="480"
       alt="Tattle's Settings window: the menu bar and appearance options, the Claude Code preset and its command under Explain with, and the prompt instructions">
</p>

To use another tool, edit **Command** so it reads the prompt on standard input and prints
the answer on standard output; the picker then shows **Custom**. Tattle replaces `{schema}`
in the command with the JSON schema the answer must match. **Output contract** in Settings
shows the schema, and **Last prompt sent** shows the exact text of the last request.

The command runs in your login shell, in an empty temporary folder, and is stopped after
120 seconds or once it has written 4 MB. When it exits, Tattle kills what is left in its
process group; a process that left the group keeps running.

## Privacy

Tattle makes no network call of its own and has no account, identifier or crash reporter.
The one thing that leaves your Mac is the item you click **Explain** on, sent through the
command you configured.

Before sending, Tattle replaces these in the item and its facts with placeholders: your
home path, your username, private and local IP addresses, the Mac's names, Tailscale device
names, other accounts' folders, disk names, email addresses, and a public address a port is
bound to. The default instructions go out as written. Instructions you edit lose your home
path in any case, your username, the Mac's names with either apostrophe, and private or
local addresses unless spelled with hyphens; a dotted name such as `com.username.helper`,
other accounts' folders, disk names, Tailscale names and email addresses stay in them.

Some of an item is not sent at all. A process that gave itself a title, such as
`postgres: appuser payroll_prod db01.corp.example.com(54321) idle`, is sent as the program
alone, `postgres`, and its answer is kept under that name; the panel still shows the title.
A path under your home folder, another account's or another disk is sent without its
folders: `~/Library/CloudStorage/<a cloud drive>/Client/bin/sync` goes out as
`<home>/Library/CloudStorage/<folders>/sync`. Of the folders, only macOS's own at the start
are kept (`Documents`, `Downloads`, `Library/Application Support` and the like). A last part
straight inside a `Users` or a `Volumes` folder at the top of your home or of a disk is an
account's or a disk's name and goes out as a placeholder: `~/Volumes/NAS` as
`<home>/Volumes/<volume>`. A path
anywhere else, such as `/Applications` or `/opt`, is where software is installed and is
sent whole. A host name that only your network resolves is sent as a placeholder, even at
a public address: a name under `.local`, `.lan`, `.internal`, `.home.arpa`, `.home`, `.corp`
or `.localdomain` goes out as `<private-host>` with that ending, and a name under one of
your network's search domains, or with no dot at all, as `<private-host>` alone. A value
longer than 500 characters is cut there.

<details>
<summary>Where a name stays in</summary>

A name is replaced only where Tattle can tell it from an ordinary word, so some stay:

- Your home folder's path matches in any case, at the start of a path or straight after a
  disk's root; your username as a word only as written, so a login `code` leaves the app `Code`
  alone. An exact match that is the item's own name is still replaced.
- Your username stays inside a host name, next to `_` (`username_db`), and in a file named for it
  (`username.py`). In another dotted name it is replaced only as the author's part
  (`com.username.helper`): the label straight after a leading `com`, `org`, `net` or `io`, or
  after that ending in a numbered login item id (`8.com.username.helper`), with another label
  after it that is not a script's extension. So `io.github.username.tool`,
  `dev.username.tool`, `com.username` and `com.username.sh` stay.
- A username of one or two letters is replaced only before an `@`, straight after the program
  in a process title, and as the author's part. In edited instructions it stays.
- The Mac's names are replaced in a host only when the whole host is one of them, so
  `dev.azure.com` stays on a Mac called `dev`, and `dev.lan` reads as a private host, not
  as the Mac, unless `lan` is a search domain. A search domain itself (`corp.example.com`)
  stays; only names under it go. In a startup item they are replaced only as the author's part, and in a process or
  a port they stay. Straight and curly apostrophes count as one; other spellings do not match.
- A process's title is cut to the program only when its name holds a space and does not
  start with `/`. One with no space (`worker:tenant-acme`) goes out whole, and one that
  starts with `/` (`/opt/bin/worker: tenant acme`) from its last `/` on.
- An email address is a name, an `@` and a dotted name whose last part is letters and whose
  first part is not a number, so `python@3.12`, `pkg@1.2.3` and `user@ttys003` stay, and so
  does an address at a bare name (`name@localhost`). Anything of that shape is replaced,
  an address or not: `pkg@latest.tgz` reads `<email>`.
- A `Users` or a `Volumes` folder is read as holding accounts or disks only at the top of
  your home or of a disk, after a folder whose name ends in a space or in punctuation
  other than `.`, `-` and `_`, or after a repeated slash. Anywhere else
  (`~/dev/api/users/server`) it is an ordinary folder, and the last part is sent as it is.
  Where the two readings differ the rule errs toward replacing: a path is read both as it is
  written and as the file system reads it, without its repeated slashes and `.` parts, and
  the last part is replaced whatever it holds, so `~/Users/Shared Stuff` and
  `~/Volumes/(Backup)` go out as placeholders too.
- A path loses its folders only where Tattle holds it whole: a program's, a plist's, a file a
  startup item watches. A path inside other text, such as a reason macOS gave, keeps them.
  There, a disk's name with spaces or punctuation is replaced whole only while the disk is
  mounted, and another account's folder is replaced only at the start of a path or straight
  after a disk's root, and only up to the first space or punctuation a name rarely holds, so
  `/Users/Other User` keeps `User`.

</details>

The command can add what Tattle cannot remove. The Claude Code preset keeps no transcript
of the call and starts none of your account's connectors, but Claude Code adds the email
address it is signed in with to the request.

### Connection history

Tattle records each connection it sees in
`~/Library/Application Support/Tattle/tattle.sqlite`: the process, its app and who signed
them, the address and port at the other end, the name it learned, and when the connection
opened and closed. That covers every process on the Mac, root's included. A row is deleted
30 days after its connection ended; **History** in Settings changes that, from 1 to 365
days. Tattle uses the record to mark an address it has not reached before; no screen lists
it yet.

The file is not encrypted, and every process you run can read it: the names the broker keeps
from them are in it, for as long as the rows last. The same holds for `tattle.sqlite-wal` and
`tattle.sqlite-shm` beside it, where SQLite keeps the latest changes and their index until it
folds them into the file. So `tattle.sqlite` alone is not a complete copy of the history: copy
all three files together, with Tattle quit. Spotlight does not index the folder, and Time
Machine backs it up unless you exclude it.

## Uninstall

1. If you allowed packet access, click **Remove** on the **Packet access** screen. Deleting
   the app leaves the broker's launch daemon in `/Library/LaunchDaemons`. If the app is
   already gone, remove the broker in a terminal:

       sudo launchctl bootout system/io.github.eladefrati.tattle.capture-broker
       sudo rm /Library/LaunchDaemons/io.github.eladefrati.tattle.capture-broker.plist
       sudo rm /Library/PrivilegedHelperTools/io.github.eladefrati.tattle.capture-broker

2. Delete `Tattle.app`.
3. To remove your history, rules, and settings, delete
   `~/Library/Application Support/Tattle/`. Tattle's window positions are in
   `~/Library/Preferences/io.github.eladefrati.tattle.plist`.

## Not yet built

- A mark on a new listening port or a new startup item (only an address reached for the
  first time is marked)
- Any view of the connection history
- When a startup item last ran
- Cron and `periodic` entries in the Startup tab
- A LAN tab
- Per-page browser attribution
- A search bar
- A "started by" filter on processes
- IP block owner data (iptoasn)

The Tracker Radar and Apple hosts knowledge files ship with no rules. Blocking is not
planned; the PRD leaves it to a future decision of its own.

## Development

    make test      # unit tests
    make run       # build and open the dev copy, build/TattleDev.app
    make stop      # quit the dev copy
    make log       # stream both copies' logs

The dev copy is a separate app, "Tattle Dev" (`io.github.eladefrati.tattle.dev`), with its
own data in `~/Library/Application Support/Tattle Dev/` and its own permission grants, so
`make run` never replaces or quits a release build that is running.

The [PRD](docs/PRD.md) says what Tattle does, the [design](docs/design.md) how it is
built, and the [ADRs](docs/adr/) why each decision was made.

## License

MIT, including the knowledge base in `Resources/knowledge/`. Tracker Radar data, once added
to `tracker-radar.json`, stays under its own license (CC BY-NC-SA 4.0) in that file.
