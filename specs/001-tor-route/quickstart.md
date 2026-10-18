# Quickstart — Tor Route v1 (Local Profile)

**Audience**: a privacy-conscious user with a Linux x86_64 Local-profile host,
Docker, and Mullvad Browser already installed. The browser may run in a private
local or remote/virtual session, including on the existing VPS. SC-001 measures
a first-time human from **extension installation → token paste → rendered
`.onion` page** in **under 5 minutes** on a fresh browser profile. Record the
complete clean-checkout setup duration separately; it has no five-minute
threshold. An agent-run walkthrough provides functional evidence only.

**Profile**: `local` (loopback only), including when the Local-profile stack
runs on the existing VPS for a private browser measurement. LAN and VPS
deployment profiles ship later.

---

## Prerequisites

- Linux x86_64 with AppArmor, including the Ubuntu kernel's af_unix mediation
  (`/sys/kernel/security/apparmor/features/network/af_unix` reads `yes`), and
  Landlock ABI 4 or newer (upstream Linux 6.7+; the distribution must enable
  Landlock), plus seccomp thread synchronization. `init` refuses a host without
  that file, including mainline kernels, which report af_unix mediation (6.17+)
  elsewhere. Only Ubuntu 24.04 with Linux 6.8 has been measured.
- Docker Engine ≥ 26 and Docker Compose ≥ 2.26.0 (the Compose file mounts a
  volume `subpath`; Compose 2.25 accepts but ignores it). Measured with Engine
  29.1.3 and Compose 2.40.3.
- Mullvad Browser installed (https://mullvad.net/en/browser).
- About 1 GB free disk (Tor image + state + control DB).

You do **not** need a Tor configuration on your host; the Tor binary
runs in a Stargate-managed container.

---

## Step 1 — Clone and build (1 minute)

```bash
git clone https://github.com/zcat-app/stargate.git
cd stargate
./scripts/stargate init
```

`init` establishes the Compose project name **`stargate`** and writes
`compose/env/local.env` (copied from `compose/env/local.env.example`). Every
`docker compose` command below MUST use the same project name + env file, so
`init` and the quickstart share one identity (T088 / B1). Set this shell
variable once and reuse it for every command in this walkthrough:

```bash
COMPOSE="docker compose -p stargate -f compose/docker-compose.local.yml --env-file compose/env/local.env"
```

`init` does the following in order:

1. Preflight checks (`docker`, `docker compose v2`, socket access).
2. Stops any previously running DP, installs its host AppArmor profile and
   IPv4/IPv6 UID-specific firewall rules, and verifies both before starting
   it. This needs host administration rights (`sudo -v` before `init`, or a
   suitable passwordless sudo policy). A failure exits 60 with the DP stopped;
   do not bypass the gate with a direct `docker compose up`. It also exits 60 if
   the kernel lacks AppArmor af_unix mediation or the AppArmor parser would drop
   the profile's Unix-socket denies.
3. Generates the ed25519 inter-plane and observer keys and the bearer-token
   pepper. In the `stargate-keys` volume the private keys are mode 0600, the
   public keys 0644 and the pepper 0640 (group-readable by both planes); the
   observer's private key is 0600 in `stargate-observer-keys`.
4. Brings up the stack via `compose/docker-compose.local.yml`
   (data plane, control plane, Tor sidecar, Tor observer).
5. Confirms the services are running and waits for the observer's authenticated
   cached READY result. Each decision reads a finite Tor bootstrap sample whose
   age must be less than four seconds from the publisher's query start; it does
   not start a new Tor query. The default is one 300-second window after Compose
   startup; `STARGATE_HEALTHCHECK_TIMEOUT` overrides it.
6. Runs a bounded TCP-connect check on `127.0.0.1:8881`.
7. Prints a status table. CP receives only the observer's finite health
   result, which remains advisory for DP admission.

The data plane installs its own kernel network restriction before serving.
`network confinement unavailable` means that the required kernel feature or
deployment setting is unavailable; the proxy exits without admitting requests.
Use a host meeting the prerequisites and rerun `init`. The shipped image is a
static Go build; custom cgo builds are unsupported. Do not disable the restriction.
After successful installation, `$COMPOSE restart stargate-dp` reapplies it on
every start. A firewall flush does not remove it from an existing process;
rerunning `init` also restores the additional owner rules.

Expected output (truncated). Each state is one `init` observed: `RUNNING`
means the container was running, and `READY` is the observer's authenticated
Tor result. The control plane has no network (`network_mode: none`).

```
data plane         RUNNING    127.0.0.1    TCP connect to 127.0.0.1:8881 accepted
control plane      RUNNING    none         container running; gRPC over control.sock
Tor sidecar        RUNNING    internal     container running
Tor observer       READY      internal     authenticated cached Tor health
```

If `init` exits non-zero, see arch §9.1 step 7 for the error-code
table. The most common first-time failure is missing Docker socket
access; the fix is documented in the error message.

---

## Step 2 — Generate and configure a bearer token (1 minute)

Generate the token into a shell variable. Never type or paste the token
itself on a command line: interactive shells save command lines, including
here-document bodies, to history.

```bash
# Only this command line is recorded in history, not the token value.
TOKEN=$(openssl rand -hex 16)
```

Write the token file. The path inside the control-plane container is
`/etc/stargate/tokens.yaml`; on the host it lives in the named volume
`stargate-control-config`, which mounts a directory you can edit
directly:

```bash
# init established the `stargate` project, so the token volume's physical
# name is <project>_<volume> = stargate_stargate-control-config.
VOL_PATH=$(docker volume inspect stargate_stargate-control-config --format '{{ .Mountpoint }}')

# printf is a shell builtin, so the token does not appear in the process
# list; tee's copy of it goes to /dev/null instead of the terminal.
printf 'tokens:\n  - label: my-laptop\n    token: %s\n' "$TOKEN" \
  | sudo tee "${VOL_PATH}/tokens.yaml" > /dev/null

# Show the token once to copy into the extension (Step 4), then drop it.
# To see it again later, read the file: sudo cat "${VOL_PATH}/tokens.yaml"
printf '%s\n' "$TOKEN"   # 32 lowercase hex, e.g. 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f
unset TOKEN

# Re-read the file by restarting the control-plane container (same project
# identity + env file `init` uses — T088):
$COMPOSE restart stargate-control
```

The data plane keeps serving on port 8881 across the control-plane
restart with its previous in-memory token list (in this case, empty —
this is the first token load). After the restart, the new generation is
pushed via gRPC and the data plane accepts requests authenticated with
your token.

### Check token delivery (and revocation)

A change to `tokens.yaml` — including removing a label to revoke it — may be
installed before the CP observes the exact acknowledgment. Check the
control plane's current delivery state (T187/T201):

```bash
scripts/stargate status
```

| Output / exit | Meaning |
|---|---|
| `ACKNOWLEDGED(<generation>)` / 0 | The data plane durably applied exactly this credential set before returning its exact acknowledgment, and the control plane committed the matching local clear. A removed token is refused for new requests; already-open connections may finish. |
| `PENDING` / 30 | Delivery is unresolved. The DP may already have installed the candidate if its acknowledgment was lost. The current CP retries while it remains running; after a CP restart, this state blocks token loading and delivery until explicit offline recovery. It does not prove that a revocation has or has not taken effect. |
| `STALE_CONFLICT` / 40 | The data plane refused the set as stale and the control plane durably recorded that refusal. It blocks token loading and delivery across restarts. Follow the recovery below. |
| `UNKNOWN` / 50 | The delivery marker or status is unavailable, no delivery state has been published, or the process is still starting. An unreadable durable marker blocks token loading; UNKNOWN does not claim a lifecycle. |
| exit 20 | State unavailable: the control plane is not running or its status could not be read. Nothing is claimed about delivery; the data plane continues using its existing valid credential state. |
| exit 70 | Docker did not answer within `STARGATE_STATUS_TIMEOUT` seconds (default 10) on one of the command's calls; the command stops instead of hanging. Nothing is claimed about delivery. Check the Docker daemon, then run the command again. |

The status file is one current value in the control plane's private memory-backed `/tmp`; it is
not authority and records no history, timestamps, labels or counts. The durable delivery gate in
the control-plane SQLite database is separate. The hourly `enrolled`/`revoked` operational counts
include a change only after exact acknowledgment and committed local clear.

#### Stale-conflict recovery

Neither `STALE_CONFLICT` nor restart-inherited `PENDING` automatically sends changed token
content. A stale refusal is durable; if a process exits while delivery is unresolved, the next
process also blocks because the earlier CP may have received a stale refusal before it could
persist that result. A lost acknowledgment may mean the DP already installed the candidate. No
file edit, timeout, reconnect or ordinary restart clears this gate (Constitution II;
THREAT-MODEL §5.15). Choose an explicit offline recovery path:

1. **Restore the newer control-plane state (preferred).** Stop both planes. Restore the
   `stargate-control-state` volume that matches the data plane, with its matching
   `stargate-control-config` and `stargate-keys` pepper/IPC keys if those were replaced. If the
   restored database still contains an unresolved or stale delivery marker, explicitly clear
   only that marker using the procedure below. Start matching peers and wait for the exact
   acknowledgment and verified credential outcomes before treating recovery as complete.
2. **Deliberately adopt the selected control-plane set (explicit rollback).** This can
   re-authorize credentials that the newer data-plane state had revoked. First verify the
   intended `tokens.yaml`, preserve the newer CP/DP state, stop both planes (open connections
   end), and move the active data-plane snapshot aside without editing it:

   ```bash
   # Resolve the volume by Compose label (never a guessed name); PROJECT is the
   # Compose project `init` used (default `stargate`, or your STARGATE_PROJECT).
   PROJECT=${STARGATE_PROJECT:-stargate}
   DP_VOL=$(docker volume ls -q --filter "label=com.docker.compose.project=${PROJECT}" \
     --filter "label=com.docker.compose.volume=stargate-dp-state")
   test "$(printf '%s\n' "$DP_VOL" | sed '/^$/d' | wc -l)" -eq 1 || { echo 'expected exactly one DP state volume' >&2; exit 1; }
   DP_STATE=$(docker volume inspect "$DP_VOL" --format '{{ .Mountpoint }}')
   sudo mv "${DP_STATE}/dp-snapshot.json" "${DP_STATE}/dp-snapshot.json.stale-conflict"
   ```

   Resolve the unique matching `stargate-control-state` volume using the same Compose project
   label and `label=com.docker.compose.volume=stargate-control-state`; identify its existing
   `control.db`. Do not guess volume names or proceed if zero or multiple matches exist. After
   preserving the original database owner and mode, run the
   following bounded host operation as the database owner. It accepts only the fixed existing
   `control.db` path and the literal confirmation operand. Root invocation imports Python's
   SQLite module before entering the state-volume directory, chroots this one process to that
   directory, clears supplementary groups, then drops to the database owner's GID/UID before
   opening the fixed file. A matching nonroot database owner may run it without the identity
   transition. It does not create a missing database or query credentials.

   ```bash
   DB_PATH=/resolved/existing/state-volume/control.db
   timeout 10s python3 - "$DB_PATH" CLEAR-UNRESOLVED-TOKEN-DELIVERY <<'PY'
   import os, sqlite3, stat, sys

   db = os.path.abspath(sys.argv[1])
   if len(sys.argv) != 3 or os.path.basename(db) != "control.db" or sys.argv[2] != "CLEAR-UNRESOLVED-TOKEN-DELIVERY":
       raise SystemExit("refused: fixed path and explicit confirmation required")
   info = os.stat(db, follow_symlinks=False)
   if not stat.S_ISREG(info.st_mode):
       raise SystemExit("refused: control.db must be a regular file")
   owner_uid, owner_gid = info.st_uid, info.st_gid
   root = os.path.dirname(db)
   if os.geteuid() == 0:
       os.chroot(root)
       os.chdir("/")
       os.setgroups([])
       os.setgid(owner_gid)
       os.setuid(owner_uid)
       db = "/control.db"
   else:
       if os.geteuid() != owner_uid:
           raise SystemExit("refused: run as the database owner")
       os.chdir(root)
       db = "control.db"

   con = sqlite3.connect("file:" + db + "?mode=rw", uri=True, timeout=2.0)
   try:
       con.execute("PRAGMA busy_timeout=2000")
       con.execute("PRAGMA synchronous=FULL")
       version = con.execute("SELECT version FROM flyway_schema_history WHERE version='003' AND success=1").fetchone()
       ddl = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='auth_delivery'").fetchone()
       required = ("ID = 1", "STATE IN ('CLEAR','UNRESOLVED','STALE')", "GENERATION >= 0",
                   "STATE = 'CLEAR' AND GENERATION = 0", "STATE IN ('UNRESOLVED','STALE') AND GENERATION > 0")
       normalized_ddl = " ".join(ddl[0].upper().split()) if ddl and ddl[0] else ""
       columns = {row[1] for row in con.execute("PRAGMA table_info(auth_delivery)")}
       rows = con.execute("SELECT id,state,generation FROM auth_delivery").fetchall()
       if not version or not ddl or any(item not in normalized_ddl for item in required) or not {"id", "state", "generation"}.issubset(columns) or len(rows) != 1:
           raise SystemExit("refused: expected T201 V003 singleton schema")
       row_id, state, generation = rows[0]
       if row_id != 1 or state not in ("CLEAR", "UNRESOLVED", "STALE") or not isinstance(generation, int) or generation < 0:
           raise SystemExit("refused: unknown delivery marker")
       if (state == "CLEAR" and generation != 0) or (state != "CLEAR" and generation <= 0):
           raise SystemExit("refused: invalid delivery marker")
       con.execute("BEGIN IMMEDIATE")
       con.execute("UPDATE auth_delivery SET state='CLEAR', generation=0 WHERE id=1")
       con.commit()
   finally:
       con.close()
   print("delivery gate cleared; restart matching peers and verify exact acknowledgment and credential outcomes")
   PY
   ```

   After the explicit clear, start both matching peers and confirm `scripts/stargate status`
   reports `ACKNOWLEDGED(<generation>)`; verify the intended credential outcomes. Moving the
   DP snapshot aside makes the DP deny admission until valid authority is durably installed. A
   lost response can still leave status `PENDING` even after DP installation, so do not treat
   recovery as complete until the exact acknowledgment is observed.
   Keep or securely delete the moved-aside file deliberately; it holds verifiers of the newer
   state.

---

## Step 3 — Create the Stargate browser profile and install the WebExtension (2 minutes)

Stargate uses a **dedicated Mullvad Browser profile** whose own proxy settings fail
closed (T188). Mullvad Browser runs every window in private browsing, and any request
the extension does not route through Tor (because it is not installed, not allowed in
private windows, disabled or still starting) uses the browser's proxy settings. The
template `browser-profile/user.js` sets those to an unreachable SOCKS5 proxy with
proxy-side DNS, bypassed only for ordinary ICANN top-level domains. It also turns
WebRTC off (`media.peerconnection.enabled=false`; THREAT-MODEL §5.3): Mullvad Browser
ships it enabled, and while it is enabled the extension blocks every `.onion` request.
Do not use it in your daily profile.

```bash
# Create the profile with the baseline before its first start:
mkdir -p ~/.stargate-browser-profile
cp browser-profile/user.js ~/.stargate-browser-profile/user.js
mullvad-browser --no-remote --profile ~/.stargate-browser-profile

# Build the deterministic extension zip:
./extension/package.sh
# produces dist/stargate-extension.zip
```

Always start Stargate browsing with that `--profile` command. In that profile:

1. Open `about:debugging#/runtime/this-firefox`.
2. Extract `dist/stargate-extension.zip` to a temporary directory.
3. Click **Load Temporary Add-on** and select the extracted
   `manifest.json`. (Firefox's "Load Temporary Add-on" accepts an
   unpacked `manifest.json` or a signed `.xpi`, not a raw `.zip`.)
4. **Required:** open `about:addons` → **Stargate** → set **Run in Private
   Windows** to **Allow**. A temporary load does not grant it, and without it
   the extension never starts in Mullvad Browser's private windows.
5. **Positive check:** the Stargate icon is in the toolbar (or the extensions
   menu) and clicking it opens the Stargate popup. If the popup does not open, or
   shows `Stargate is not protecting private windows` or a `Warning: the Stargate
   fail-closed proxy baseline …` line, Stargate is not protecting this browser:
   fix step 4 or reinstall `user.js`, then restart the browser.

> **Note**: temporary load is for v1 quickstart only. The signed-add-on
> distribution flow is a later feature. A temporary add-on is removed when the
> browser closes: repeat steps 1–5 after every restart. Until you do, the
> profile baseline keeps `.onion` addresses from loading at all.

**What the baseline does and does not cover** (THREAT-MODEL §4.2, T188):

- With the extension missing, disabled or without private-window access,
  `.onion` addresses in any spelling and names under unknown top-level domains
  fail to load; ordinary clearnet sites load directly, as they do through the
  extension's Direct route.
- Skipping the profile step reverts to whatever proxy settings the browser has:
  `.onion` requests the extension cannot see may then reach a configured proxy.
- A top-level domain delegated after the list in `user.js`, a name with a
  trailing dot (`example.com.`) and non-loopback IP addresses fail to load in this
  profile until a reviewed list update.
- Emptying or changing the SOCKS setting (`network.proxy.socks`) makes names
  that are not bypassed connect directly; the running extension warns when the
  live settings differ from `user.js`, but cannot warn when it is not running.

---

## Tor ingress migration (pre-release T173 repair)

When upgrading to the T173 repair, stop new admission and restart the data
plane with the repaired binary. Restart closes existing old-process tunnels;
there is no certified mixed-version service window. The extension already
selects SOCKS5h and needs no HTTP CONNECT fallback. Third-party clients must
provide the complete bearer plus trustworthy device/profile/initiating-site
`sg1:` partition; a generic `socks5h` URL with a constant username is
insufficient. Clients without that context must stop protected requests.
Do not switch them to Direct. The change requires no credential or snapshot
schema rewrite, route-binding change or Tor configuration migration. Existing
credentials/snapshots remain usable for authenticated SOCKS under their
normal generation rules, but their presence does not authorize HTTP. T173
records the actual stop/restart and Local listener evidence separately. LAN/VPS live
behaviour and post-repair circuit/browser evidence remain open.

## Step 4 — Configure the bearer token in the extension (30 seconds)

Click the Stargate icon → **Options**. Paste the token you generated in
Step 2 into the "Bearer token" field. Click **Save**.

The options page shows this warning:

> Your bearer token will be saved to disk in this extension's
> storage.local, inside your browser profile directory. Any local
> process with read access to that directory can read it. Firefox ESR
> offers no credential-grade alternative for extensions.

The text above is the canonical string pinned in `data-model.md` §5.1;
T056's inline test asserts byte-for-byte equality between
`extension/options/options.html` and that canonical string, so any
drift in either location fails CI. The warning satisfies spec FR-019.

---

## Step 5 — Verify hardening (30 seconds)

The extension audits the one hardening surface it can read at runtime, WebRTC
(arch §14.5), whenever it starts. Mullvad Browser's own default has WebRTC
**enabled**, so a profile without `browser-profile/user.js` fails the audit; the
`user.js` from Step 3 sets `media.peerconnection.enabled=false`, so the audit passes.
The shipped profile sets DoH off (`network.trr.mode=5`) and HTTP/3 off
(`network.http.http3.enable=false`). The extension cannot read DoH, DoT or HTTP/3 settings.
They require a separate check of the exact supported browser/profile at release cadence.
A passing template check alone does not establish that browser result; until its evidence
is recorded, release verification remains pending. Later profile changes require rechecking.

If the audit fails, Stargate blocks every non-Direct route (`.onion` requests do not
load) and:

- shows a brief browser notification (it disappears by itself) naming WebRTC; and
- keeps the blocked state in the Stargate popup, which shows
  `Main navigation decision: Blocked by Stargate` for a `.onion` page.

To recover, set `media.peerconnection.enabled` to `false` in `about:config` (or
reinstall `user.js`) and restart the browser, then re-load the extension (Step 3
steps 1-4). There is no Re-audit button: the audit runs again at each extension
start.

---

## Step 6 — Load a `.onion` site (30 seconds)

In Mullvad Browser, navigate to:

```
https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/
```

The Stargate popup should show **Main navigation decision: Tor**, followed by
**Other requests may use different routes. Connection success is not verified.**
This reports only the latest observed main-navigation request's routing
decision; it does not claim that every request in the tab used Tor or prove a
successful connection or page load. Separately, DuckDuckGo's onion mirror
should render.

If the page does not render:

- If `init` exited 40, leave the containers running and retry after checking
  the host clock and Tor network connectivity. The observer's finite current
  result can be queried with
  `$COMPOSE exec -T tor-observer /opt/stargate/tor-observer --check-ready`:
  exit 0 is READY, 1 is NOT_READY, and 2 is UNAVAILABLE.
- Check that the token in the extension matches the token in `tokens.yaml` (case-sensitive 32-char hex).
- Check whether `init` reached the loopback TCP verification step. A TCP
  connection alone does not prove authenticated SOCKS forwarding.

---

## Verification: privacy properties hold

Optional sanity checks corresponding to the spec's measurable outcomes:

### SC-003 — No DNS leak

In a second terminal, before browsing:

```bash
sudo tshark -i any \
  -Y 'dns.qry.name contains ".onion" || dns.resp.name contains ".onion"'
```

This is an optional spot check, not the SC-003 release measurement. T034a
requires at least 10 minutes of repeated successful page loads of only `.onion`
content in a fresh supported full Mullvad Browser profile, with complete simultaneous
guest-host `lo` and active-egress pcaps, safe pre/post DNS query-and-answer
positive controls, zero drops/truncation and the same canonical filter over
both complete pcaps. The existing VPS Local profile is an allowed venue;
its result covers only those guest interfaces and the recorded browser
build/channel. An Alpha result does not establish stable-browser support or
encrypted-DNS absence; the separate browser hardening proof remains required.

### SC-002 — Stream isolation

Visit two different onion sites in two tabs. Query the Tor control port
from inside the container (cookie-auth required — the contract test
suite at `tests/contract/torrc/` is the documented way; doing it by
hand requires reading the cookie file from the `stargate-tor-state`
volume). Each first-party domain should attach to a distinct circuit.

### SC-004 — Privacy-safe failure

Stop the Tor sidecar:

```bash
$COMPOSE stop tor
```

With the T173 repair, a refresh through the extension's authenticated SOCKS5
route receives a fixed binary `ROUTE_DOWN` reply (`05 03 00 01 00 00 00 00
00 00`) and closes. The browser may show its own connection error; Stargate
does not send an HTML response on Tor port 8881. HTTP proxy clients that begin
with `C` are unsupported and receive zero response bytes, regardless of token.
Use T173's candidate-specific evidence record for measured deployed refusal. Inspect the SOCKS reply and proxy logs for
absence of destination, Tor version and per-request details in the tests.

Restart the sidecar to recover:

```bash
$COMPOSE start tor
```

---

## Teardown

```bash
$COMPOSE down
```

This stops the stack but leaves the named volumes. Persistent Tor entry-guard
state, control-plane state, and inter-plane keys + pepper remain. The Tor health
handoff is volatile tmpfs; its contents are not durable across unmount or host
reboot and are invalidated before Tor starts.

To remove all state, the future `scripts/stargate wipe` subcommand will
be the documented path. In v1 of this feature, project-scoped volume
removal is the operator's responsibility — `$COMPOSE down -v` removes
the ten named volumes Compose created for the `stargate` project (no
literal volume names to keep in sync; the project identity `init`
established does the work):

```bash
$COMPOSE down -v
```

> **Warning**: `down -v` discards Tor's entry-guard set (in
> `stargate-tor-state`), which degrades anonymity if you re-install
> (THREAT-MODEL §4.2). It also removes the inter-plane keys and the
> bearer-token pepper (`stargate-keys`) — a re-install generates fresh
> ones, invalidating any previously configured tokens. Only wipe if you
> intend a fresh installation.
