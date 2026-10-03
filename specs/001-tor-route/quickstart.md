# Quickstart — Tor Route v1 (Local Profile)

**Audience**: a privacy-conscious user with a Linux desktop, Docker, and
Mullvad Browser already installed. This walkthrough is the SC-001
target: from a clean checkout to a `.onion` page loaded in the browser
in **under 5 minutes**.

**Profile**: `local` (loopback only). LAN and VPS profiles ship later.

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
   current READY result. The default is one 300-second window after Compose
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
Tor observer       READY      internal     authenticated current Tor bootstrap
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

A change to `tokens.yaml` — including removing a label to revoke it — is
**not effective until the data plane acknowledges it**. Check the control
plane's current delivery state (T187):

```bash
scripts/stargate status
```

| Output / exit | Meaning |
|---|---|
| `ACKNOWLEDGED(<generation>)` / 0 | The data plane durably applied exactly this credential set. A removed token is refused for new requests; already-open connections may finish. |
| `PENDING` / 30 | Not acknowledged yet (typically the data plane is down or restarting). The control plane keeps redelivering while it runs; **a revocation is not effective yet**. Stop the route (`$COMPOSE stop stargate-dp`) if access must end now. |
| `STALE_CONFLICT` / 40 | The data plane refused the set because it already holds a newer generation (typically after the control-plane database was lost or restored from an older backup). Nothing was applied and it is not retried. Follow the recovery below. |
| `UNKNOWN` / 50 | This control-plane process has published no delivery state: it started no delivery (`tokens.yaml` missing or invalid, or its state store unavailable), it is still starting, or its status write is failing. The control plane attempts to publish `PENDING` before each delivery starts; UNKNOWN can also occur while a delivery is in flight if status publication fails. Check `tokens.yaml`, restart `stargate-control`, and check again. |
| exit 20 | State unavailable: the control plane is not running or its status could not be read. Nothing is claimed about delivery; the data plane keeps serving its last acknowledged state. |
| exit 70 | Docker did not answer within `STARGATE_STATUS_TIMEOUT` seconds (default 10) on one of the command's calls; the command stops instead of hanging. Nothing is claimed about delivery. Check the Docker daemon, then run the command again. |

The value is one current state kept in the control plane's private
memory-backed `/tmp` (volatile, lost when its container stops); it
records no history, timestamps, labels or counts. The hourly
`enrolled`/`revoked` operational counts likewise include a change only once
this running control plane observes the acknowledgement.

#### Stale-conflict recovery

`STALE_CONFLICT` never renumbers or forces the older set onto the data
plane automatically, because doing so could silently re-authorize revoked
tokens from an old backup (Constitution II; THREAT-MODEL §5.15). Choose one:

1. **Restore the newer control-plane state (preferred).** If you still have
   the `stargate-control-state` volume content that matches the data plane
   (the state before the loss/restore), stop `stargate-control`, put that
   content back (with the matching `stargate-control-config`, and the matching
   `stargate-keys` pepper/IPC keys if those were replaced too), start it
   again, and confirm
   `scripts/stargate status` reports `ACKNOWLEDGED(<generation>)`. Then
   re-apply any intended `tokens.yaml` change and check again.
2. **Deliberately adopt the control plane's current set (explicit
   rollback).** This can re-authorize tokens that the newer data-plane state
   had revoked, so first make sure `tokens.yaml` lists only tokens you want
   valid. Stop both planes (`$COMPOSE stop stargate-control stargate-dp`;
   open connections end), then move the data plane's active snapshot aside
   without editing it:

   ```bash
   # Resolve the volume by Compose label (never a guessed name); PROJECT is the
   # Compose project `init` used (default `stargate`, or your STARGATE_PROJECT).
   PROJECT=${STARGATE_PROJECT:-stargate}
   DP_VOL=$(docker volume ls -q --filter "label=com.docker.compose.project=${PROJECT}" \
     --filter "label=com.docker.compose.volume=stargate-dp-state")
   echo "$DP_VOL"   # must be exactly one volume name; stop here otherwise
   DP_STATE=$(docker volume inspect "$DP_VOL" --format '{{ .Mountpoint }}')
   sudo mv "${DP_STATE}/dp-snapshot.json" "${DP_STATE}/dp-snapshot.json.stale-conflict"
   $COMPOSE start stargate-dp stargate-control
   scripts/stargate status
   ```

   The data plane admits nobody until the control plane reseeds it. Proceed
   only after the status shows `ACKNOWLEDGED(<generation>)` and a removed
   token is actually refused. Keep or securely delete the moved-aside file
   deliberately; it holds verifiers of the newer state.

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
DoH, DoT and HTTP/3 cannot be read by an extension; they are verified outside it at
each Stargate release (THREAT-MODEL §5.4, §5.5) and nothing here checks them.

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

Browse `.onion` sites for a few minutes. The output should be empty
(spec SC-003 requires zero matches). Same display filter as the per-PR
gate (T034 via `gopacket`) and the release-tag Wireshark capture
(T034a), so the three measurement points assert the same property.

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

This stops the stack but leaves all named volumes (and therefore the
Tor entry-guard state, the audit log, and the inter-plane keys + pepper)
intact.

To remove all state, the future `scripts/stargate wipe` subcommand will
be the documented path. In v1 of this feature, project-scoped volume
removal is the operator's responsibility — `$COMPOSE down -v` removes
the nine named volumes Compose created for the `stargate` project (no
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
