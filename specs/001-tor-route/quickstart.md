# Quickstart — Tor Route v1 (Local Profile)

**Audience**: a privacy-conscious user with a Linux desktop, Docker, and
Mullvad Browser already installed. This walkthrough is the SC-001
target: from a clean checkout to a `.onion` page loaded in the browser
in **under 5 minutes**.

**Profile**: `local` (loopback only). LAN and VPS profiles ship later.

---

## Prerequisites

- Linux x86_64 with AppArmor and Landlock ABI 4 or newer (upstream Linux 6.7+;
  the distribution must enable Landlock), plus seccomp thread synchronization.
- Docker Engine ≥ 25 with `docker compose v2`.
- Mullvad Browser installed (https://mullvad.net/en/browser).
- About 1 GB free disk (Tor image + state + control DB).

You do **not** need a Tor configuration on your host; the Tor binary
runs in a Stargate-managed container.

---

## Step 1 — Clone and build (1 minute)

```bash
git clone https://github.com/zcatapp/stargate.git
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
   do not bypass the gate with a direct `docker compose up`.
3. Generates ed25519 inter-plane keys, writes them to the
   `stargate-keys` volume with mode 0600.
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

Expected output (truncated):

```
data plane         HEALTHY
control plane      HEALTHY
Tor sidecar        HEALTHY
Tor observer       READY
```

If `init` exits non-zero, see arch §9.1 step 7 for the error-code
table. The most common first-time failure is missing Docker socket
access; the fix is documented in the error message.

---

## Step 2 — Generate and configure a bearer token (1 minute)

Generate the token:

```bash
openssl rand -hex 16
# example output: 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f
```

Write the token file. The path inside the control-plane container is
`/etc/stargate/tokens.yaml`; on the host it lives in the named volume
`stargate-control-config`, which mounts a directory you can edit
directly:

```bash
# init established the `stargate` project, so the token volume's physical
# name is <project>_<volume> = stargate_stargate-control-config.
VOL_PATH=$(docker volume inspect stargate_stargate-control-config --format '{{ .Mountpoint }}')

cat <<EOF | sudo tee "${VOL_PATH}/tokens.yaml"
tokens:
  - label: my-laptop
    token: 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f
EOF

# Re-read the file by restarting the control-plane container (same project
# identity + env file `init` uses — T088):
$COMPOSE restart stargate-control
```

The data plane keeps serving on port 8881 across the control-plane
restart with its previous in-memory token list (in this case, empty —
this is the first token load). After the restart, the new generation is
pushed via gRPC and the data plane accepts requests authenticated with
your token.

---

## Step 3 — Install the Stargate WebExtension (1 minute)

```bash
# Build the deterministic extension zip:
./extension/package.sh
# produces dist/stargate-extension.zip
```

In Mullvad Browser:

1. Open `about:debugging#/runtime/this-firefox`.
2. Extract `dist/stargate-extension.zip` to a temporary directory.
3. Click **Load Temporary Add-on** and select the extracted
   `manifest.json`. (Firefox's "Load Temporary Add-on" accepts an
   unpacked `manifest.json` or a signed `.xpi`, not a raw `.zip`.)

The extension's icon appears in the toolbar.

> **Note**: temporary load is for v1 quickstart only. The signed-add-on
> distribution flow is a later feature.

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

The extension runs the hardening audit (arch §14.5) automatically on
first run. If a check fails, it blocks routing and shows a dialog.
Mullvad Browser's defaults pass every check out of the box, so this
step is usually a no-op.

If the dialog appears, follow its instructions to disable DoH, restrict
WebRTC, and disable HTTP/3, then click **Re-audit**.

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
the seven named volumes Compose created for the `stargate` project (no
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
