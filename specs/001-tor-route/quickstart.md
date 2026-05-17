# Quickstart — Tor Route v1 (Local Profile)

**Audience**: a privacy-conscious user with a Linux desktop, Docker, and
Mullvad Browser already installed. This walkthrough is the SC-001
target: from a clean checkout to a `.onion` page loaded in the browser
in **under 5 minutes**.

**Profile**: `local` (loopback only). LAN and VPS profiles ship later.

---

## Prerequisites

- Linux x86_64.
- Docker Engine ≥ 25 with `docker compose v2`.
- Mullvad Browser installed (https://mullvad.net/en/browser).
- About 1 GB free disk (Tor image + state + control DB).

You do **not** need a Tor configuration on your host; the Tor binary
runs in a Stargate-managed container.

---

## Step 1 — Clone and build (1 minute)

```bash
git clone https://github.com/<org>/stargate.git
cd stargate
./scripts/stargate init
```

`init` does the following in order:

1. Preflight checks (`docker`, `docker compose v2`, socket access).
2. Generates ed25519 inter-plane keys, writes them to the
   `stargate-keys` volume with mode 0600.
3. Brings up the stack via `compose/docker-compose.local.yml`
   (data plane, control plane, Tor sidecar).
4. Waits for each container's healthcheck (≤60 s per sidecar).
5. Runs a minimal verification: SOCKS5h handshake on port 8881
   accepts, control plane gRPC handshake succeeds.
6. Prints a status table (see arch §9.1 step 6 for the exact shape).

Expected output (truncated):

```
┌──────────────┬──────────┬────────────┬──────────────────────┐
│ Component    │ Status   │ Bind       │ Notes                │
├──────────────┼──────────┼────────────┼──────────────────────┤
│ Data plane   │ HEALTHY  │ 127.0.0.1  │ port 8881            │
│ Control plane│ HEALTHY  │ 127.0.0.1  │ healthcheck only     │
│ Tor sidecar  │ HEALTHY  │ internal   │ SOCKS5 9050          │
└──────────────┴──────────┴────────────┴──────────────────────┘
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
# Resolve the host-side path:
VOL_PATH=$(docker volume inspect stargate-control-config --format '{{ .Mountpoint }}')

cat <<EOF | sudo tee "${VOL_PATH}/tokens.yaml"
tokens:
  - label: my-laptop
    token: 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f
EOF

# Re-read the file by restarting the control-plane container:
docker compose -f compose/docker-compose.local.yml restart stargate-control
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
2. Click **Load Temporary Add-on**.
3. Select `dist/stargate-extension.zip` (or its inner `manifest.json`).

The extension's icon appears in the toolbar.

> **Note**: temporary load is for v1 quickstart only. The signed-add-on
> distribution flow is a later feature.

---

## Step 4 — Configure the bearer token in the extension (30 seconds)

Click the Stargate icon → **Options**. Paste the token you generated in
Step 2 into the "Bearer token" field. Click **Save**.

The options page shows:

> ⚠️ Bearer token stored in `storage.local`. This is the only storage
> path the WebExtensions API offers; it is protected against access by
> other browser extensions, but any process with filesystem access to
> the browser profile can read it. See SECURITY-DECISIONS.md for
> rationale.

This warning is per spec FR-019.

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

The Stargate popup icon should show **Route: Tor** for this tab.
DuckDuckGo's onion mirror renders.

If the page does not render:

- Check `docker compose -f compose/docker-compose.local.yml logs stargate-tor` for bootstrap failures.
- Check that the token in the extension matches the token in `tokens.yaml` (case-sensitive 32-char hex).
- Verify the data plane's journal for `AUTH_REQUIRED` or `ROUTE_DOWN`
  entries.

---

## Verification: privacy properties hold

Optional sanity checks corresponding to the spec's measurable outcomes:

### SC-003 — No DNS leak

In a second terminal, before browsing:

```bash
sudo tcpdump -i lo -i any 'port 53'
```

Browse `.onion` sites for a few minutes. The capture should be empty.
Any line containing `.onion` is a leak (spec SC-003 requires zero such
packets).

### SC-002 — Stream isolation

Visit two different onion sites in two tabs. Query the Tor control port
from inside the container (cookie-auth required — the contract test
suite at `tests/contract/torrc/` is the documented way; doing it by
hand requires reading the cookie file from the `stargate-tor-state`
volume). Each first-party domain should attach to a distinct circuit.

### SC-004 — Privacy-safe failure

Stop the Tor sidecar:

```bash
docker compose -f compose/docker-compose.local.yml stop stargate-tor
```

Refresh a `.onion` page. The browser shows the privacy-safe error
template body with:

- `X-Stargate-Error: ROUTE_DOWN`
- HTTP 502
- No destination hostname, no exit IP, no Tor version string anywhere
  in the response.

Restart the sidecar to recover:

```bash
docker compose -f compose/docker-compose.local.yml start stargate-tor
```

---

## Teardown

```bash
docker compose -f compose/docker-compose.local.yml down
```

This stops the stack but leaves all named volumes (and therefore the
Tor entry-guard state, the audit log, and the inter-plane keys) intact.

To remove all state, the future `scripts/stargate wipe` subcommand will
be the documented path. In v1 of this feature, manual volume removal is
the operator's responsibility:

```bash
docker volume rm \
  stargate-keys stargate-ipc stargate-control-config \
  stargate-control-state stargate-dp-state stargate-tor-state
```

> ⚠️ Wiping `stargate-tor-state` discards Tor's entry-guard set, which
> degrades anonymity if you re-install (THREAT-MODEL §4.2). Only wipe
> if you intend a fresh installation.
