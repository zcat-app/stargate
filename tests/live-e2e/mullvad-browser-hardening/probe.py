#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Connection-level Mullvad Browser proof for protected-route fail-closed behavior.

The probe starts independent ordinary-proxy, destination, and SOCKS5 catchers, then
exercises failure and positive-control paths in ephemeral WebDriver profiles. It
writes the complete evidence record selected by ``--report-out``.

Run: python3 tests/live-e2e/mullvad-browser-hardening/probe.py --browser
<mullvadbrowser> --driver <geckodriver> --extension <package.sh zip>
--artifact <browser archive> --report-out <report.json>. Use --only startup or
--only sidecar for the calibrated boundaries, and --mutation for falsification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


PROTECTED_HOST = "abcd2345" * 7 + ".onion"
DIRECT_HOST = "direct.example.com"
TOKEN = "0f1e2d3c" * 4
PROTECTED_PORT = 80
VALID_DEVICE = {"name": "live-control", "bearerToken": TOKEN, "tokenStoredAt": 1}
MALFORMED_DEVICE = {
    "name": "corrupt-storage", "bearerToken": "not-a-token", "tokenStoredAt": 1,
}
MUTATION = "none"


class Captures:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.http: list[dict[str, object]] = []
        self.socks: list[dict[str, object]] = []
        self.destination: list[dict[str, object]] = []

    def append(self, kind: str, item: dict[str, object]) -> None:
        with self.lock:
            item["observedAtMonotonic"] = round(time.monotonic(), 6)
            getattr(self, kind).append(item)

    def reset(self, *kinds: str) -> None:
        with self.lock:
            for kind in kinds:
                getattr(self, kind).clear()

    def snapshot(self, kind: str) -> list[dict[str, object]]:
        with self.lock:
            return list(getattr(self, kind))


CAPTURES = Captures()


def protected_url(path: str) -> str:
    return f"http://{PROTECTED_HOST}:{PROTECTED_PORT}{path}"


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("short socket read")
        data.extend(chunk)
    return bytes(data)


def read_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class HTTPProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        raw = read_headers(self.request)
        if not raw:
            return
        first = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split(" ")
        target = parts[1] if len(parts) >= 2 else ""
        parsed = urllib.parse.urlsplit(target)
        headers = raw.decode("latin-1", "replace").split("\r\n")
        host_header = next(
            (line[5:].strip() for line in headers if line.lower().startswith("host:")),
            "",
        )
        host = (parsed.hostname or host_header.split(":", 1)[0]).lower()
        path = parsed.path or "/"
        CAPTURES.append("http", {"firstLine": first, "host": host, "path": path})

        if host == DIRECT_HOST and path == "/redirect":
            response = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {protected_url('/redirect-target')}\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode()
        elif host == DIRECT_HOST and path in ("/page", "/sidecar-page"):
            if path == "/sidecar-page":
                body = (
                    "<!doctype html><meta charset=utf-8><script>"
                    "window.runSidecarProbe=async()=>{"
                    f"await fetch('http://{DIRECT_HOST}/marker/sidecar-start');"
                    "let outcome;try{"
                    f"await fetch('{protected_url('/sidecar-path')}',{{cache:'no-store'}});"
                    "outcome='fulfilled';}catch(e){outcome='rejected';}"
                    f"await fetch('http://{DIRECT_HOST}/marker/sidecar-done');"
                    "return {completed:true,outcome};};"
                    "</script>"
                ).encode()
            else:
                body = (
                    "<!doctype html><meta charset=utf-8>"
                    f"<img src='{protected_url('/subresource')}' "
                    "onload=mark('subresource-done') onerror=mark('subresource-done')>"
                    "<script>"
                    f"const mark=p=>fetch('http://{DIRECT_HOST}/marker/'+p).catch(()=>{{}});"
                    f"fetch('{protected_url('/retry-one')}').finally(()=>mark('retry-one-done'));"
                    f"setTimeout(()=>fetch('{protected_url('/retry-two')}')"
                    ".finally(()=>mark('retry-two-done')),100);</script>"
                ).encode()
                if MUTATION == "suppress-subrequest":
                    body = b"<!doctype html><p>fixture generation deliberately suppressed</p>"
            response = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                "Cache-Control: no-store\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body
        else:
            body = b"capture-ok"
            response = (
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body
        self.request.sendall(response)


class DestinationHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        raw = read_headers(self.request)
        if not raw:
            return
        first = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split(" ")
        CAPTURES.append("destination", {
            "firstLine": first,
            "path": parts[1] if len(parts) >= 2 else "",
        })
        body = b"destination-catcher"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" +
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        capture: dict[str, object] = {"stage": "accepted"}
        CAPTURES.append("socks", capture)
        self.request.settimeout(5)
        try:
            version, count = read_exact(self.request, 2)
            if version != 5:
                return
            read_exact(self.request, count)
            self.request.sendall(b"\x05\x02")
            if read_exact(self.request, 1) != b"\x01":
                return
            user_len = read_exact(self.request, 1)[0]
            username = read_exact(self.request, user_len).decode("utf-8", "replace")
            password_len = read_exact(self.request, 1)[0]
            password = read_exact(self.request, password_len).decode("utf-8", "replace")
            self.request.sendall(b"\x01\x00")
            version, command, _reserved, address_type = read_exact(self.request, 4)
            if version != 5 or command != 1:
                return
            if address_type == 3:
                host = read_exact(self.request, read_exact(self.request, 1)[0]).decode()
            elif address_type == 1:
                host = socket.inet_ntoa(read_exact(self.request, 4))
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(self.request, 16))
            else:
                return
            port = int.from_bytes(read_exact(self.request, 2), "big")
            capture.update({
                "host": host.lower(), "port": port, "username": username,
                "passwordMatches": password == TOKEN, "stage": "connect",
            })
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            raw = read_headers(self.request)
            first = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            request_path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/"
            capture["path"] = request_path
            capture["stage"] = "request"
            if request_path == "/tor-redirect-start":
                response = (
                    "HTTP/1.1 302 Found\r\n"
                    f"Location: {protected_url('/tor-redirect-target')}\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode()
            elif request_path == "/tor-page":
                body = (
                    "<!doctype html><meta charset=utf-8>"
                    f"<img src='{protected_url('/tor-subresource')}'>"
                    f"<script>fetch('{protected_url('/tor-retry')}').catch(()=>{{}})</script>"
                ).encode()
                response = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body
            else:
                body = b"socks-control-ok"
                response = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    "Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode() + body
            self.request.sendall(response)
        except (EOFError, OSError, TimeoutError):
            return


class DelayedSocksHandler(SocksHandler):
    accepted = threading.Event()
    release = threading.Event()

    def handle(self) -> None:
        self.accepted.set()
        if self.release.wait(timeout=10):
            super().handle()


class Server:
    def __init__(self, handler: type[socketserver.BaseRequestHandler], port: int = 0):
        self.server = ThreadingServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class WebDriver:
    def __init__(self, browser: pathlib.Path, driver: pathlib.Path,
                 extension: pathlib.Path, proxy_port: int, hardened: bool,
                 log_path: pathlib.Path, install_wait: float = 1.0) -> None:
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        self.base = f"http://127.0.0.1:{port}"
        self.session: str | None = None
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_file = log_path.open("ab")
        self.process = subprocess.Popen(
            [str(driver), "--allow-system-access", "--port", str(port)],
            stdout=self.log_file, stderr=subprocess.STDOUT,
        )
        try:
            self.wait_ready()
            prefs = {
                "browser.privatebrowsing.autostart": True,
                "dom.security.https_only_mode": False,
                "dom.security.https_only_mode_pbm": False,
                "extensions.autoDisableScopes": 0,
                "extensions.install.requireBuiltInCerts": False,
                "extensions.webextensions.uuids": json.dumps({
                    "stargate@stargate.local": "stargate-test",
                }),
                "media.peerconnection.enabled": not hardened,
                "network.proxy.allow_hijacking_localhost": True,
                "network.dns.localDomains": PROTECTED_HOST,
                "network.proxy.http": "127.0.0.1",
                "network.proxy.http_port": proxy_port,
                "network.proxy.no_proxies_on": "",
                "network.proxy.ssl": "127.0.0.1",
                "network.proxy.ssl_port": proxy_port,
                "network.proxy.type": 1,
                "xpinstall.signatures.required": False,
            }
            value = self.request("POST", "/session", {"capabilities": {"alwaysMatch": {
                "browserName": "firefox", "acceptInsecureCerts": True,
                "pageLoadStrategy": "none",
                "moz:firefoxOptions": {
                    "binary": str(browser), "args": ["-headless"], "prefs": prefs,
                },
            }}})
            self.session = value.get("sessionId") or value["capabilities"]["sessionId"]
            self.request("POST", f"/session/{self.session}/moz/addon/install", {
                "path": str(extension.resolve()), "temporary": True,
                "allowPrivateBrowsing": True,
            })
            time.sleep(install_wait)
        except Exception:
            self.close()
            raise

    def request(self, method: str, path: str, body: object | None = None):
        request = urllib.request.Request(
            self.base + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method, headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            payload = json.load(error)
            raise RuntimeError(json.dumps(payload, sort_keys=True)) from error
        return payload.get("value", payload)

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if self.request("GET", "/status").get("ready"):
                    return
            except Exception:
                pass
            time.sleep(0.1)
        raise RuntimeError("geckodriver did not become ready")

    def set_context(self, context: str) -> None:
        self.request("POST", f"/session/{self.session}/moz/context", {"context": context})

    def execute(self, script: str, args: list[object] | None = None):
        return self.request("POST", f"/session/{self.session}/execute/sync", {
            "script": script, "args": args or [],
        })

    def execute_async(self, script: str, args: list[object] | None = None):
        return self.request("POST", f"/session/{self.session}/execute/async", {
            "script": script, "args": args or [],
        })

    def set_raw_device(self, device: dict[str, object]) -> None:
        # Bypass only form validation; use the extension's actual storage backend.
        self.navigate("moz-extension://stargate-test/options/options.html", timeout=1)
        self.set_context("content")
        result = self.execute_async(
            "const value=arguments[0],done=arguments[arguments.length-1];"
            "browser.storage.local.set({device:value})"
            ".then(()=>done({ok:true}),e=>done({error:String(e)}));",
            [device],
        )
        if result != {"ok": True}:
            raise RuntimeError(f"could not seed raw extension storage: {result}")

    def read_raw_storage(self) -> dict[str, object]:
        self.set_context("content")
        result = self.execute_async(
            "const done=arguments[arguments.length-1];"
            "browser.storage.local.get(null)"
            ".then(value=>done(value),e=>done({error:String(e)}));"
        )
        return result if isinstance(result, dict) else {"unexpected": result}

    def background_state(self) -> dict[str, object]:
        self.set_context("chrome")
        result = self.execute(
            "const {ExtensionParent}=ChromeUtils.importESModule("
            "'resource://gre/modules/ExtensionParent.sys.mjs');"
            "const extension=ExtensionParent.GlobalManager.extensionMap.get("
            "'stargate@stargate.local');"
            "return {state:extension._backgroundState,"
            "persistent:extension.manifest.background.persistent};"
        )
        return result if isinstance(result, dict) else {"unexpected": result}

    def set_proxy_type(self, value: int) -> None:
        self.set_context("chrome")
        self.execute("Services.prefs.setIntPref('network.proxy.type',arguments[0]);", [value])

    def hardening_pref_state(self) -> dict[str, object]:
        self.set_context("chrome")
        return self.execute(
            "const n='media.peerconnection.enabled';"
            "const t=Services.prefs.getPrefType(n);"
            "let value=null;"
            "if(t===Services.prefs.PREF_BOOL)value=Services.prefs.getBoolPref(n);"
            "else if(t===Services.prefs.PREF_STRING)value=Services.prefs.getStringPref(n);"
            "else if(t===Services.prefs.PREF_INT)value=Services.prefs.getIntPref(n);"
            "return {prefType:t,value};"
        )

    def seed_valid_device(self) -> None:
        self.set_raw_device(VALID_DEVICE)
        time.sleep(0.5)
        if self.read_raw_storage().get("device") != VALID_DEVICE:
            raise RuntimeError("raw valid-device seed did not persist")

    def restart_extension(self) -> None:
        self.navigate("about:blank", timeout=2)
        self.set_context("chrome")
        result = self.execute_async(
            "const done=arguments[arguments.length-1];"
            "const {AddonManager}=ChromeUtils.importESModule('resource://gre/modules/AddonManager.sys.mjs');"
            "AddonManager.getAddonByID('stargate@stargate.local').then(a=>a.reload())"
            ".then(()=>done({reloaded:true}),e=>done({error:String(e)}));"
        )
        if result != {"reloaded": True}:
            raise RuntimeError(f"extension reload failed: {result}")

    def open_control_tab(self) -> None:
        self.set_context("content")
        self.request_handle = self.request("GET", f"/session/{self.session}/window")
        control = self.request("POST", f"/session/{self.session}/window/new", {"type": "tab"})
        self.control_handle = control["handle"]
        self.request("POST", f"/session/{self.session}/window", {"handle": self.control_handle})
        self.navigate("moz-extension://stargate-test/options/options.html")
        self.request("POST", f"/session/{self.session}/window", {"handle": self.request_handle})

    def startup_control(self, operation: str) -> dict[str, object]:
        self.set_context("content")
        self.request("POST", f"/session/{self.session}/window", {"handle": self.control_handle})
        try:
            return self.execute_async(
                "const done=arguments[arguments.length-1];"
                "browser.runtime.sendMessage({type:'t157:startup',operation:arguments[0]})"
                ".then(done,e=>done({error:String(e)}));", [operation]
            )
        finally:
            self.request("POST", f"/session/{self.session}/window", {"handle": self.request_handle})

    def audit_control(self) -> list[dict[str, object]]:
        self.set_context("content")
        self.request("POST", f"/session/{self.session}/window", {"handle": self.control_handle})
        try:
            return self.execute_async(
                "const done=arguments[arguments.length-1];"
                "browser.runtime.sendMessage({type:'t157:audit'}).then(done);"
            )
        finally:
            self.request("POST", f"/session/{self.session}/window", {"handle": self.request_handle})

    def sidecar_fetch(self, load_page: bool = True) -> dict[str, object]:
        if load_page:
            self.navigate(f"http://{DIRECT_HOST}/sidecar-page")
        self.set_context("content")
        return self.execute_async(
            "const done=arguments[arguments.length-1];"
            "window.runSidecarProbe().then(done,e=>done({completed:false,error:String(e)}));"
        )

    def navigate(self, url: str, timeout: float = 15.0) -> dict[str, object]:
        self.set_context("content")
        before = self.request("GET", f"/session/{self.session}/url")
        started = time.monotonic()
        self.request("POST", f"/session/{self.session}/url", {"url": url})
        deadline = started + timeout
        last: dict[str, object] = {"url": before, "documentURI": None, "readyState": None}
        while time.monotonic() < deadline:
            try:
                current = self.request("GET", f"/session/{self.session}/url")
                state = self.execute(
                    "return {documentURI:document.documentURI,readyState:document.readyState};"
                )
                if not isinstance(state, dict):
                    time.sleep(0.1)
                    continue
                last = {
                    "url": current,
                    "documentURI": state["documentURI"],
                    "readyState": state["readyState"],
                }
                if current != before and state["readyState"] == "complete":
                    last.update({
                        "completed": True,
                        "elapsedSeconds": round(time.monotonic() - started, 3),
                    })
                    return last
            except RuntimeError:
                pass
            time.sleep(0.1)
        last.update({
            "completed": False,
            "elapsedSeconds": round(time.monotonic() - started, 3),
        })
        return last

    def blocked_navigation(self, url: str, expected_url: str | None = None) -> dict[str, object]:
        # Browser-owned channel state is independent of the extension's route/UI decision.
        self.set_context("chrome")
        self.execute(
            "const b=gBrowser.selectedBrowser;"
            "const state={events:[],expected:arguments[0],browser:b,started:Date.now()};"
            "const listener={"
            "QueryInterface:ChromeUtils.generateQI(['nsIWebProgressListener',"
            "'nsISupportsWeakReference']),"
            "onStateChange(progress,request,flags,status){"
            "if(!progress.isTopLevel || !request)return;"
            "const url=request.QueryInterface(Ci.nsIChannel).URI.spec;"
            "state.events.push({url,flags,status:status>>>0,"
            "elapsedMs:Date.now()-state.started,"
            "networkStop:!!(flags & Ci.nsIWebProgressListener.STATE_STOP) && "
            "!!(flags & Ci.nsIWebProgressListener.STATE_IS_NETWORK)});"
            "},onLocationChange(){},onProgressChange(){},onStatusChange(){},"
            "onSecurityChange(){},onContentBlockingEvent(){}};"
            "state.listener=listener;window.t157Navigation=state;"
            "b.addProgressListener(listener);", [expected_url or url]
        )
        terminal = self.navigate(url, timeout=3)
        # Never replace/close the tested tab, even if it is still navigating.
        terminal["popupLabel"] = self.blocked_popup_label()
        deadline = time.monotonic() + 15
        while True:
            self.set_context("chrome")
            observed = self.execute(
                "const s=window.t157Navigation;"
                "return {events:s.events,expected:s.expected,"
                "expectedAbortStatus:Cr.NS_ERROR_ABORT>>>0,"
                "testedTabPreserved:gBrowser.browsers.includes(s.browser),"
                "terminal:s.events.find(e=>e.url===s.expected && e.networkStop)||null};"
            )
            if observed["terminal"] is not None or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        terminal["browserProgress"] = observed
        terminal["completed"] = bool(observed["terminal"] and
                                     observed["terminal"]["status"] == observed["expectedAbortStatus"] and
                                     observed["testedTabPreserved"])
        terminal["completionEvidence"] = "browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT"
        self.execute(
            "const s=window.t157Navigation;s.browser.removeProgressListener(s.listener);"
        )
        return terminal

    def blocked_popup_label(self) -> str | None:
        self.set_context("content")
        original = self.request("GET", f"/session/{self.session}/window")
        before = self.request("GET", f"/session/{self.session}/window/handles")
        self.set_context("chrome")
        self.execute(
            "gBrowser.addTab('moz-extension://stargate-test/popup/popup.html',"
            "{triggeringPrincipal:Services.scriptSecurityManager.getSystemPrincipal(),"
            "inBackground:true});"
        )
        # The popup queries the still-active tested tab while loading in the background.
        time.sleep(1)
        self.set_context("content")
        after = self.request("GET", f"/session/{self.session}/window/handles")
        popup = next(handle for handle in after if handle not in before)
        self.request("POST", f"/session/{self.session}/window", {"handle": popup})
        try:
            return self.execute(
                "const e=document.getElementById('route-indicator');"
                "return e ? e.textContent : null;"
            )
        finally:
            self.request("POST", f"/session/{self.session}/window", {"handle": original})

    def close(self) -> None:
        if self.session is not None:
            try:
                self.request("DELETE", f"/session/{self.session}")
            except Exception:
                pass
            self.session = None
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log_file.close()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


STARTUP_SCRIPT = r"""
// Test-only barrier: preserve the real storage value and routing callback.
(() => {
  const state = {events: [], held: false, released: false, storedDevice: null};
  const event = (kind, extra = {}) => state.events.push({
    sequence: state.events.length, kind, ...extra,
  });
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const getDevice = StargateStorage.getDevice;
  StargateStorage.getDevice = async function() {
    const device = await getDevice();
    state.storedDevice = device;
    state.held = true;
    event('initialization-held');
    await gate;
    event('initialization-returned');
    return device;
  };
  const add = browser.proxy.onRequest.addListener.bind(browser.proxy.onRequest);
  browser.proxy.onRequest.addListener = function(listener, ...args) {
    return add(function(details) {
      if (details.url.includes('/startup-held')) {
        event('protected-proxy-request', {
          requestId: details.requestId, held: state.held, released: state.released,
          hardeningOk, type: details.type,
        });
      }
      return listener(details);
    }, ...args);
  };
  browser.runtime.onMessage.addListener(message => {
    if (!message || message.type !== 't157:startup') return undefined;
    if (message.operation === 'release' && !state.released) {
      event('initialization-release');
      state.released = true;
      release();
    }
    return Promise.resolve({...state, hardeningOk});
  });
})();
"""

AUDIT_SCRIPT = r"""
// Observe callback inputs/results without changing either listener's response.
(() => {
  const events = [];
  for (const [name, api] of [['proxy', browser.proxy.onRequest],
                            ['blocker', browser.webRequest.onBeforeRequest]]) {
    const add = api.addListener.bind(api);
    api.addListener = function(listener, ...args) {
      return add(function(details) {
        const result = listener(details);
        if (details.url.includes('/sidecar-path')) {
          const record = {name, requestId:details.requestId, proxyInfo:details.proxyInfo};
          events.push(record);
          Promise.resolve(result).then(value => { record.result = value; });
        }
        return result;
      }, ...args);
    };
  }
  browser.runtime.onMessage.addListener(message => {
    if (message && message.type === 't157:audit') return Promise.resolve(events);
    return undefined;
  });
})();
"""


def variant_extension(source: pathlib.Path, destination: pathlib.Path,
                      variant: str) -> tuple[pathlib.Path, dict[str, object]]:
    """Materialize a deterministic, explicitly scoped test-only package."""
    with zipfile.ZipFile(source) as archive:
        before = {name: archive.read(name) for name in archive.namelist()}
    members = dict(before)
    manifest = json.loads(members["manifest.json"])
    if variant == "startup":
        scripts = manifest["background"]["scripts"]
        scripts.insert(scripts.index("background/router.js"), "background/t157-startup.js")
        members["background/t157-startup.js"] = STARTUP_SCRIPT.encode()
        members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    elif variant == "unknown-hardening":
        manifest["permissions"].remove("privacy")
        members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    else:
        router = members["background/router.js"].decode()
        if variant in ("observe", "terminal-null", "terminal-null-and-blocker"):
            old = "}, null];"
            new = old if variant == "observe" else "}];"
            scripts = manifest["background"]["scripts"]
            scripts.insert(scripts.index("background/router.js"), "background/t157-audit.js")
            members["background/t157-audit.js"] = AUDIT_SCRIPT.encode()
            members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
            if variant == "terminal-null-and-blocker":
                blocker = "async function stargateOnBeforeRequest(details) {"
                if router.count(blocker) != 1:
                    raise RuntimeError("blocking listener mutation anchor differs")
                router = router.replace(blocker, blocker + "\n      return {};\n")
        elif variant == "opaque-context":
            old = "function requestSite(details) {"
            new = old + "\n    if (details.url.includes('/opaque-context')) " + \
                "return {site: 'dns:example.com', document: null};"
        elif variant == "delayed-fallback":
            old = "async function route(details) {"
            new = old + "\n    if (details.url.includes('/delayed-fallback')) " + \
                "return {route: 'direct'};"
            guard = "decision.route === 'direct' && !protectedDestination"
            if router.count(guard) != 1:
                raise RuntimeError("mutation guard anchor differs from candidate")
            router = router.replace(guard, "decision.route === 'direct'")
        elif variant == "delayed-main-navigation":
            old = "commitIndicator(details, record.indicator, 'blocked');\n      return { cancel: true };"
            new = "commitIndicator(details, record.indicator, 'blocked');\n" + \
                "      await new Promise(resolve => setTimeout(resolve, 6000));\n      return {};"
        else:
            raise ValueError(variant)
        if router.count(old) != 1:
            raise RuntimeError(f"mutation anchor differs from candidate: {variant}")
        members["background/router.js"] = router.replace(old, new).encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, members[name])
    changes = {
        name: {"beforeSha256": hashlib.sha256(before[name]).hexdigest() if name in before else None,
               "afterSha256": hashlib.sha256(value).hexdigest()}
        for name, value in members.items() if before.get(name) != value
    }
    return destination, {"variant": variant, "sourceSha256": sha256(source),
                         "packageSha256": sha256(destination), "changedMembers": changes}


def make_unknown_hardening_fault_extension(
    source: pathlib.Path, destination: pathlib.Path
) -> pathlib.Path:
    return variant_extension(source, destination, "unknown-hardening")[0]


def protected_captures() -> list[dict[str, object]]:
    return [x for x in CAPTURES.snapshot("http") if x["host"] == PROTECTED_HOST]


def relevant_http_captures() -> list[dict[str, object]]:
    return [
        x for x in CAPTURES.snapshot("http")
        if x["host"] in (PROTECTED_HOST, DIRECT_HOST)
    ]


def marker_paths() -> set[str]:
    return {
        str(x["path"]) for x in CAPTURES.snapshot("http")
        if x["host"] == DIRECT_HOST and str(x["path"]).startswith("/marker/")
    }


def wait_for_markers(expected: set[str], timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if expected.issubset(marker_paths()):
            return True
        time.sleep(0.1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", type=pathlib.Path, required=True)
    parser.add_argument("--driver", type=pathlib.Path, required=True)
    parser.add_argument("--extension", type=pathlib.Path, required=True)
    parser.add_argument("--artifact", type=pathlib.Path)
    parser.add_argument("--driver-log", type=pathlib.Path,
                        default=pathlib.Path("target/runs/T157.geckodriver.log"))
    parser.add_argument("--report-out", type=pathlib.Path,
                        default=pathlib.Path("target/runs/T157.browser.json"))
    parser.add_argument("--only", choices=("full", "startup", "sidecar", "context", "fixture", "navigation"),
                        default="full")
    parser.add_argument("--mutation", choices=("none", "observe", "terminal-null", "opaque-context",
                        "terminal-null-and-blocker", "suppress-subrequest",
                        "delayed-fallback", "startup-release", "delayed-main-navigation"), default="none")
    args = parser.parse_args()
    for path in (args.browser, args.driver, args.extension):
        if not path.is_file():
            parser.error(f"missing file: {path}")

    report: dict[str, object] = {
        "command": sys.argv,
        "browserVersion": subprocess.check_output(
            [str(args.browser), "--version"], text=True, stderr=subprocess.STDOUT
        ).strip(),
        "driverVersion": subprocess.check_output(
            [str(args.driver), "--version"], text=True
        ).splitlines()[0],
        "extensionSha256": sha256(args.extension),
        "artifactSha256": sha256(args.artifact) if args.artifact else None,
        "scenarios": {},
    }
    global MUTATION
    MUTATION = args.mutation
    if args.mutation in ("observe", "terminal-null", "terminal-null-and-blocker", "opaque-context", "delayed-fallback", "delayed-main-navigation"):
        args.extension, report["mutation"] = variant_extension(
            args.extension, args.report_out.with_suffix(".mutant.zip"), args.mutation
        )
    report["executedExtensionSha256"] = sha256(args.extension)
    report["mutationName"] = args.mutation
    scenarios = report["scenarios"]
    assert isinstance(scenarios, dict)
    failures: list[str] = []
    http_proxy = Server(HTTPProxyHandler)
    destination = Server(DestinationHandler)
    global PROTECTED_PORT
    PROTECTED_PORT = destination.port
    http_proxy.start()
    destination.start()

    def record(name: str, passed: bool, terminal: dict[str, object] | None = None,
               extra: dict[str, object] | None = None) -> None:
        result: dict[str, object] = {
            "passed": passed,
            "httpCaptures": relevant_http_captures(),
            "destinationCaptures": CAPTURES.snapshot("destination"),
            "socksCaptures": CAPTURES.snapshot("socks"),
        }
        if terminal is not None:
            result["terminal"] = terminal
        if extra is not None:
            result.update(extra)
        scenarios[name] = result
        if not passed:
            failures.append(name)

    def record_negative(name: str, terminal: dict[str, object],
                        markers: set[str] | None = None) -> None:
        terminal["observedAtMonotonic"] = round(time.monotonic(), 6)
        markers_ok = True if markers is None else wait_for_markers(markers)
        # This pinned browser's ProxyChannelFilter uses a ten-second default.
        # Watch past that bound after terminal state, including delayed retries.
        time.sleep(11)
        passed = (
            terminal.get("completed") is True and markers_ok and
            ("popupLabel" not in terminal or str(terminal["popupLabel"]).startswith(
                "Main navigation decision: Blocked by Stargate")) and
            not protected_captures() and not CAPTURES.snapshot("destination") and
            not CAPTURES.snapshot("socks")
        )
        record(name, passed, terminal, {
            "requiredMarkers": sorted(markers or set()),
            "markersObserved": sorted(marker_paths()),
        })

    def socks_path(path: str) -> bool:
        return any(x.get("path") == path and x.get("host") == PROTECTED_HOST and
                   x.get("passwordMatches") is True for x in CAPTURES.snapshot("socks"))

    def run_startup() -> None:
        instrumented, identity = variant_extension(
            args.extension, args.report_out.with_suffix(".startup.zip"), "startup"
        )
        server = Server(SocksHandler, 8881)
        server.start()
        browser = WebDriver(args.browser, args.driver, instrumented, http_proxy.port,
                            True, args.driver_log)
        try:
            browser.seed_valid_device()
            browser.restart_extension()
            browser.open_control_tab()
            before = browser.startup_control("state")
            CAPTURES.reset("http", "destination", "socks")
            if args.mutation == "startup-release":
                browser.startup_control("release")
            terminal = browser.navigate(protected_url("/startup-held"), timeout=0.2)
            deadline = time.monotonic() + 5
            observed = browser.startup_control("state")
            while time.monotonic() < deadline and not any(
                e["kind"] == "protected-proxy-request" for e in observed.get("events", [])
            ):
                time.sleep(0.1)
                observed = browser.startup_control("state")
            # The actual proxy callback has begun while the real credential read
            # is held. Keep all three calibrated catchers live until release.
            time.sleep(6)
            pending_captures = {"http": relevant_http_captures(),
                                "destination": CAPTURES.snapshot("destination"),
                                "socks": CAPTURES.snapshot("socks")}
            overlap = any(e["kind"] == "protected-proxy-request" and
                          e.get("held") is True and e.get("released") is False and
                          e.get("hardeningOk") is True for e in observed.get("events", []))
            pending_ok = (before.get("held") is True and before.get("released") is False and
                          before.get("storedDevice") == VALID_DEVICE and overlap and
                          not protected_captures() and not pending_captures["destination"] and
                          not pending_captures["socks"])
            browser.startup_control("release")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not socks_path("/startup-held"):
                time.sleep(0.1)
            after = browser.startup_control("state")
            browser.set_context("content")
            terminal = browser.execute(
                "return {url:location.href,readyState:document.readyState,"
                "completed:document.readyState==='complete'};"
            )
            time.sleep(11)
            record("startup-initialization-overlap", (
                pending_ok and socks_path("/startup-held") and
                terminal.get("completed") is True and
                terminal.get("url") == protected_url("/startup-held") and
                not protected_captures() and not CAPTURES.snapshot("destination")
            ), terminal, {"instrumentation": identity, "before": before,
                          "pending": observed, "pendingCaptures": pending_captures,
                          "after": after, "overlapEstablished": overlap})
        finally:
            browser.close()
            server.stop()

    def run_sidecar() -> None:
        server = Server(SocksHandler, 8881)
        server.start()
        browser = WebDriver(args.browser, args.driver, args.extension, http_proxy.port,
                            True, args.driver_log)
        try:
            browser.seed_valid_device()
            audit = args.mutation in ("observe", "terminal-null", "terminal-null-and-blocker")
            if audit:
                browser.open_control_tab()
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.sidecar_fetch()
            positive = (terminal.get("outcome") == "fulfilled" and
                        socks_path("/sidecar-path") and not protected_captures() and
                        not CAPTURES.snapshot("destination"))
            record("sidecar-identical-path-positive-control", positive, terminal)
            server.stop()
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.sidecar_fetch(load_page=False)
            terminal["completed"] = (positive and terminal.get("completed") is True and
                                     terminal.get("outcome") == "rejected")
            record_negative("sidecar-identical-path-unavailable", terminal, {
                "/marker/sidecar-start", "/marker/sidecar-done",
            })
            scenarios["sidecar-identical-path-unavailable"]["matchingPositivePassed"] = positive
            if audit:
                observations = browser.audit_control()
                scenarios["sidecar-identical-path-unavailable"]["callbackAudit"] = observations
                descriptors = [e.get("result") for e in observations if e["name"] == "proxy"]
                record("live-terminal-chain-contract", bool(descriptors) and all(
                    isinstance(d, list) and len(d) == 2 and d[-1] is None
                    for d in descriptors
                ), extra={"callbackAudit": observations})
        finally:
            browser.close()
            if server.thread.is_alive():
                server.stop()

    def run_context(browser: WebDriver) -> None:
        CAPTURES.reset("http", "destination", "socks")
        extra = (
            f"setTimeout(()=>fetch('{protected_url('/delayed-fallback')}'),1500);"
            if args.mutation == "delayed-fallback" else ""
        )
        data_page = urllib.parse.quote(
            f"<script>{extra}fetch('http://{DIRECT_HOST}/marker/context-start')"
            f".finally(()=>fetch('{protected_url('/opaque-context')}')"
            f".finally(()=>fetch('http://{DIRECT_HOST}/marker/context-done')))</script>"
        )
        terminal = browser.navigate("data:text/html," + data_page)
        record_negative("absent-initiating-context-no-fallback", terminal, {
            "/marker/context-start", "/marker/context-done",
        })

    def finish() -> int:
        report["result"] = "GREEN" if not failures else "RED"
        report["failures"] = failures
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(rendered)
        print(rendered, end="")
        return 0 if not failures else 1

    if args.only != "full":
        try:
            if args.only == "startup":
                run_startup()
            elif args.only == "sidecar":
                run_sidecar()
            else:
                server = Server(SocksHandler, 8881)
                server.start()
                browser = WebDriver(args.browser, args.driver, args.extension, http_proxy.port,
                                    args.only == "context", args.driver_log)
                try:
                    browser.seed_valid_device()
                    if args.only == "context":
                        run_context(browser)
                    elif args.only == "navigation":
                        CAPTURES.reset("http", "destination", "socks")
                        terminal = browser.blocked_navigation(protected_url("/hardening-closed"))
                        record_negative("hardening-failure-no-fallback", terminal)
                    else:
                        CAPTURES.reset("http", "destination", "socks")
                        terminal = browser.navigate(f"http://{DIRECT_HOST}/page")
                        record_negative("subresource-and-retry-no-fallback", terminal, {
                            "/marker/subresource-done", "/marker/retry-one-done",
                            "/marker/retry-two-done",
                        })
                finally:
                    browser.close()
                    server.stop()
        finally:
            http_proxy.stop()
            destination.stop()
        return finish()

    socks = Server(SocksHandler, 8881)
    socks.start()
    try:
        browser = WebDriver(args.browser, args.driver, args.extension,
                            http_proxy.port, True, args.driver_log)
        try:
            browser.seed_valid_device()
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(f"http://{DIRECT_HOST}/control")
            record("direct-positive-control", any(
                x["host"] == DIRECT_HOST and x["path"] == "/control"
                for x in CAPTURES.snapshot("http")
            ) and terminal.get("completed") is True, terminal)

            browser.set_proxy_type(0)
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(
                f"http://127.0.0.1:{destination.port}/destination-control"
            )
            record("destination-positive-control", (
                terminal.get("completed") is True and
                any(x.get("path") == "/destination-control"
                    for x in CAPTURES.snapshot("destination"))
            ), terminal)
            browser.set_proxy_type(1)
        finally:
            browser.close()

        browser = WebDriver(args.browser, args.driver, args.extension,
                            http_proxy.port, False, args.driver_log)
        try:
            browser.seed_valid_device()
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.blocked_navigation(protected_url("/hardening-closed"))
            record_negative("hardening-failure-no-fallback", terminal)

            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(f"http://{DIRECT_HOST}/page")
            record_negative("subresource-and-retry-no-fallback", terminal, {
                "/marker/subresource-done",
                "/marker/retry-one-done",
                "/marker/retry-two-done",
            })

            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.blocked_navigation(
                f"http://{DIRECT_HOST}/redirect", protected_url("/redirect-target")
            )
            record_negative("redirect-no-fallback", terminal)
        finally:
            browser.close()

        browser = WebDriver(args.browser, args.driver, args.extension,
                            http_proxy.port, True, args.driver_log)
        try:
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.blocked_navigation(protected_url("/missing-token"))
            record_negative("missing-token-no-fallback", terminal)

        finally:
            browser.close()

        browser = WebDriver(args.browser, args.driver, args.extension,
                            http_proxy.port, True, args.driver_log)
        try:
            browser.seed_valid_device()
            browser.set_raw_device(MALFORMED_DEVICE)
            time.sleep(0.5)
            stored_state = browser.read_raw_storage()
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.blocked_navigation(protected_url("/malformed-token"))
            terminal["completed"] = (terminal.get("completed") is True and
                                     stored_state.get("device") == MALFORMED_DEVICE)
            record_negative("malformed-token-no-fallback", terminal)
            scenarios["malformed-token-no-fallback"]["storedDevice"] = stored_state.get("device")
        finally:
            browser.close()

        fault_extension = make_unknown_hardening_fault_extension(
            args.extension,
            args.report_out.with_name("T157.unknown-hardening-fault.zip"),
        )
        report["unknownHardeningFaultExtensionSha256"] = sha256(fault_extension)
        browser = WebDriver(args.browser, args.driver, fault_extension,
                            http_proxy.port, True, args.driver_log)
        try:
            browser.seed_valid_device()
            time.sleep(1)
            audit_state = browser.read_raw_storage().get("hardening")
            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.blocked_navigation(protected_url("/unreadable-hardening-api"))
            record_negative("unreadable-hardening-api-no-fallback", terminal)
            scenarios["unreadable-hardening-api-no-fallback"].update({
                "auditRecord": audit_state,
                "faultInjection": "privacy permission removed from otherwise identical package",
            })
        finally:
            browser.close()

        browser = WebDriver(args.browser, args.driver, args.extension,
                            http_proxy.port, True, args.driver_log)
        try:
            browser.seed_valid_device()
            run_context(browser)

            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(protected_url("/tor-positive"))
            socks_captures = CAPTURES.snapshot("socks")
            tor_ok = any(
                x.get("host") == PROTECTED_HOST and x.get("passwordMatches") is True
                for x in socks_captures
            ) and not protected_captures() and terminal.get("completed") is True
            record("tor-positive-control", tor_ok, terminal, {
                "socksCaptures": socks_captures,
            })

            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(protected_url("/tor-page"))
            deadline = time.monotonic() + 10
            wanted = {"/tor-page", "/tor-subresource", "/tor-retry"}
            while time.monotonic() < deadline:
                seen = {str(x.get("path")) for x in CAPTURES.snapshot("socks")}
                if wanted.issubset(seen):
                    break
                time.sleep(0.1)
            socks_captures = CAPTURES.snapshot("socks")
            seen = {str(x.get("path")) for x in socks_captures}
            record("tor-subresource-retry-positive-control", (
                terminal.get("completed") is True and wanted.issubset(seen) and
                all(x.get("passwordMatches") is True for x in socks_captures) and
                not protected_captures()
            ), terminal, {"socksCaptures": socks_captures})

            CAPTURES.reset("http", "destination", "socks")
            terminal = browser.navigate(protected_url("/tor-redirect-start"))
            socks_captures = CAPTURES.snapshot("socks")
            redirect_paths = {str(x.get("path")) for x in socks_captures}
            record("tor-redirect-positive-control", (
                terminal.get("completed") is True and
                {"/tor-redirect-start", "/tor-redirect-target"}.issubset(redirect_paths) and
                not protected_captures()
            ), terminal, {"socksCaptures": socks_captures})

            socks.stop()
            DelayedSocksHandler.accepted.clear()
            DelayedSocksHandler.release.clear()
            socks = Server(DelayedSocksHandler, 8881)
            socks.start()
            CAPTURES.reset("http", "destination", "socks")
            reconnect_result: dict[str, dict[str, object]] = {}
            started_at = time.monotonic()

            def reconnect_navigation() -> None:
                reconnect_result["terminal"] = browser.navigate(
                    protected_url("/sidecar-reconnected")
                )

            reconnect_thread = threading.Thread(target=reconnect_navigation)
            reconnect_thread.start()
            accepted = DelayedSocksHandler.accepted.wait(timeout=10)
            accepted_after = round(time.monotonic() - started_at, 3)
            DelayedSocksHandler.release.set()
            reconnect_thread.join(timeout=20)
            terminal = reconnect_result.get("terminal", {"completed": False})
            socks_captures = CAPTURES.snapshot("socks")
            record("sidecar-reconnect-race-positive-control", (
                accepted and not reconnect_thread.is_alive() and
                terminal.get("completed") is True and
                any(x.get("path") == "/sidecar-reconnected" for x in socks_captures) and
                not protected_captures()
            ), terminal, {
                "socksCaptures": socks_captures,
                "connectionAcceptedBeforeRelease": accepted,
                "acceptedAfterSeconds": accepted_after,
            })
        finally:
            browser.close()
            if socks.thread.is_alive():
                socks.stop()
        run_startup()
        run_sidecar()
    finally:
        if socks.thread.is_alive():
            socks.stop()
        http_proxy.stop()
        destination.stop()

    return finish()


if __name__ == "__main__":
    sys.exit(main())
