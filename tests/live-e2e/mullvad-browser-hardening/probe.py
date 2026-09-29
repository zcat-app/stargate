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
import os
import pathlib
import re
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
        # T186: impostor listeners standing at a fail-closed descriptor's target.
        self.impostor: list[dict[str, object]] = []

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
        host = next((line[5:].strip() for line in
                     raw.decode("latin-1", "replace").split("\r\n")
                     if line.lower().startswith("host:")), "")
        CAPTURES.append("destination", {
            "firstLine": first,
            "host": host.lower(),
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
                 log_path: pathlib.Path, install_wait: float = 1.0,
                 extra_prefs: dict[str, object] | None = None,
                 accept_insecure_certs: bool = True,
                 trace: "NameTrace | None" = None) -> None:
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        self.base = f"http://127.0.0.1:{port}"
        self.session: str | None = None
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_file = log_path.open("ab")
        command = [str(driver), "--allow-system-access", "--port", str(port)]
        env = None
        if trace is not None:
            command, env = trace.wrap(command)
        self.process = subprocess.Popen(
            command, stdout=self.log_file, stderr=subprocess.STDOUT, env=env,
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
            prefs.update(extra_prefs or {})
            value = self.request("POST", "/session", {"capabilities": {"alwaysMatch": {
                "browserName": "firefox", "acceptInsecureCerts": accept_insecure_certs,
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

    def open_tab(self, url: str) -> str:
        """Start a navigation in a new tab that no later request replaces."""
        self.set_context("content")
        created = self.request("POST", f"/session/{self.session}/window/new", {"type": "tab"})
        handle = str(created["handle"])
        self.request("POST", f"/session/{self.session}/window", {"handle": handle})
        self.request("POST", f"/session/{self.session}/url", {"url": url})
        return handle

    def tab_state(self, handle: str) -> dict[str, object] | None:
        self.set_context("content")
        self.request("POST", f"/session/{self.session}/window", {"handle": handle})
        state = self.execute(
            "return {documentURI:document.documentURI,readyState:document.readyState};"
        )
        return state if isinstance(state, dict) else None

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
        elif variant.startswith("no-blocker"):
            # T186: remove the cancel layer so the proxy result stands alone.
            blocker = "async function stargateOnBeforeRequest(details) {"
            if variant == "no-blocker":
                old, new = blocker, blocker + "\n      return {};\n"
            else:
                # Falsifiers for the probe itself: one blocked request's proxy
                # result arrives late as null (Direct) or never arrives.
                if router.count(blocker) != 1:
                    raise RuntimeError("blocking listener mutation anchor differs")
                router = router.replace(blocker, blocker + "\n      return {};\n")
                late = {
                    "no-blocker-delayed-null":
                        "new Promise((resolve) => setTimeout(() => resolve(null), 6000))",
                    "no-blocker-hung-proxy": "new Promise(() => {})",
                }[variant]
                old = "browser.proxy.onRequest.addListener(function proxyOnRequest(details) {"
                new = old + ("\n    if (details.url.includes('/blocked/trailing-dot')) "
                             f"return {late};\n")
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


# --- T186: fail-closed proxy results for blocked protected requests -------
#
# Gecko's ProxyChannelFilter turns a `null` proxy.onRequest result into "no
# proxy at all": an explicit direct connection. `x.onion.` escapes
# network.dns.blockDotOnion, so a null result for a blocked protected request
# can resolve and connect directly once the cancel listener is absent. These
# modes run with no cancel listener and observe four surfaces per request:
# the destination, the configured ordinary (system) proxy, listeners standing
# at the proxy descriptor's own target, and name resolution (strace of every
# browser socket to port 53 plus the MOZ_LOG nsHostResolver record).

T186_BLOCKED_TLS_PORT = 1023  # unused privileged port: the D4 target
T186_UNIX_SINK = "file:///dev/null/stargate-blocked"  # D5: never bindable
T186_BASE32 = "abcdefghijklmnopqrstuvwxyz234567"


def t186_label() -> str:
    raw = os.urandom(35)
    bits = int.from_bytes(raw, "big")  # 280 random bits = 56 base32 characters
    return "".join(T186_BASE32[(bits >> (5 * i)) & 31] for i in range(56))


class NameTrace:
    """Out-of-band name-resolution capture for one browser session."""

    def __init__(self, directory: pathlib.Path, name: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.strace = directory / f"{name}.strace"
        self.moz_log = directory / f"{name}.moz_log"
        for stale in directory.glob(f"{name}.*"):
            stale.unlink()

    def wrap(self, command: list[str]) -> tuple[list[str], dict[str, str]]:
        env = dict(os.environ)
        env["MOZ_LOG"] = "timestamp,sync,nsHostResolver:5"
        env["MOZ_LOG_FILE"] = str(self.moz_log)
        return ([
            "strace", "-f", "-qq", "-yy", "-s", "4096", "-o", str(self.strace),
            "-e", "trace=connect,sendto,sendmsg,sendmmsg,writev",
        ] + command, env)

    def lines(self) -> list[str]:
        if not self.strace.is_file():
            return []
        return self.strace.read_text(errors="replace").splitlines()

    def resolver_lines(self) -> list[str]:
        # glibc (`hosts: files dns`) talks to the stub resolver on port 53.
        return [line for line in self.lines()
                if ":53]" in line or "htons(53)" in line]

    def dns_hits(self, label: str) -> list[str]:
        return [line[:300] for line in self.resolver_lines() if label in line.lower()]

    def moz_log_hits(self, label: str) -> list[str]:
        # Resolver lines carry the request's origin attributes, whose
        # firstPartyDomain names the destination even while the resolved host
        # is only the proxy address. Match the looked-up host, not that key.
        hits: list[str] = []
        for path in sorted(self.moz_log.parent.glob(self.moz_log.name + "*")):
            for line in path.read_text(errors="replace").splitlines():
                if label in re.sub(r"<\^[^>]*>", "", line).lower():
                    hits.append(line[:300])
        return hits

    def connects(self, needle: str) -> list[str]:
        return [line[:300] for line in self.lines()
                if " connect(" in line and needle in line]


def t186_labels_in(data: bytes, labels: list[str]) -> list[str]:
    lowered = data.lower()
    return [label for label in labels if label.encode() in lowered]


T186_LABELS: list[str] = []


class RawImpostorHandler(socketserver.BaseRequestHandler):
    """A plain TCP listener squatting on a fail-closed descriptor target."""

    def handle(self) -> None:
        self.request.settimeout(3)
        data = bytearray()
        try:
            while len(data) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
        except (OSError, TimeoutError):
            pass
        CAPTURES.append("impostor", {
            "listener": "plain-tcp", "bytes": len(data),
            "firstBytesHex": bytes(data[:8]).hex(),
            "tlsClientHello": bool(data[:1] == b"\x16"),
            "onionBytes": b"onion" in bytes(data).lower(),
            "labels": t186_labels_in(bytes(data), T186_LABELS),
        })


class TLSImpostorHandler(socketserver.BaseRequestHandler):
    """A TLS listener with a self-signed certificate for 127.0.0.1."""

    context = None

    def handle(self) -> None:
        import ssl
        record: dict[str, object] = {"listener": "self-signed-tls"}
        self.request.settimeout(5)
        try:
            tls = self.context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError) as error:
            record.update({"handshake": "failed", "error": str(error)[:200]})
            CAPTURES.append("impostor", record)
            return
        record["handshake"] = "completed"
        try:
            raw = read_headers(tls)
        except (OSError, TimeoutError):
            raw = b""
        record.update({
            "decryptedFirstLine": raw.split(b"\r\n", 1)[0].decode("latin-1", "replace"),
            "labels": t186_labels_in(raw, T186_LABELS),
        })
        CAPTURES.append("impostor", record)


class UnixServer:
    def __init__(self, handler: type[socketserver.BaseRequestHandler],
                 path: pathlib.Path) -> None:
        if path.exists():
            path.unlink()
        self.server = socketserver.ThreadingUnixStreamServer(str(path), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def t186_tls_context(directory: pathlib.Path):
    import ssl
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / "impostor.key", directory / "impostor.crt"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out",
        str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
        "-addext", "subjectAltName=IP:127.0.0.1",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def t186_matrix_extension(destination: pathlib.Path, modes: dict[str, object],
                          hosts: dict[str, str]) -> pathlib.Path:
    """A minimal proxy-only extension: a fixed descriptor per request host.

    Every request to one host (including browser-initiated favicon loads)
    gets that host's descriptor. It has no webRequest listener at all, so
    nothing can cancel a request: the browser's handling of the returned
    proxy result is observed alone.
    """
    manifest = {
        "manifest_version": 2, "name": "t186-descriptor-matrix", "version": "1",
        "browser_specific_settings": {"gecko": {"id": "t186-matrix@stargate.local"}},
        "permissions": ["proxy", "<all_urls>"],
        "background": {"scripts": ["background.js"]},
    }
    script = (
        "'use strict';\nconst MODES = " + json.dumps(modes, sort_keys=True) + ";\n"
        "const HOSTS = " + json.dumps(hosts, sort_keys=True) + ";\n"
        "browser.proxy.onRequest.addListener((details) => {\n"
        "  const host = new URL(details.url).hostname.replace(/\\.+$/, '').toLowerCase();\n"
        "  const mode = HOSTS[host];\n"
        "  if (Object.prototype.hasOwnProperty.call(MODES, mode)) return MODES[mode];\n"
        "  return { type: 'direct' };\n"
        "}, { urls: ['<all_urls>'] });\n"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in (("manifest.json", json.dumps(manifest, sort_keys=True)),
                           ("background.js", script)):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            archive.writestr(info, body)
    return destination


def t186_request_url(host: str, port: int, mode: str, variant: str) -> str:
    return f"http://{host}:{port}/{mode}/{variant}"


def t186_hits(label: str, trace: NameTrace) -> dict[str, list[object]]:
    return {
        "destination": [x for x in CAPTURES.snapshot("destination")
                        if label in str(x.get("host")) or label in str(x.get("path"))],
        "systemProxy": [x for x in CAPTURES.snapshot("http")
                        if label in str(x.get("host")) or label in str(x.get("path"))],
        "socks": [x for x in CAPTURES.snapshot("socks") if label in str(x.get("host"))],
        "impostorLabel": [x for x in CAPTURES.snapshot("impostor")
                          if label in (x.get("labels") or [])],
        "dnsStrace": trace.dns_hits(label),
        "dnsMozLog": trace.moz_log_hits(label),
    }


def t186_clean(hits: dict[str, list[object]]) -> bool:
    return not any(hits.values())


def t186_summary(report: dict[str, object]) -> dict[str, object]:
    def surfaces(hits: dict[str, list[object]]) -> list[str]:
        return sorted(name for name, found in hits.items() if found)

    scenarios: dict[str, object] = {}
    for name, scenario in dict(report["scenarios"]).items():
        entry: dict[str, object] = {"passed": scenario["passed"]}
        for key in ("results", "liveUnixCalibration", "controls"):
            value = scenario.get(key)
            if not isinstance(value, dict):
                continue
            flat: dict[str, object] = {}
            for variant, result in value.items():
                if isinstance(result, dict) and "hits" in result:
                    flat[variant] = {"host": result["host"], "surfaces": surfaces(result["hits"]),
                                     "terminal": (result.get("terminal") or {}).get("kind")}
                elif isinstance(result, dict) and all(isinstance(x, dict) for x in result.values()):
                    flat[variant] = {v: {"host": r["host"], "surfaces": surfaces(r["hits"])}
                                     for v, r in result.items() if "hits" in r}
                elif isinstance(result, dict):
                    flat[variant] = {"surfaces": surfaces(result)}
            entry[key] = flat
        for key in ("controlsPassed", "unixSocksSupported", "nameReceived", "socksReached"):
            if key in scenario:
                value = scenario[key]
                entry[key] = ({k: len(v) for k, v in value.items()}
                              if isinstance(value, dict) else value)
        scenarios[name] = entry
    return {"browserVersion": report["browserVersion"], "result": report["result"],
            "failures": report["failures"], "designs": report.get("t186Designs"),
            "executedExtensionSha256": report["executedExtensionSha256"],
            "scenarios": scenarios}


class ImpostorSocksHandler(socketserver.BaseRequestHandler):
    """A SOCKS5 listener that accepts any client and records the CONNECT name."""

    def handle(self) -> None:
        record: dict[str, object] = {"listener": "socks-impostor", "stage": "accepted"}
        CAPTURES.append("socks", record)
        self.request.settimeout(5)
        try:
            version, count = read_exact(self.request, 2)
            methods = read_exact(self.request, count)
            if version != 5:
                return
            if 0 in methods:
                self.request.sendall(b"\x05\x00")
            elif 2 in methods:
                self.request.sendall(b"\x05\x02")
                read_exact(self.request, 1)
                read_exact(self.request, read_exact(self.request, 1)[0])
                read_exact(self.request, read_exact(self.request, 1)[0])
                self.request.sendall(b"\x01\x00")
            else:
                return
            _version, command, _reserved, address_type = read_exact(self.request, 4)
            if command != 1 or address_type != 3:
                record["stage"] = f"connect-atyp-{address_type}"
                return
            host = read_exact(self.request, read_exact(self.request, 1)[0]).decode("latin-1")
            record.update({"stage": "connect", "host": host.lower()})
        except (EOFError, OSError, TimeoutError):
            return


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
    parser.add_argument("--only", choices=("full", "startup", "sidecar", "context", "fixture", "navigation",
                                           "descriptor-matrix", "blocked-proxy"),
                        default="full")
    parser.add_argument("--mutation", choices=("none", "observe", "terminal-null", "opaque-context",
                        "terminal-null-and-blocker", "suppress-subrequest",
                        "delayed-fallback", "startup-release", "delayed-main-navigation",
                        "delayed-null", "hung-proxy"), default="none")
    args = parser.parse_args()
    if args.mutation in ("delayed-null", "hung-proxy") and args.only != "blocked-proxy":
        parser.error(f"--mutation {args.mutation} applies only to --only blocked-proxy")
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

    def t186_session_prefs(mapped: list[str]) -> dict[str, object]:
        forms = sorted({h.lower().rstrip(".") for h in mapped} |
                       {h.lower().rstrip(".") + "." for h in mapped})
        return {
            "network.dns.localDomains": ",".join(forms),
            # Native resolution keeps every lookup observable at the socket
            # layer; MOZ_LOG additionally records resolver requests whatever
            # the backend (Mullvad Browser defaults to DoH-only mode 3).
            "network.trr.mode": 5,
            "network.dns.disablePrefetch": True,
            "network.http.speculative-parallel-limit": 0,
        }

    def t186_variants(port: int, mode: str) -> dict[str, dict[str, object]]:
        variants: dict[str, dict[str, object]] = {}
        for variant, suffix, mapped in (("onion", ".onion", True),
                                        ("trailing-dot", ".onion.", True),
                                        ("mixed-case", ".OnIoN.", True),
                                        ("unmapped-dns", ".onion.", False)):
            label = t186_label()
            T186_LABELS.append(label)
            shown = label.upper() if variant == "mixed-case" else label
            host = shown + suffix
            variants[variant] = {"label": label, "host": host, "mapped": mapped,
                                 "url": t186_request_url(host, port, mode, variant)}
        return variants

    def t186_controls(port: int, sysproxy_mode: str, null_mode: str) -> dict[str, dict[str, object]]:
        controls: dict[str, dict[str, object]] = {}
        for name, suffix, mapped, mode in (
            ("destination", ".test", True, null_mode),
            ("system-proxy", ".test", True, sysproxy_mode),
            ("dns", ".invalid", False, null_mode),
        ):
            label = t186_label()
            T186_LABELS.append(label)
            host = label + suffix
            controls[name] = {"label": label, "host": host, "mapped": mapped,
                              "url": t186_request_url(host, port, mode, "control-" + name)}
        return controls

    def t186_mapped(groups: list[dict[str, dict[str, object]]]) -> list[str]:
        return [str(v["host"]) for group in groups for v in group.values() if v["mapped"]]

    def t186_run_requests(browser: WebDriver, requests: list[dict[str, object]],
                          settle: float) -> None:
        # Each request keeps its own tab for the whole observation, so no
        # later navigation can cancel it. A request counts as observed only
        # once its tab reaches a terminal document bound to that request's
        # unique label (the loaded page or an error page naming the URL);
        # every tab then stays open for `settle` seconds more.
        started = time.monotonic()
        for request in requests:
            request["handle"] = browser.open_tab(str(request["url"]))
        pending = list(requests)
        last: dict[int, dict[str, object]] = {}
        deadline = time.monotonic() + 30
        while pending and time.monotonic() < deadline:
            for request in list(pending):
                try:
                    state = browser.tab_state(str(request["handle"]))
                except RuntimeError:
                    continue
                if state is None:
                    continue
                last[id(request)] = state
                uri = str(state.get("documentURI") or "").lower()
                # A browser error page naming this request is its terminal
                # channel failure; background tabs may leave it "interactive".
                error = uri.startswith(("about:neterror", "about:certerror"))
                ready = state.get("readyState") == "complete" or (
                    error and state.get("readyState") == "interactive")
                if ready and str(request["label"]) in uri:
                    request["terminal"] = {
                        **state, "completed": True,
                        "kind": "error" if error else "loaded",
                        "elapsedSeconds": round(time.monotonic() - started, 3),
                    }
                    pending.remove(request)
            time.sleep(0.2)
        for request in pending:
            request["terminal"] = {**last.get(id(request), {}), "completed": False,
                                   "kind": "incomplete"}
        time.sleep(settle)

    def t186_terminal_error(request: dict[str, object]) -> bool:
        terminal = request.get("terminal") or {}
        return terminal.get("completed") is True and terminal.get("kind") == "error"

    def run_descriptor_matrix() -> None:
        # Maintainer-directed feasibility study (T186 Notes): which fail-closed
        # proxy result keeps a blocked protected request off every surface when
        # no cancel listener exists?
        workdir = args.report_out.with_suffix(".t186")
        trace = NameTrace(workdir, "matrix")
        raw = Server(RawImpostorHandler)
        TLSImpostorHandler.context = t186_tls_context(workdir)
        tls = Server(TLSImpostorHandler)
        socks_impostor = Server(ImpostorSocksHandler)
        unix_path = workdir / "live-socks.sock"
        unix_socks = UnixServer(ImpostorSocksHandler, unix_path)
        for server in (raw, tls, socks_impostor, unix_socks):
            server.start()
        modes: dict[str, object] = {
            "ctl-null": None,
            "ctl-direct": {"type": "direct"},
            "d1-null": None,
            "d1-socks": [{"type": "socks", "host": "127.0.0.1", "port": socks_impostor.port,
                          "username": "blocked", "password": "invalid", "proxyDNS": True}, None],
            "d5-live": [{"type": "socks", "host": "file://" + str(unix_path.resolve()),
                         "port": 1, "proxyDNS": True}, None],
            "d5": [{"type": "socks", "host": T186_UNIX_SINK, "port": 1, "proxyDNS": True}, None],
            "d4": [{"type": "https", "host": "127.0.0.1", "port": T186_BLOCKED_TLS_PORT}, None],
            "d4-plain": [{"type": "https", "host": "127.0.0.1", "port": raw.port}, None],
            "d4-tls": [{"type": "https", "host": "127.0.0.1", "port": tls.port}, None],
        }
        report["t186Modes"] = modes
        port = destination.port
        groups = {mode: t186_variants(port, mode)
                  for mode in ("d1-null", "d1-socks", "d5-live", "d5", "d4", "d4-plain", "d4-tls")}
        controls = t186_controls(port, "ctl-direct", "ctl-null")
        calibration = t186_variants(port, "d4-tls")
        everything = list(groups.values()) + [controls, calibration]
        mapped = t186_mapped(everything)
        hosts = {str(r["host"]).rstrip(".").lower(): urllib.parse.urlsplit(str(r["url"])).path.split("/")[1]
                 for group in everything for r in group.values()}
        extension = t186_matrix_extension(workdir / "matrix-extension.zip", modes, hosts)
        report["t186MatrixExtensionSha256"] = sha256(extension)
        try:
            browser = WebDriver(args.browser, args.driver, extension, http_proxy.port, True,
                                args.driver_log, extra_prefs=t186_session_prefs(mapped),
                                accept_insecure_certs=False, trace=trace)
            try:
                CAPTURES.reset("http", "destination", "socks", "impostor")
                ordered = [v for group in groups.values() for v in group.values()]
                # Past Gecko's ten-second proxy failover bound, all tabs open.
                t186_run_requests(browser, ordered + list(controls.values()), settle=12)
            finally:
                browser.close()
            impostor_after_main = CAPTURES.snapshot("impostor")
            # Calibration: the same TLS impostor, but with certificate errors
            # accepted by the automation session, must see the request name.
            cal_trace = NameTrace(workdir, "calibration")
            browser = WebDriver(args.browser, args.driver, extension, http_proxy.port, True,
                                args.driver_log, extra_prefs=t186_session_prefs(mapped),
                                accept_insecure_certs=True, trace=cal_trace)
            try:
                t186_run_requests(browser, [calibration["trailing-dot"]], settle=3)
            finally:
                browser.close()
        finally:
            for server in (raw, tls, socks_impostor, unix_socks):
                server.stop()

        def evaluate(group: dict[str, dict[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for variant, request in group.items():
                hits = t186_hits(str(request["label"]), trace)
                out[variant] = {"host": request["host"], "terminal": request.get("terminal"),
                                "terminalError": t186_terminal_error(request),
                                "hits": hits, "clean": t186_clean(hits)}
            return out

        results = {mode: evaluate(group) for mode, group in groups.items()}
        control_results = evaluate(controls)
        controls_ok = (
            all((c.get("terminal") or {}).get("completed") is True for c in controls.values()) and
            bool(control_results["destination"]["hits"]["destination"]) and
            bool(control_results["system-proxy"]["hits"]["systemProxy"]) and
            bool(control_results["dns"]["hits"]["dnsStrace"]) and
            bool(control_results["dns"]["hits"]["dnsMozLog"])
        )
        record("t186-positive-controls", controls_ok, extra={"controls": control_results})

        def all_clean(mode: str) -> bool:
            # A negative result needs a request-bound terminal failure too.
            return all(v["clean"] and v["terminalError"] for v in results[mode].values())

        d1_leaks = {v: sorted(k for k, hits in r["hits"].items() if hits)
                    for v, r in results["d1-null"].items()}
        record("t186-d1-null-comparison", True, extra={
            "results": results["d1-null"], "leakSurfaces": d1_leaks})
        socks_names = [x for x in CAPTURES.snapshot("socks")
                       if any(str(r["label"]) in str(x.get("host"))
                              for r in groups["d1-socks"].values())]
        record("t186-d1-socks-impostor-comparison", True, extra={
            "results": results["d1-socks"], "impostorReceivedNames": socks_names,
            "nameReceived": bool(socks_names)})

        d5_supported = any(results["d5-live"][v]["hits"]["socks"] for v in results["d5-live"])
        d5_attempts = trace.connects("/dev/null/stargate-blocked")
        d5_pass = d5_supported and all_clean("d5") and bool(d5_attempts)
        record("t186-d5-unix-sink", d5_pass, extra={
            "unixSocksSupported": d5_supported, "liveUnixCalibration": results["d5-live"],
            "results": results["d5"], "sinkConnectAttempts": d5_attempts[:8]})

        impostor = impostor_after_main
        plain = [x for x in impostor if x.get("listener") == "plain-tcp"]
        tls_seen = [x for x in impostor if x.get("listener") == "self-signed-tls"]
        cal_label = str(calibration["trailing-dot"]["label"])
        cal_seen = [x for x in CAPTURES.snapshot("impostor")
                    if x.get("listener") == "self-signed-tls" and cal_label in (x.get("labels") or [])]
        d4_attempts = trace.connects(f"htons({T186_BLOCKED_TLS_PORT})")
        d4_pass = (
            all_clean("d4") and all_clean("d4-plain") and all_clean("d4-tls") and
            bool(d4_attempts) and bool(plain) and
            all(not x["labels"] and not x["onionBytes"] for x in plain) and
            bool(tls_seen) and all(x.get("handshake") == "failed" for x in tls_seen) and
            bool(cal_seen)
        )
        record("t186-d4-https-privileged", d4_pass, extra={
            "results": {m: results[m] for m in ("d4", "d4-plain", "d4-tls")},
            "privilegedPortConnectAttempts": d4_attempts[:8],
            "plainImpostor": plain, "tlsImpostor": tls_seen,
            "acceptedCertificateCalibration": {
                "host": calibration["trailing-dot"]["host"], "impostorDecrypted": cal_seen},
        })
        report["t186Designs"] = {"D5": d5_pass, "D4": d4_pass}
        report["t186ResolverLinesTotal"] = len(trace.resolver_lines())

    def run_blocked_proxy() -> None:
        # Acceptance 3: the real extension with its cancel listener disabled.
        # Every blocked protected request must stay off all four surfaces.
        workdir = args.report_out.with_suffix(".t186")
        variant = "no-blocker" if args.mutation == "none" else f"no-blocker-{args.mutation}"
        mutant, identity = variant_extension(
            args.extension, workdir / f"{variant}.zip", variant)
        report["t186NoBlocker"] = identity
        socks = Server(SocksHandler, 8881)  # Stargate's Tor port: must stay silent
        socks.start()
        port = destination.port
        try:
            for session, hardened, seed in (("missing-token", True, False),
                                             ("hardening-closed", False, True)):
                trace = NameTrace(workdir, session)
                blocked = t186_variants(port, "blocked")
                controls = t186_controls(port, "sysproxy", "direct")
                browser = WebDriver(args.browser, args.driver, mutant, http_proxy.port,
                                    hardened, args.driver_log,
                                    extra_prefs=t186_session_prefs(t186_mapped([blocked, controls])),
                                    accept_insecure_certs=False, trace=trace)
                try:
                    if seed:
                        browser.seed_valid_device()
                    CAPTURES.reset("http", "destination", "socks", "impostor")
                    t186_run_requests(browser, list(blocked.values()), settle=12)
                    t186_run_requests(browser, [controls["system-proxy"]], settle=0)
                    browser.set_proxy_type(0)
                    t186_run_requests(browser, [controls["destination"], controls["dns"]],
                                      settle=2)
                    browser.set_proxy_type(1)
                finally:
                    browser.close()
                results = {}
                for form, request in blocked.items():
                    hits = t186_hits(str(request["label"]), trace)
                    results[form] = {"host": request["host"], "terminal": request.get("terminal"),
                                     "terminalError": t186_terminal_error(request),
                                     "hits": hits, "clean": t186_clean(hits)}
                control_hits = {name: t186_hits(str(c["label"]), trace)
                                for name, c in controls.items()}
                controls_ok = (all((c.get("terminal") or {}).get("completed") is True
                                   for c in controls.values()) and
                               bool(control_hits["system-proxy"]["systemProxy"]) and
                               bool(control_hits["destination"]["destination"]) and
                               bool(control_hits["dns"]["dnsStrace"]) and
                               bool(control_hits["dns"]["dnsMozLog"]))
                record(f"t186-blocked-{session}-no-direct-proxy-or-dns",
                       controls_ok and all(r["clean"] and r["terminalError"]
                                           for r in results.values()),
                       extra={"results": results, "controls": control_hits,
                              "controlsPassed": controls_ok,
                              "fixtureStorageSeeded": seed, "hardened": hardened})
            # Positive control for the protected route itself: with valid state
            # the same trailing-dot form reaches Stargate's SOCKS port by name.
            trace = NameTrace(workdir, "tor-positive")
            tor = t186_variants(port, "tor")
            browser = WebDriver(args.browser, args.driver, mutant, http_proxy.port, True,
                                args.driver_log, extra_prefs=t186_session_prefs(t186_mapped([tor])),
                                accept_insecure_certs=False, trace=trace)
            try:
                browser.seed_valid_device()
                CAPTURES.reset("http", "destination", "socks", "impostor")
                t186_run_requests(browser, [tor["trailing-dot"], tor["mixed-case"]], settle=2)
            finally:
                browser.close()
            reached = {v: [x for x in CAPTURES.snapshot("socks")
                           if str(tor[v]["label"]) in str(x.get("host")) and
                           x.get("passwordMatches") is True]
                       for v in ("trailing-dot", "mixed-case")}
            record("t186-tor-route-positive-control", all(reached.values()), extra={
                "socksReached": reached,
                "otherSurfaces": {v: t186_hits(str(tor[v]["label"]), trace)
                                  for v in ("trailing-dot", "mixed-case")}})
        finally:
            socks.stop()

    def finish() -> int:
        report["result"] = "GREEN" if not failures else "RED"
        report["failures"] = failures
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(rendered)
        if args.only in ("descriptor-matrix", "blocked-proxy"):
            # The complete record (captures, strace and MOZ_LOG lines) is in
            # --report-out; stdout carries the per-request surface verdicts.
            print(json.dumps(t186_summary(report), indent=1, sort_keys=True))
        else:
            print(rendered, end="")
        return 0 if not failures else 1

    if args.only in ("descriptor-matrix", "blocked-proxy"):
        try:
            if args.only == "descriptor-matrix":
                run_descriptor_matrix()
            else:
                run_blocked_proxy()
        finally:
            http_proxy.stop()
            destination.stop()
        return finish()

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
