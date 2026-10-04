# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T204 actual network-namespace listener observation; run on the disposable guest.

Polling detects exposure, but cannot prove absence of a shorter exposure. The
pre-listen framework ordering is a separate required part of the evidence.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def parse_table(contents, family):
    lines = contents.splitlines()
    if not lines or "local_address" not in lines[0]:
        raise ValueError("missing socket-table header")
    result = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise ValueError("truncated socket-table row")
        if fields[3] != "0A":
            continue
        host, port = fields[1].split(":")
        raw = bytes.fromhex(host)
        if len(raw) != (4 if family == 4 else 16):
            raise ValueError("wrong socket-table address family")
        # procfs prints native-endian 32-bit words for both address families.
        raw = b"".join(int.from_bytes(raw[i:i + 4], "big").to_bytes(4, sys.byteorder)
                       for i in range(0, len(raw), 4))
        result.append({"family": family, "address": str(ipaddress.ip_address(raw)),
                       "port": int(port, 16), "inode": fields[9]})
    return result


def snapshot(pid):
    process = Path(f"/proc/{pid}")
    identity = (process / "stat").read_text().rsplit(")", 1)[1].split()[19]
    namespace = os.readlink(process / "ns/net")
    listeners = []
    for name, family in (("tcp", 4), ("tcp6", 6)):
        listeners.extend(parse_table((process / "net" / name).read_text(), family))
    if identity != (process / "stat").read_text().rsplit(")", 1)[1].split()[19]:
        raise RuntimeError("process identity changed during observation")
    return {"pid": pid, "start_ticks": identity, "namespace": namespace,
            "listeners": listeners, "families_inspected": [4, 6]}


def assert_boundary(observation):
    if observation["families_inspected"] != [4, 6]:
        raise AssertionError("both IP families must be observed")
    for entry in observation["listeners"]:
        address = ipaddress.ip_address(entry["address"])
        if isinstance(address, ipaddress.IPv6Address):
            address = address.ipv4_mapped
        if address != ipaddress.ip_address("127.0.0.1"):
            raise AssertionError(f"forbidden CP listener: {entry['address']}:{entry['port']}")


def calibrate():
    """Real family controls and a short-lived forbidden listener (not a timing proof)."""
    observed = []
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "0.0.0.0"),
                            (socket.AF_INET6, "::1"), (socket.AF_INET6, "::")):
        with socket.socket(family) as listener:
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((address, 0))
            listener.listen()
            port = listener.getsockname()[1]
            rows = [entry for entry in snapshot(os.getpid())["listeners"] if entry["port"] == port]
            if not any(row["address"] == address for row in rows):
                raise AssertionError("live address positive control not observed")
            observed.append(address)
    child = subprocess.Popen([sys.executable, "-u", "-c",
        "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',0)); s.listen(); "
        "print(s.getsockname()[1],flush=True); time.sleep(0.2)"], stdout=subprocess.PIPE, text=True)
    try:
        port = int(child.stdout.readline())
        rows = snapshot(child.pid)
        rows["listeners"] = [row for row in rows["listeners"] if row["port"] == port]
        if not rows["listeners"]:
            raise AssertionError("transient listener was missed")
        try:
            assert_boundary(rows)
        except AssertionError:
            pass
        else:
            raise AssertionError("transient forbidden listener accepted")
    finally:
        child.wait(timeout=5)
        child.stdout.close()
    return {"addresses": observed, "transient_forbidden_detected": True,
            "polling_is_not_no_transient_proof": True}


def checked(argv, timeout=5):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=timeout).strip()


def startup_observation(container, pid, samples, expected_refusal):
    try:
        view = snapshot(pid)
        unix = Path(f"/proc/{pid}/net/unix").read_text()
        return view, unix
    except (FileNotFoundError, ProcessLookupError):
        # A refusing process can exit between inspect and procfs. This is no
        # observation: retain prior samples and require terminal refusal below.
        if expected_refusal and samples:
            # Docker's state publication can lag procfs teardown. A bounded
            # confirmation may establish terminal refusal, never clean absence.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                state = json.loads(checked(["docker", "inspect", "--format", "{{json .State}}", container], timeout=5))
                if state["Status"] == "exited":
                    if not state["Running"] and state["ExitCode"] != 0:
                        return None
                    break
                if not state["Running"]:
                    break
                time.sleep(0.05)
        raise


def refused_restart(container):
    process = subprocess.Popen(["docker", "start", "-a", container],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    samples, observed_pid, terminal_race = 0, None, False
    try:
        deadline = time.monotonic() + 180
        while process.poll() is None and time.monotonic() < deadline:
            state = json.loads(checked(["docker", "inspect", "--format", "{{json .State}}", container]))
            if state["Running"]:
                observed_pid = state["Pid"]
                observation = startup_observation(container, observed_pid, samples, True)
                if observation is None:
                    terminal_race = True
                    break
                assert_boundary(observation[0])
                samples += 1
            time.sleep(0.02)
        raw, _ = process.communicate(timeout=15)
        if not samples or process.returncode == 0 or "CP_HTTP_BOUNDARY" not in raw:
            raise AssertionError("restart did not establish the intended pre-listen refusal")
        return {"pid": observed_pid, "samples": samples, "fixed_boundary_error": True,
                "terminal_exit_during_inspection": terminal_race}
    finally:
        subprocess.run(["docker", "stop", "-t", "5", container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15)
        if process.poll() is None:
            process.communicate(timeout=15)
        process.stdout.close()


def package_matrix(image, keys, config, output, start_case=0, only_case=None):
    """Valid synthetic installation, exact normal image, fresh state per startup.

    The diagnostic fast-jar invocation uses the image's JVM/package, capturing
    only whether the fixed boundary error occurred. The real silent launcher
    is separately checked with the same configuration and no log capture.
    Containers and fixture files are stopped and retained for explicit cleanup.
    """
    output.mkdir(parents=True, exist_ok=True)
    image = checked(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    fixture = output / "config"
    fixture.mkdir(exist_ok=True)
    (fixture / "wild.properties").write_text("quarkus.http.host=0.0.0.0\n")
    (fixture / "profile.properties").write_text("%boundary.quarkus.http.host=::\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(fixture / "key.pem"),
                    "-out", str(fixture / "cert.pem")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (fixture / "key.pem").chmod(0o644)  # disposable test TLS identity, never production keys
    cases = [
        ("default", {}, [], "http"),
        ("default-launcher", {}, [], "http"),
        ("wildcard-launcher", {"QUARKUS_HTTP_HOST": "0.0.0.0"}, [], "refuse-silent"),
        ("jvm-env-launcher", {"JAVA_TOOL_OPTIONS": "-Dquarkus.http.host=0.0.0.0",
                              "JDK_JAVA_OPTIONS": "-Dquarkus.http.host=::"}, [], "http"),
        ("loopback-env", {"QUARKUS_HTTP_HOST": "127.0.0.1"}, [], "http"),
        *[(label, {"QUARKUS_HTTP_HOST": host}, [], "refuse") for label, host in
          (("ipv4-wildcard", "0.0.0.0"), ("ipv6-wildcard", "::"),
           ("ipv6-loopback", "::1"), ("nonloopback", "192.0.2.1"),
           ("hostname", "must-not-resolve.invalid"), ("mapped-host", "::ffff:127.0.0.1"))],
        ("system-over-env-refuse", {"QUARKUS_HTTP_HOST": "127.0.0.1"},
         ["-Dquarkus.http.host=0.0.0.0"], "refuse"),
        ("system-over-env-allow", {"QUARKUS_HTTP_HOST": "0.0.0.0"},
         ["-Dquarkus.http.host=127.0.0.1"], "http"),
        ("external-config", {"QUARKUS_CONFIG_LOCATIONS": "file:/fixture/wild.properties"}, [], "refuse"),
        ("external-profile", {"QUARKUS_CONFIG_LOCATIONS": "file:/fixture/profile.properties",
                              "QUARKUS_PROFILE": "boundary"}, [], "refuse"),
        ("main-disabled", {"QUARKUS_HTTP_HOST_ENABLED": "false"}, [], "absent"),
        ("domain-with-main-disabled", {"QUARKUS_HTTP_HOST_ENABLED": "false",
          "QUARKUS_HTTP_DOMAIN_SOCKET_ENABLED": "true", "QUARKUS_HTTP_DOMAIN_SOCKET": "/tmp/http.sock"}, [], "refuse"),
        ("https", {"QUARKUS_HTTP_SSL_CERTIFICATE_FILES": "/fixture/cert.pem",
                   "QUARKUS_HTTP_SSL_CERTIFICATE_KEY_FILES": "/fixture/key.pem"}, [], "refuse"),
        # Management enablement is build-time in the reviewed fast jar. Runtime
        # inputs must not activate either management transport, even with main off.
        ("management-runtime", {"QUARKUS_MANAGEMENT_ENABLED": "true",
                                "QUARKUS_MANAGEMENT_HOST": "0.0.0.0"}, [], "http"),
        ("management-domain-main-off", {"QUARKUS_HTTP_HOST_ENABLED": "false",
          "QUARKUS_MANAGEMENT_ENABLED": "true", "QUARKUS_MANAGEMENT_DOMAIN_SOCKET_ENABLED": "true",
          "QUARKUS_MANAGEMENT_DOMAIN_SOCKET": "/tmp/management.sock"}, [], "absent"),
    ]
    if not 0 <= start_case < len(cases):
        raise ValueError("start-case outside matrix")
    if only_case is not None and only_case not in [case[0] for case in cases[start_case:]]:
        raise ValueError("only-case outside selected matrix")
    report = {"image": image, "calibration": calibrate(), "cases": [], "complete": False,
              "selected_start_index": start_case, "only_case": only_case,
              "selection_complete": False, "total_defined_cases": len(cases)}
    path = output / "matrix.json"
    try:
        for number, (label, env, properties, expected) in enumerate(cases):
            if number < start_case or (only_case is not None and label != only_case):
                continue
            name = f"t204-http-{output.name}-{number}"
            argv = ["docker", "create", "--name", name, "--network", "none", "--read-only",
                    "--user", "5101:5100", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "--log-driver", "none", "--tmpfs", "/tmp:rw,exec", "--tmpfs", "/run",
                    "--tmpfs", "/run/stargate:uid=5101,gid=5100,mode=0770",
                    "--tmpfs", "/var/lib/stargate:uid=5101,gid=5100,mode=0750",
                    "-v", f"{config}:/etc/stargate:ro", "-v", f"{keys}:/etc/stargate/keys:ro",
                    "-v", f"{fixture.resolve()}:/fixture:ro"]
            for key, value in env.items():
                argv.extend(["-e", f"{key}={value}"])
            if label.endswith("-launcher"):
                argv.append(image)
            else:
                argv.extend(["--entrypoint", "java", image,
                             "-Dquarkus.log.level=ERROR", "-Dquarkus.log.console.enabled=true",
                             *properties, "-jar", "/opt/stargate/quarkus-run.jar"])
            container = checked(argv)
            process = subprocess.Popen(["docker", "start", "-a", container],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            observed, ready_at, pid, samples = [], None, None, 0
            item = {"name": label, "expected": expected, "container": container,
                    "config": env, "system_properties": properties, "launch_argv": argv}
            report["cases"].append(item)
            try:
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    state = json.loads(checked(["docker", "inspect", "--format", "{{json .State}}", container]))
                    if not state["Running"]:
                        if state["Status"] == "created":
                            time.sleep(0.05)
                            continue
                        break
                    pid = state["Pid"]
                    observation = startup_observation(container, pid, samples, expected.startswith("refuse"))
                    if observation is None:
                        item["terminal_exit_during_inspection"] = True
                        break
                    view, unix = observation
                    samples += 1
                    assert_boundary(view)
                    for row in view["listeners"]:
                        if row not in observed:
                            observed.append(row)
                    if "/tmp/http.sock" in unix or "/tmp/management.sock" in unix:
                        raise AssertionError("unsupported HTTP domain socket exists")
                    if "/run/stargate/control.sock" in unix:
                        if ready_at is None:
                            ready_at = time.monotonic()
                        if time.monotonic() - ready_at >= 2:
                            if expected.startswith("refuse"):
                                raise AssertionError(f"{label}: forbidden configuration started")
                            if expected == "http":
                                if len(observed) != 2 or sum(row["port"] == 8080 for row in observed) != 1:
                                    raise AssertionError("HTTP listener inventory differs")
                                response = checked(["nsenter", "-t", str(pid), "-n", "curl", "-sS",
                                    "--max-time", "5", "-w", "%{http_code}:%{size_download}",
                                    "http://127.0.0.1:8080/healthz"])
                                if response != "200:0" or not observed:
                                    raise AssertionError("finite health positive control failed")
                            elif any(row["port"] == 8080 for row in observed) or len(observed) != 1:
                                # Narayana SocketProcessId reserves one loopback
                                # TCP port even without HTTP; it never accepts.
                                raise AssertionError("disabled HTTP listener inventory differs")
                            break
                    time.sleep(0.02)
                else:
                    raise AssertionError("startup deadline expired; absence unproven")
                if expected.startswith("refuse"):
                    raw, _ = process.communicate(timeout=15)
                    intended = "CP_HTTP_BOUNDARY" in raw if expected == "refuse" else not raw
                    if not samples or process.returncode == 0 or not intended:
                        raise AssertionError("startup failed without the intended boundary refusal")
                    item["fixed_boundary_error"] = expected == "refuse"
                    item["silent_launcher"] = expected == "refuse-silent"
                elif ready_at is None or not state["Running"]:
                    raise AssertionError("premature CP exit is not a valid startup/absence control")
                item.update({"outcome": "PASS", "pid": pid, "listeners": observed,
                             "startup_samples": samples})
            finally:
                subprocess.run(["docker", "stop", "-t", "5", container],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15)
                if process.poll() is None:
                    process.communicate(timeout=15)
                process.stdout.close()
                path.write_text(json.dumps(report, indent=2) + "\n")
            if label == "ipv4-wildcard":
                item["same_container_restart"] = refused_restart(container)
                if item["same_container_restart"]["pid"] == pid:
                    raise AssertionError("restart reused the old process identity")
        report["selection_complete"] = True
        report["complete"] = start_case == 0 and only_case is None
    finally:
        path.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: selected production fast-jar cases " + ", ".join(item["name"] for item in report["cases"]), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int)
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--record-only", action="store_true")
    parser.add_argument("--image")
    parser.add_argument("--keys")
    parser.add_argument("--config")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--start-case", type=int, default=0,
                        help="run this index onward; preserve and separately bind earlier evidence")
    parser.add_argument("--only-case", help="run only this named case; not a complete matrix")
    args = parser.parse_args()
    if args.image:
        if not all((args.keys, args.config, args.output)):
            parser.error("matrix needs --keys, --config and --output")
        package_matrix(args.image, args.keys, args.config, args.output, args.start_case, args.only_case)
    elif args.calibrate:
        print(json.dumps(calibrate(), sort_keys=True))
    elif args.pid:
        observation = snapshot(args.pid)
        print(json.dumps(observation, sort_keys=True), flush=True)
        if not args.record_only:
            assert_boundary(observation)
    else:
        parser.error("--pid or --calibrate required")


if __name__ == "__main__":
    main()
