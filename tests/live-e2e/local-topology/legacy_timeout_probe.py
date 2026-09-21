# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T163 acceptance 1: measure the legacy timeout probe's discrimination gap."""

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time

from run import Recorder, ROOT, classify, stop_recorders


def command(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout


def main() -> None:
    if (os.geteuid() != 0 or os.environ.get("STARGATE_LIVE_E2E") != "1"
            or os.environ.get("STARGATE_DISPOSABLE_HOST") != "1"):
        raise RuntimeError("requires root and explicit disposable live-host opt-in")
    for tool in ("ip", "iptables", "tcpdump"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required tool missing: {tool}")

    namespace, interface, peer, chain = "t163-timeout", "t163-timeout0", "t163-timeout1", "T163_TIMEOUT"
    if any(line.split()[0] == namespace for line in command("ip", "netns", "list").splitlines()):
        raise RuntimeError("timeout fixture namespace already exists")
    if any(line == f"-N {chain}" for line in command("iptables", "-S").splitlines()):
        raise RuntimeError("timeout fixture chain already exists")

    evidence = ROOT / "target/live-e2e" / time.strftime("T163-legacy-%Y%m%d-%H%M%S", time.gmtime())
    evidence.mkdir(parents=True)
    destination = "198.51.100.2"
    hook = ("OUTPUT", "-m", "owner", "--uid-owner", "5102", "-d", destination,
            "-p", "tcp", "--dport", "39112", "-j", chain)
    with contextlib.ExitStack() as cleanup:
        command("ip", "netns", "add", namespace)
        cleanup.callback(command, "ip", "netns", "del", namespace)
        command("ip", "link", "add", interface, "type", "veth", "peer", "name", peer)
        cleanup.callback(command, "ip", "link", "del", interface)
        command("ip", "link", "set", peer, "netns", namespace)
        command("ip", "addr", "add", "198.51.100.1/30", "dev", interface)
        command("ip", "link", "set", interface, "up")
        command("ip", "-n", namespace, "addr", "add", destination + "/30", "dev", peer)
        command("ip", "-n", namespace, "link", "set", peer, "up")
        command("ip", "netns", "exec", namespace, "iptables", "-A", "INPUT",
                "-p", "tcp", "--dport", "39111:39112", "-j", "DROP")
        command("iptables", "-N", chain)
        cleanup.callback(command, "iptables", "-X", chain)
        cleanup.callback(command, "iptables", "-F", chain)
        command("iptables", "-A", chain, "-j", "DROP")
        command("iptables", "-I", *hook)
        cleanup.callback(command, "iptables", "-D", *hook)

        # Both paths end in silent DROP. Only one sends a SYN onto the veth.
        recorders = [Recorder(name, f"tcp and dst host {destination}", evidence / f"{name}.pcap")
                     for name in ("any", interface)]
        outcomes = {}
        try:
            for recorder in recorders:
                recorder.start()
            for label, uid, port in (("routed_then_dropped", 6000, 39111), ("filtered", 5102, 39112)):
                outcomes[label] = command(sys.executable, "-c", """
import os, socket, sys
os.setgroups([])
os.setgid(int(sys.argv[1]))
os.setuid(int(sys.argv[1]))
with socket.socket() as connection:
    connection.settimeout(0.8)
    try:
        connection.connect((sys.argv[2], int(sys.argv[3])))
    except TimeoutError:
        print("TimeoutError")
    else:
        sys.exit("unexpected connection success")
""", str(uid), destination, str(port)).strip()
            time.sleep(0.4)
        finally:
            decoded = stop_recorders(recorders)

        counts = [{"interface": recorder.interface,
                   "routed_syns": classify(packets, destination, 39111),
                   "filtered_syns": classify(packets, destination, 39112)}
                  for recorder, packets in zip(recorders, decoded)]
        dropped = int(command("iptables", "-L", chain, "-n", "-v", "-x").splitlines()[2].split()[0])
        if (set(outcomes.values()) != {"TimeoutError"} or len(counts) != 2 or dropped < 1
                or any(row["routed_syns"] < 1 or row["filtered_syns"] != 0 for row in counts)):
            raise RuntimeError("timeout/capture discrimination controls failed")
        (evidence / "result.json").write_text(json.dumps(
            {"outcomes": outcomes, "captures": counts, "owner_drop_packets": dropped}, indent=2) + "\n")

    print(f"PASS: both paths timed out; captures distinguish emitted from filtered SYNs ({evidence})")


if __name__ == "__main__":
    main()
