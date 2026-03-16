#!/usr/bin/env python3
"""agent — CLI for kvm4 agent-monitor.

Usage:
    agent status                  Show current health status
    agent scan                    Run all checks now
    agent audit                   Run deep security audit
    agent info [--defs|--node]    Show system/node info
    agent spool [name]            View spool data (JSON)
    agent metrics                 Show current Prometheus metrics
    agent config [key] [value]    View or modify node config
    agent log [--tail N]          Show recent agent-monitor logs
    agent heartbeat               Trigger immediate collection cycle
    agent findings                Show security findings (MITRE + audit)
    agent capture [opts]          On-demand packet capture + analysis
    agent help                    Show this help

Capture options:
    agent capture --duration 60                 Capture 60s on all interfaces
    agent capture --duration 30 -i eth0         Capture on specific interface
    agent capture --duration 60 --filter "port 443"   BPF filter
    agent capture --analyze /path/to/file.pcap  Analyze existing capture
    agent capture --summary                     Summarize last capture
    agent capture --clean                       Delete all capture files
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

SPOOL_DIR = Path("/var/lib/agent-monitor/spool")
STATE_DIR = Path("/var/lib/agent-monitor/state")
CACHE_DIR = Path("/var/lib/agent-monitor/cache")
METRICS_DIR = Path("/var/lib/node_exporter/textfile_collector")
CONFIG_FILE = Path("/etc/agent-monitor/node.json")
PLUGINS_DIR = Path("/opt/agent-monitor/plugins")
LOCAL_DIR = Path("/opt/agent-monitor/local")
EXT_DIR = Path("/opt/agent-monitor/extensions")
RUNNER = Path("/opt/agent-monitor/run-all.sh")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def load_spool(name: str | None = None) -> dict:
    result = {}
    for f in sorted(SPOOL_DIR.glob("*.json")):
        if name and f.stem != name:
            continue
        try:
            result[f.stem] = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            result[f.stem] = {"error": "unreadable"}
    return result


def cmd_status():
    """Show current health status — one-line summary per check."""
    spool = load_spool()
    last_run = {}
    lr_path = STATE_DIR / "last-run.json"
    if lr_path.exists():
        last_run = json.loads(lr_path.read_text())

    ago = ""
    if last_run.get("last_run"):
        seconds = int(time.time() - last_run["last_run"])
        ago = f"{seconds}s ago"

    print(f"agent-monitor | last run: {ago} | "
          f"duration: {last_run.get('duration_sec', '?')}s | "
          f"errors: {last_run.get('errors', '?')}")
    print(f"plugins: {last_run.get('plugins', '?')} | "
          f"local: {last_run.get('local_checks', '?')}")
    print()

    for name, data in spool.items():
        if isinstance(data, dict) and "error" not in data:
            svc = data.get("service", name)
            ts = data.get("ts", 0)
            age = int(time.time() - ts) if ts else 0

            # Build status line based on service type
            if svc == "sovereign-docs":
                status = data.get("status", "?")
                pages = data.get("pages", "?")
                builds = data.get("builds", "?")
                print(f"  [{status}] {svc}: {pages} pages, {builds} builds, "
                      f"WAL {data.get('wal_bytes', 0) // 1024}KB")
            elif svc == "docker":
                r = data.get("running", 0)
                s = data.get("stopped", 0)
                u = data.get("unhealthy", 0)
                state = "OK" if u == 0 and s == 0 else "WARN"
                print(f"  [{state}] {svc}: {r} running, {s} stopped, {u} unhealthy")
            elif svc == "wireguard":
                peers = data.get("peers", [])
                stale = sum(1 for p in peers if p.get("stale"))
                state = "OK" if stale == 0 else "WARN"
                print(f"  [{state}] {svc}: {len(peers)} peers, {stale} stale")
            elif svc == "security-audit":
                ports = data.get("listening_ports", "?")
                failed = data.get("failed_auth_today", 0)
                ssh_pw = data.get("ssh_password_auth", "?")
                print(f"  [INFO] {svc}: {ports} ports, {failed} failed auth, "
                      f"ssh_pw={ssh_pw}")
            elif svc == "mitre-detect":
                total = data.get("findings_count", 0)
                crit = data.get("critical", 0)
                state = "ALERT" if crit > 0 else "OK" if total == 0 else "WARN"
                print(f"  [{state}] {svc}: {total} findings ({crit} critical)")
            elif svc == "deep-audit":
                total = data.get("findings_count", 0)
                crit = data.get("critical", 0)
                suid = data.get("suid_count", "?")
                print(f"  [{'ALERT' if crit > 0 else 'OK'}] {svc}: "
                      f"{total} findings, {suid} SUID binaries")
            else:
                print(f"  [---] {svc}: {json.dumps(data)[:80]}")
        else:
            print(f"  [ERR] {name}: {data}")


def cmd_scan():
    """Run all checks now."""
    print("Running all plugins + local checks...")
    result = subprocess.run([str(RUNNER)], capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        last_run = json.loads((STATE_DIR / "last-run.json").read_text())
        print(f"Done in {last_run['duration_sec']}s, {last_run['errors']} errors")
    else:
        print(f"Failed: {result.stderr[:200]}")
    cmd_status()


def cmd_audit():
    """Run deep security audit."""
    audit_script = EXT_DIR / "deep-audit.sh"
    if not audit_script.exists():
        print("deep-audit.sh not found")
        return
    print("Running deep audit...")
    result = subprocess.run([str(audit_script)], capture_output=True, text=True, timeout=300)
    if result.returncode == 0:
        data = json.loads((SPOOL_DIR / "deep-audit.json").read_text())
        print(f"Findings: {data['findings_count']} "
              f"({data['critical']} critical, {data['high']} high)")
        for f in data.get("findings", []):
            sev = f["severity"].upper()
            print(f"  [{sev}] {f['category']}: {f['description']}")
        if data["findings_count"] == 0:
            print("  All clear.")
    else:
        print(f"Failed: {result.stderr[:200]}")


def cmd_info(args):
    """Show system/node info."""
    if "--node" in args or not args:
        config = load_config()
        print(json.dumps(config, indent=2))
    if "--defs" in args or not args:
        print(f"\nKernel: {os.uname().release}")
        print(f"Hostname: {os.uname().nodename}")
        print(f"Uptime: {open('/proc/uptime').read().split()[0]}s")
        # sysdig version
        r = subprocess.run(["sysdig", "--version"], capture_output=True, text=True)
        print(f"Sysdig: {r.stdout.strip()}")
        # Docker version
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        print(f"Docker: {r.stdout.strip()}")


def cmd_spool(args):
    """View spool data."""
    name = args[0] if args else None
    data = load_spool(name)
    print(json.dumps(data, indent=2))


def cmd_metrics():
    """Show current Prometheus metrics."""
    for f in sorted(METRICS_DIR.glob("*.prom")):
        for line in f.read_text().splitlines():
            if line and not line.startswith("#"):
                print(line)


def cmd_config(args):
    """View or modify node config."""
    config = load_config()
    if not args:
        print(json.dumps(config, indent=2))
        return

    # Navigate nested keys with dot notation: "thresholds.cpu_warn"
    keys = args[0].split(".")
    if len(args) == 1:
        # Read
        val = config
        for k in keys:
            val = val.get(k, "NOT FOUND") if isinstance(val, dict) else "NOT FOUND"
        print(json.dumps(val, indent=2) if isinstance(val, (dict, list)) else val)
    elif len(args) == 2:
        # Write
        val = args[1]
        # Auto-type: bool, int, float
        if val.lower() in ("true", "false"):
            val = val.lower() == "true"
        elif val.isdigit():
            val = int(val)
        else:
            try:
                val = float(val)
            except ValueError:
                pass

        obj = config
        for k in keys[:-1]:
            obj = obj.setdefault(k, {})
        obj[keys[-1]] = val
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
        print(f"Set {args[0]} = {val}")


def cmd_log(args):
    """Show recent agent-monitor logs."""
    n = 20
    if "--tail" in args:
        idx = args.index("--tail")
        if idx + 1 < len(args):
            n = int(args[idx + 1])
    result = subprocess.run(
        ["journalctl", "-u", "agent-monitor", "-u", "agent-monitor-daily",
         "--no-pager", "-n", str(n)],
        capture_output=True, text=True
    )
    print(result.stdout)


def cmd_findings():
    """Show all security findings across MITRE + deep-audit."""
    for name in ["mitre-detect", "deep-audit"]:
        path = SPOOL_DIR / f"{name}.json"
        if path.exists():
            data = json.loads(path.read_text())
            findings = data.get("findings", [])
            if findings:
                print(f"=== {name} ({len(findings)} findings) ===")
                for f in findings:
                    sev = f["severity"].upper()
                    print(f"  [{sev}] {f.get('technique', f.get('category', '?'))}: "
                          f"{f['description']}")
            else:
                print(f"=== {name}: clean ===")
        else:
            print(f"=== {name}: no data (run 'agent scan' first) ===")


def cmd_heartbeat():
    """Trigger immediate collection."""
    print("Triggering heartbeat...")
    cmd_scan()


CAPTURE_DIR = Path("/var/lib/agent-monitor/captures")


def cmd_capture(args):
    """On-demand packet capture + analysis. Spin up, capture, stop, analyze, delete."""
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    # Parse args
    duration = 30
    interface = "any"
    bpf_filter = ""
    analyze_file = None

    if "--clean" in args:
        import glob
        files = list(CAPTURE_DIR.glob("*.pcap"))
        for f in files:
            f.unlink()
        print(f"Deleted {len(files)} capture files")
        return

    if "--summary" in args:
        _capture_summary_last()
        return

    if "--analyze" in args:
        idx = args.index("--analyze")
        if idx + 1 < len(args):
            analyze_file = args[idx + 1]
        if analyze_file:
            _capture_analyze(Path(analyze_file))
        return

    if "--duration" in args:
        idx = args.index("--duration")
        if idx + 1 < len(args):
            duration = int(args[idx + 1])

    if "-i" in args:
        idx = args.index("-i")
        if idx + 1 < len(args):
            interface = args[idx + 1]

    if "--filter" in args:
        idx = args.index("--filter")
        if idx + 1 < len(args):
            bpf_filter = args[idx + 1]

    # Safety: max 5 min capture, max 100MB
    if duration > 300:
        print("Cap: max 300 seconds (5 minutes). Use --duration 300.")
        return

    ts = time.strftime("%Y%m%d-%H%M%S")
    pcap_file = CAPTURE_DIR / f"capture-{ts}.pcap"

    print(f"Capturing on {interface} for {duration}s...")
    if bpf_filter:
        print(f"Filter: {bpf_filter}")
    print(f"Output: {pcap_file}")
    print()

    # Use tshark if available, fall back to tcpdump
    tshark = subprocess.run(["which", "tshark"], capture_output=True).returncode == 0

    if tshark:
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}",
               "-a", "filesize:102400",  # 100MB cap
               "-w", str(pcap_file)]
        if bpf_filter:
            cmd.extend(["-f", bpf_filter])
    else:
        cmd = ["tcpdump", "-i", interface, "-G", str(duration), "-W", "1",
               "-s", "0", "-w", str(pcap_file)]
        if bpf_filter:
            cmd.append(bpf_filter)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=duration + 10)
        size = pcap_file.stat().st_size if pcap_file.exists() else 0
        print(f"\nCapture complete: {size // 1024}KB")

        # Auto-analyze
        _capture_analyze(pcap_file)

    except subprocess.TimeoutExpired:
        print("\nCapture timed out (killed)")
    except KeyboardInterrupt:
        print("\nCapture interrupted")


def _capture_analyze(pcap_file: Path):
    """Analyze a pcap file with tshark."""
    if not pcap_file.exists():
        print(f"File not found: {pcap_file}")
        return

    size_kb = pcap_file.stat().st_size // 1024
    print(f"\n{'='*60}")
    print(f"Analyzing: {pcap_file.name} ({size_kb}KB)")
    print(f"{'='*60}")

    tshark = subprocess.run(["which", "tshark"], capture_output=True).returncode == 0
    if not tshark:
        # Fallback: basic tcpdump analysis
        r = subprocess.run(["tcpdump", "-nn", "-r", str(pcap_file), "-c", "20"],
                           capture_output=True, text=True)
        print(r.stdout)
        return

    # Protocol hierarchy
    print("\n--- Protocol Hierarchy ---")
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-q", "-z", "io,phs"],
                       capture_output=True, text=True, timeout=30)
    print(r.stdout[:1000] if r.stdout else "(empty)")

    # Conversation summary
    print("--- Top Conversations ---")
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-q",
                        "-z", "conv,ip"],
                       capture_output=True, text=True, timeout=30)
    lines = r.stdout.strip().split("\n")
    for line in lines[:15]:
        print(line)

    # DNS queries
    print("\n--- DNS Queries ---")
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-Y", "dns.qry.name",
                        "-T", "fields", "-e", "dns.qry.name"],
                       capture_output=True, text=True, timeout=30)
    if r.stdout.strip():
        # Count unique queries
        queries = {}
        for q in r.stdout.strip().split("\n"):
            q = q.strip()
            if q:
                queries[q] = queries.get(q, 0) + 1
        for q, c in sorted(queries.items(), key=lambda x: -x[1])[:10]:
            print(f"  {c:4d}  {q}")
    else:
        print("  (none)")

    # HTTP hosts
    print("\n--- HTTP/TLS Hosts ---")
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-Y",
                        "http.host or tls.handshake.extensions_server_name",
                        "-T", "fields",
                        "-e", "http.host",
                        "-e", "tls.handshake.extensions_server_name"],
                       capture_output=True, text=True, timeout=30)
    if r.stdout.strip():
        hosts = {}
        for line in r.stdout.strip().split("\n"):
            h = line.strip().replace("\t", " ").strip()
            if h:
                hosts[h] = hosts.get(h, 0) + 1
        for h, c in sorted(hosts.items(), key=lambda x: -x[1])[:10]:
            print(f"  {c:4d}  {h}")
    else:
        print("  (none)")

    # Suspicious indicators
    print("\n--- Suspicious Indicators ---")
    suspicious = 0

    # Check for common C2 ports
    for port in [4444, 1337, 31337, 6667, 8888]:
        r = subprocess.run(["tshark", "-r", str(pcap_file), "-Y",
                            f"tcp.port == {port}", "-c", "1"],
                           capture_output=True, text=True, timeout=10)
        if r.stdout.strip():
            print(f"  [!] Traffic on suspicious port {port}")
            suspicious += 1

    # Check for large DNS responses (tunneling indicator)
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-Y",
                        "dns && frame.len > 512", "-c", "5"],
                       capture_output=True, text=True, timeout=10)
    if r.stdout.strip():
        print(f"  [!] Large DNS packets detected (possible tunneling)")
        suspicious += 1

    if suspicious == 0:
        print("  None detected")

    # Packet count
    r = subprocess.run(["tshark", "-r", str(pcap_file), "-q", "-z", "io,stat,0"],
                       capture_output=True, text=True, timeout=10)
    print(f"\n--- Summary ---")
    for line in r.stdout.strip().split("\n"):
        if "Frames" in line or "Bytes" in line or "|" in line:
            print(f"  {line.strip()}")


def _capture_summary_last():
    """Summarize the most recent capture."""
    captures = sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda f: f.stat().st_mtime)
    if not captures:
        print("No captures found. Run 'agent capture --duration 30' first.")
        return
    _capture_analyze(captures[-1])


def main():
    args = sys.argv[1:]
    if not args or args[0] == "help":
        print(__doc__)
        return

    cmd = args[0]
    rest = args[1:]

    commands = {
        "status": lambda: cmd_status(),
        "scan": lambda: cmd_scan(),
        "audit": lambda: cmd_audit(),
        "info": lambda: cmd_info(rest),
        "spool": lambda: cmd_spool(rest),
        "metrics": lambda: cmd_metrics(),
        "config": lambda: cmd_config(rest),
        "log": lambda: cmd_log(rest),
        "findings": lambda: cmd_findings(),
        "heartbeat": lambda: cmd_heartbeat(),
        "capture": lambda: cmd_capture(rest),
    }

    if cmd in commands:
        commands[cmd]()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
