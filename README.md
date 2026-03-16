# kvm4 Agent Monitor + Security Stack

Full monitoring, security detection, and DNS filtering stack for Linux nodes.
Born from a real incident: a heartbeat that generated 832 million characters of logs and killed a node.

## What's In Here

```
├── run-all.sh                    # Main runner (5-min systemd timer)
├── agent-cli.py                  # CLI: agent status/scan/audit/capture/findings
├── node.json                     # Node config (thresholds, extensions, identity)
│
├── plugins/                      # → Prometheus metrics via textfile collector
│   ├── overflow-metrics.sh       #   21 metrics (CPU, mem, disk, WG, sysdig canary)
│   ├── security-metrics.sh       #   7 metrics (ports, SUID, auth, zombies, iptables)
│   └── pihole-metrics.sh         #   8 metrics (queries, blocked, cached, gravity)
│
├── local/                        # → spool JSON (structured health data)
│   ├── sovereign-docs.sh         #   Service health, pages, builds, WAL
│   ├── docker-health.sh          #   Container states, top memory
│   ├── wireguard.sh              #   Peer handshakes, stale detection
│   └── security-audit.sh         #   SSH config, failed auth, world-writable
│
├── extensions/                   # → spool + Prometheus
│   ├── mitre-detect.sh           #   20 MITRE ATT&CK technique detections
│   └── deep-audit.sh             #   Daily: SUID drift, rootkits, crypto mining
│
├── pihole/                       # DNS filtering stack
│   ├── docker-compose.yml        #   Pi-hole + Unbound containers
│   └── unbound.conf              #   DNS-over-TLS to Quad9, DNSSEC
│
├── grafana-dashboard.json        # "Overflow Detection + DNS" (16 panels)
├── journald-size-limit.conf      # 500M journal cap (DEPLOY FIRST)
│
├── agent-monitor.service         # systemd units
├── agent-monitor.timer           #   5-min collection timer
├── agent-monitor-daily.service   #   deep audit
├── agent-monitor-daily.timer     #   daily at 3am
├── sysdig-metrics.service        #   (legacy, replaced by agent-monitor)
└── sysdig-metrics.timer
```

## Quick Start

```bash
# 1. Cap journald (prevents overflow regardless of detection)
cp journald-size-limit.conf /etc/systemd/journald.conf.d/
systemctl restart systemd-journald

# 2. Install tools
apt install -y sysdig tshark

# 3. Deploy agent-monitor
mkdir -p /opt/agent-monitor/{plugins,local,extensions,bin}
mkdir -p /var/lib/agent-monitor/{cache,jobs,spool,state,captures}
mkdir -p /var/lib/node_exporter/textfile_collector
mkdir -p /etc/agent-monitor
cp plugins/* /opt/agent-monitor/plugins/
cp local/* /opt/agent-monitor/local/
cp extensions/* /opt/agent-monitor/extensions/
cp run-all.sh /opt/agent-monitor/
cp agent-cli.py /opt/agent-monitor/bin/agent
cp node.json /etc/agent-monitor/
chmod +x /opt/agent-monitor/**/*.sh /opt/agent-monitor/run-all.sh /opt/agent-monitor/bin/agent
ln -sf /opt/agent-monitor/bin/agent /usr/local/bin/agent

# 4. Edit node.json — change "kvm4" to your node name

# 5. Install systemd timers
cp agent-monitor.service agent-monitor.timer /etc/systemd/system/
cp agent-monitor-daily.service agent-monitor-daily.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now agent-monitor.timer agent-monitor-daily.timer

# 6. Add textfile collector to node-exporter
# volumes: - /var/lib/node_exporter/textfile_collector:/textfile:ro
# command: --collector.textfile.directory=/textfile

# 7. Deploy Pi-hole + Unbound
cd pihole && docker compose up -d
# Then point /etc/resolv.conf at 127.0.0.1

# 8. Import grafana-dashboard.json into Grafana

# 9. Test
agent status
agent scan
agent findings
agent capture --duration 10
```

## Agent CLI

```
agent status      Health at a glance
agent scan        Run all checks now
agent audit       Deep security audit
agent findings    MITRE + audit findings
agent capture     On-demand tshark packet capture + analysis
agent metrics     Raw Prometheus metrics
agent config      View/modify node config
agent log         Recent journal entries
```

## What This Detects

| Detection | How |
|-----------|-----|
| Log overflow | /var/log growth + sysdig write syscall count |
| CPU runaway | Top 5 processes by CPU% |
| Memory pressure | Top 5 by memory% |
| Container failure | Running/stopped/unhealthy/restarting counts |
| WireGuard peer down | Handshake age > 300s |
| SUID drift | Baseline comparison, new SUID binaries flagged |
| Hidden processes | /proc scan vs ps output |
| Crypto mining | Process names + mining pool port connections |
| Kernel misconfig | IP forwarding, SYN cookies, ASLR check |
| Credential access | MITRE T1003.008, T1552.003 |
| Persistence | MITRE T1053.003, T1543.002, T1546.004 |
| DNS filtering | Pi-hole block rate, query types, gravity size |

## Origin Story

vm100's heartbeat → STUN binding requests → coturn errno=98 → 70M log lines → 
832M characters → 3.4GB syslog → 100% CPU → dead node.

kvm4's Coolify DNS resolver → 15M log lines → 2.1GB syslog (caught and cleaned).

Both would have been detected within one 5-minute collection cycle with this stack.

**A healthy system is silent.** Any sustained write to /var/log = investigate immediately.

## License

MIT
