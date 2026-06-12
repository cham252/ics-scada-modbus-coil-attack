# ICS/SCADA Security Lab: Modbus Coil Write Attack
### OTForge Tutorial 01 | UTSA ICS Security / NSA CyberSkills2Work | June 2026

[![Completed](https://img.shields.io/badge/Status-Completed-brightgreen)](https://cham252.github.io)
[![Platform](https://img.shields.io/badge/Platform-OTForge-blue)](https://cham252.github.io)
[![Protocol](https://img.shields.io/badge/Protocol-Modbus%20TCP-orange)](https://cham252.github.io)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20for%20ICS-red)](https://attack.mitre.org/matrices/ics/)
[![DCWF](https://img.shields.io/badge/DCWF-Work%20Role%20212-purple)](https://cham252.github.io)

---

## Overview

Full-cycle OT attack simulation against a water treatment facility PLC, from passive OSINT reconnaissance through physical consequence and remediation. The scenario mirrors the **2021 Oldsmar, Florida water treatment incident** — an attacker modified a process setpoint via remote access using the same underlying vulnerability: Modbus TCP carries no authentication.

The target: Meridian Process Controls, a simulated industrial company. A network misconfiguration exposes the OT network directly to the attacker. The attack closes the outlet valve via a single Modbus coil write. The inlet pump keeps running. The tank overflows.

All systems run in Docker containers via OTForge. No real systems were accessed.

---

## Environment

| Component | Details |
|-----------|---------|
| Platform | OTForge (Docker-based ICS simulation) |
| Attack machine | Kali Linux — 10.200.60.10 |
| PLC | OpenPLC at 10.200.10.10:502 |
| OT subnet | 10.200.10.0/24 |
| Protocol | Modbus TCP (FC05 coil write) |
| Detection | Suricata + Zeek + Grafana |
| Tank overflow threshold | 1000 cm (10.00 m) |

---

## Attack Chain

```
OSINT → DNS Enumeration → Nmap Scan → Modbus Baseline Read → Coil Write → Tank Overflow → Remediation
```

---

## Step 1 — OSINT: Discover the Target

Before touching any OT system, I fetched the company's public website and filtered the HTML for developer comments. The site had a TODO note left in production containing the full OT network map, Modbus port, and admin credentials.

```bash
curl -s http://10.200.50.10/ | grep -iE 'TODO|subnet|admin|password' | head -20
```

**Result:** Developer comment exposed OT subnet (10.200.10.0/24), port 502, and credentials (admin / Meridian2024!) — zero packets to the OT network.

![Appendix A — OSINT](screenshots/appendix-a-osint.png)
*Appendix A: Developer HTML comment reveals OT subnet, Modbus port, and plaintext credentials.*

---

## Step 2 — Remote Access Page

Fetched `/remote.html` with verbose headers. The `Server:` header returned nginx/1.27.5. An HTML comment block confirmed all three internal network ranges.

```bash
curl -sv http://10.200.50.10/remote.html 2>&1 | head -60
```

**Result:** Server nginx/1.27.5. OT (10.200.10.0/24), Control Center (10.200.20.0/24), Plant DMZ (10.200.30.0/24) confirmed in HTML comments.

![Appendix B — Remote HTML](screenshots/appendix-b-remote-curl.png)
*Appendix B: curl verbose output showing server version and network details from HTML comments.*

---

## Step 3 — DNS Enumeration

Queried the authoritative DNS server for ICS-relevant subdomains. Only `www` and `remote` resolved. OT/SCADA/PLC/HMI subdomains returned empty — but that absence did not mean those systems were unreachable.

```bash
for sub in www remote vpn mail ot scada plc hmi; do echo -n "$sub: "; dig +short @10.200.50.11 $sub.meridian-process.com; done
```

**Result:** www and remote resolve to 10.200.50.10. OT subdomains return no records. The firewall misconfiguration makes the OT subnet directly accessible regardless.

![Appendix C — DNS](screenshots/appendix-c-dns.png)
*Appendix C: DNS enumeration. OT-related subdomains return empty but systems remain reachable due to missing firewall rules.*

---

## Step 4 — Network Scan: Discover OT Devices

Scanned the OT subnet for ICS protocol ports. Used `-T4` with a 2-second host timeout to limit packet rates and avoid crashing PLCs.

```bash
nmap -T4 -Pn --host-timeout 2s -p 502,20000,4840,102,2404 --open 10.200.10.0/24
```

**Ports scanned:** 502 (Modbus TCP), 20000 (DNP3), 4840 (OPC-UA), 102 (S7comm), 2404 (IEC 60870-5-104)

**Result:** PLC at 10.200.10.10 with `502/tcp open mbap`. No authentication required to connect.

![Appendix D — Nmap](screenshots/appendix-d-nmap.png)
*Appendix D: Nmap scan results. Three hosts respond with port 502 open including primary PLC at 10.200.10.10.*

---

## Step 5 — Read Modbus Registers (Baseline)

Documented original coil and register states before making any changes. Mandatory in real engagements — you need the baseline to prove what the attack changed and to restore it cleanly.

```bash
python3 /root/Desktop/Attack_Scripts/read_coils.py
```

**Baseline state:**
- Coil 0 `pump_run` = ON (TRUE) — inlet pump running
- Coil 1 `valve_open` = ON (TRUE) — outlet valve open
- Coil 2 `emrg_stop` = OFF (FALSE) — normal operation
- HR0 `tank_level` = 500 cm (5.00 m) — 50% capacity
- HR1 `inlet_flow` = 120 L/min
- HR2 `outlet_flow` = 120 L/min
- System balanced: inflow equals outflow

![Appendix E — Baseline](screenshots/appendix-e-baseline.png)
*Appendix E: read_coils.py output. All coils documented. Tank at 500 cm, flows balanced at 120 L/min.*

---

## Step 6 — Execute the Attack: Write Modbus Coil

Set Coil 1 (`valve_open`) to FALSE via FC05. The PLC acknowledged with no authentication prompt, no error, no delay. Outlet valve closed. Inlet pump kept running at 120 L/min. Water accumulated with no path out. Tank reached 1000 cm — overflow — in under 5 minutes.

```bash
python3 /root/Desktop/Attack_Scripts/write_coil.py
```

**This is the 2021 Oldsmar technique applied to an outlet valve.** The underlying vulnerability is identical: Modbus TCP carries no authentication. Any host that can reach port 502 can write any register on any PLC without credentials.

**Result:** Script prints `ATTACK COMPLETE`. FC05 write ACK'd instantly. Tank hit 1000 cm (100%) OVERFLOW.

![Appendix F — Attack](screenshots/appendix-f-attack.png)
*Appendix F: write_coil.py output. FC05 acknowledged. Tank reached overflow threshold. No authentication required.*

---

## Step 7 — Observe the Attack in the Monitor

Switched to the defender perspective. OTForge Monitor panel shows live Suricata and Zeek alerts. Grafana ICS Lab Overview dashboard aggregates all ICS alert data.

![Appendix G — Monitor Panel](screenshots/appendix-g-monitor.png)
*Appendix G: OTForge Monitor panel (Zeek tab). 146 log entries. Canvas shows Water Tank in overflow, outlet valve pipe red.*

**Suricata alerts fired:**
- `ICS-SIM Modbus port scan detected` — Step 4 nmap scan
- `ICS-SIM Aggressive Modbus connection attempt` — Step 6 coil write

**Zeek logged:** Modbus connection records showing source 10.200.60.10 writing to 10.200.10.10:502 with FC05 function code.

![Appendix H — Grafana](screenshots/appendix-h-grafana.png)
*Appendix H: Grafana ICS Lab Overview. 530 total alerts. Three categories: Detection of Network Scan, Attempted Information Leak, Generic Protocol Command Decode.*

---

## Step 8 — Explore the OpenPLC IDE

Accessed OpenPLC IDE at `http://localhost:18080` (credentials: openplc/openplc). The Monitoring tab refreshes every 500ms and shows the PLC's actual internal state — the ground truth confirming the coil write succeeded.

**State during attack:**
- `pump_run` — GREEN TRUE (never touched)
- `valve_open` — RED FALSE (closed by attack)
- `tank_level` — 1000 (overflow)
- `outlet_flow` — 0 (no drainage)
- `inlet_flow` — 120 (still flowing in)

![Appendix I — OpenPLC During Attack](screenshots/appendix-i-openplc-attack.png)
*Appendix I: OpenPLC Monitoring during attack. valve_open shows red FALSE. tank_level at maximum 1000. outlet_flow = 0.*

---

## Step 9 — Restore Normal Operations

The attack changed exactly one coil. The fix changes exactly one coil.

```bash
python3 /root/Desktop/Attack_Scripts/write_coil.py --restore
```

**Result:** Coil 1 written to TRUE. Outlet valve reopened. Outlet flow returned to 120 L/min. Tank level stabilized. Inlet pump untouched.

![Appendix J — Restore Output](screenshots/appendix-j-restore.png)
*Appendix J: --restore command output. FC05 write ACK'd. System confirms balanced flow.*

![Appendix K — OpenPLC Post-Restore](screenshots/appendix-k-openplc-restored.png)
*Appendix K: OpenPLC Monitoring after restore. pump_run and valve_open both GREEN TRUE. outlet_flow = 120, matching inlet.*

---

## Vulnerabilities Exploited

### 1. OSINT Exposure
Developer HTML comments contained the OT subnet, Modbus port, and admin credentials in a public-facing website. A complete network map was assembled without touching the OT network.

**Prevention:** Strip HTML comments before production deployment. Implement secrets scanning (GitLeaks, TruffleHog) in CI/CD pipeline.

### 2. Unauthenticated Modbus TCP
Modbus TCP was designed for isolated serial networks with no authentication requirement. Any host reaching port 502 can read or write any register without credentials.

**Prevention:** Modbus/TLS or application-layer authentication proxy. Firewall rules restricting port 502 to engineering workstation IPs only.

### 3. Missing Network Segmentation
The attacker machine (Internet DMZ) reached the OT subnet with no firewall rule blocking cross-zone Modbus traffic. DNS absence for OT subdomains created false isolation.

**Prevention:** IEC 62443 zone-and-conduit model. Deny port 502 from all non-OT zones. Network monitoring for unexpected cross-zone traffic.

---

## Detection Summary

| Tool | Alert | Attack Phase |
|------|-------|-------------|
| Suricata | ICS-SIM Modbus port scan detected | Step 4 — Nmap |
| Suricata | ICS-SIM Aggressive Modbus connection attempt | Step 6 — Coil write |
| Zeek | Modbus connection record (source: attacker, dest: PLC:502) | Step 6 — Coil write |
| Grafana | 530 total alerts, policy-violation spike at attack time | Full session |
| OpenPLC | valve_open=FALSE, tank_level=1000, outlet_flow=0 | Step 6 — Physical consequence |

---

## MITRE ATT&CK for ICS

| Technique | ID | Phase |
|-----------|-----|-------|
| Gather Victim Host Information | T0888 | OSINT via HTML source |
| Network Scanning / Discovery | T0840 | Nmap port scan |
| Point & Tag Identification | T0861 | Modbus FC01 baseline read |
| Unauthorized Command Message | T0855 | FC05 coil write |
| Manipulation of Control | T0831 | Tank overflow physical consequence |

---

## Repository Structure

```
/
├── README.md               — This file
├── screenshots/            — All 11 lab appendix screenshots
│   ├── appendix-a-osint.png
│   ├── appendix-b-remote-curl.png
│   ├── appendix-c-dns.png
│   ├── appendix-d-nmap.png
│   ├── appendix-e-baseline.png
│   ├── appendix-f-attack.png
│   ├── appendix-g-monitor.png
│   ├── appendix-h-grafana.png
│   ├── appendix-i-openplc-attack.png
│   ├── appendix-j-restore.png
│   └── appendix-k-openplc-restored.png
└── report/
    └── lab-report.md       — Full written report (2-3 pages)
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| curl | OSINT web scraping and header capture |
| dig | DNS enumeration |
| nmap | Network and port scanning |
| Python / pymodbus | Modbus register read/write scripts |
| OpenPLC IDE | PLC program and variable monitoring |
| Suricata | Signature-based IDS |
| Zeek | Network protocol analysis |
| Grafana | SOC dashboard |
| OTForge | ICS simulation platform |
| Kali Linux | Attacker machine |

---

## About

Christopher Ham | Durham, NC
Retired law enforcement (25 years). Cybersecurity professional.

- Portfolio: [cham252.github.io](https://cham252.github.io)
- Blog: [Badge to Blue Screen](https://medium.com/@christopher.ham)
- LinkedIn: [linkedin.com/in/christopher-ham-cyber](https://linkedin.com/in/christopher-ham-cyber)

Certifications: Security+, SecurityX, CISM, CySA+, CEH, ECIH EC-Council Incident Handler, CTIA EC-Council Threat Intelligence Analyst, Splunk Core Certified User, NCAE-C OSINT Specialist Investigator, CCNA, OSMOSIS OSC

Completed as part of the UTSA ICS Security course (CyberSkills2Work / NSA, 2026). Supports the UL Digital Transformation Center Cyber Defense Forensics Analyst pathway (DCWF Work Role 212).

---

*All work performed in a controlled lab environment. No real systems were accessed.*
