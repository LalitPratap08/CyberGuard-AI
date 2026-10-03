# CyberGuard-AI: AI-Powered Cyber Attack & Defense Simulation Platform

CyberGuard-AI is an isolated, simulated cyber-range environment designed for co-evolving AI-driven attackers (Red Team) and defenders (Blue Team).

## Module Architecture & Team Allocation

- **M1**: Network & Simulation Engine (`src/cyberguard/network`) - Virtual Hosts, Graph Topology, State Engine, Simulated Event Bus.
- **M2**: Attack Simulation (Red Team Agent & MITRE ATT&CK Scenarios)
- **M3**: Threat Detection & AI Defender (SIEM Rules, Anomaly Detection & Incident Responder)
- **M4**: Strategy & Policy Evolution (Multi-Agent Reinforcement Learning Loop)
- **M5**: Backend Gateway & API Orchestrator (FastAPI, WebSockets, DB Storage)
- **M6**: Visual Dashboard & Command Center UI (React, React Flow)

---

## Safety & Non-Exploitation Guarantee

This project operates **100% inside simulated in-memory state machines**.
- No real network scanning (no raw sockets, Nmap, or ARP probes).
- No actual packet transmission or hardware network modification.
- No interaction with real IP addresses, external hosts, or system firewalls.
