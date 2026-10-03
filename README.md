# CyberGuard-AI: AI-Powered Cyber Attack & Defense Simulation Platform

CyberGuard-AI is an isolated, simulated cyber-range environment designed for co-evolving AI-driven attackers (Red Team) and defenders (Blue Team).

---

## Safety & Non-Exploitation Guarantee

This project operates **100% inside simulated in-memory state machines**.
- No real network scanning (no raw sockets, Nmap, or ARP probes).
- No actual packet transmission or hardware network modification.
- No interaction with real IP addresses, external hosts, or system firewalls.

---

## Module Architecture & Team Allocation

- **M1**: Network & Simulation Engine (`src/cyberguard/network`) - Virtual Hosts, Graph Topology, State Engine, Simulated Event Bus. [M1 Documentation](docs/M1_NETWORK_SIMULATION.md)
- **M2**: Attack Simulation (Red Team Agent & MITRE ATT&CK Scenarios)
- **M3**: Threat Detection & AI Defender (SIEM Rules, Anomaly Detection & Incident Responder)
- **M4**: Strategy & Policy Evolution (Multi-Agent Reinforcement Learning Loop)
- **M5**: Backend Gateway & API Orchestrator (FastAPI, WebSockets, DB Storage)
- **M6**: Visual Dashboard & Command Center UI (React, React Flow)

---

## Quickstart & Setup

### Prerequisites
- Python 3.10+
- Dependencies: `networkx`, `pydantic`, `pytest`

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running Unit Tests

```bash
PYTHONPATH=src pytest -v
```

---

## Quick Code Example (M1 Engine)

```python
from cyberguard.network import NetworkSimulationEngine, HostStatus, RiskLevel

# Initialize engine with baseline 5-host demo network
engine = NetworkSimulationEngine(load_demo=True)

# Inspect network topology snapshot
topology = engine.get_complete_topology()
print(f"Total Hosts: {topology['node_count']}, Total Links: {topology['edge_count']}")

# Simulate an attack action (Port Scan)
event = engine.simulate_port_scan("pc-01", "web-server", ports_to_scan=[80, 443, 22])
print(f"Discovered Ports on WEB-SERVER: {event.metadata['discovered_open_ports']}")

# Perform host isolation (M4 Response)
engine.isolate_host("web-server")
assert engine.get_host("web-server").status == HostStatus.ISOLATED
```
