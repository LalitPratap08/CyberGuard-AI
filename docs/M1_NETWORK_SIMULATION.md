# M1: Network & Simulation Engine Documentation

## 1. Responsibility & Scope
The **M1 Network & Simulation Engine** (`src/cyberguard/network`) is responsible for building, managing, and maintaining the in-memory simulated cyber-network environment for **CyberGuard-AI**.

> [!IMPORTANT]
> **Safety & Isolation Guarantee**: M1 operates **strictly inside in-memory data structures and graph models**. It does **NOT** send network packets, execute OS firewall commands, scan real IP addresses, or interact with physical machines.

---

## 2. Architecture Overview

```
                      +-----------------------------------+
                      |     NetworkSimulationEngine       |
                      +-----------------+-----------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
  +--------------v---------------+              +--------------v---------------+
  |   NetworkTopologyManager     |              |     SimulationEventBus       |
  |     (NetworkX Graph)         |              |   (Telemetry Log & Sub)      |
  +--------------+---------------+              +--------------+---------------+
                 |                                             |
  +--------------v---------------+              +--------------v---------------+
  |        SimulatedHost         |              |       SimulationEvent        |
  | (ONLINE / ISOLATED / OFFLINE)|              |  (PORT_SCAN / ISOLATION etc) |
  +------------------------------+              +------------------------------+
```

M1 consists of 4 main components:
- **`SimulatedHost` (`models.py`)**: Pydantic v2 data model representing machine state, open ports, IP, status, and risk level.
- **`NetworkTopologyManager` (`topology.py`)**: Graph structure powered by NetworkX managing network nodes, links, and path reachability.
- **`SimulationEventBus` (`events.py`)**: Event recording, subscriber notification, and history log retrieval.
- **`NetworkSimulationEngine` (`engine.py`)**: Unified API class consumed by M2, M3, M4, M5.

---

## 3. Core Data Schemas

### 3.1 SimulatedHost
```python
class SimulatedHost(BaseModel):
    host_id: str           # Unique identifier (e.g. 'web-server')
    hostname: str          # Display name (e.g. 'WEB-SERVER')
    simulated_ip: str      # Simulated IP (e.g. '192.168.1.20')
    status: HostStatus     # ONLINE | OFFLINE | ISOLATED
    open_ports: List[int]  # List of open TCP/UDP ports (e.g. [80, 443, 22])
    risk_level: RiskLevel  # LOW | MEDIUM | HIGH | CRITICAL
    connected_hosts: List[str] # Connected neighbor host_ids
    services: Dict[int, str]   # Port to service mapping {80: "HTTP", 22: "SSH"}
    subnet: Optional[str]      # Subnet CIDR / label
    metadata: Dict[str, Any]   # Custom properties
```

### 3.2 SimulationEvent
```python
class SimulationEvent(BaseModel):
    event_id: str          # Auto-generated UUID
    timestamp: str         # ISO 8601 UTC timestamp
    source_host: str       # Origin host_id
    target_host: str       # Destination host_id
    action: str            # Event action identifier (e.g. ACTION_PORT_SCAN)
    success: bool          # Simulation outcome
    metadata: Dict[str, Any] # Event payload data
```

---

## 4. Default Demo Topology

M1 provides a baseline 5-host demo network preconfigured via `engine.load_demo_topology()`:

```
ROUTER (192.168.1.1)
├── PC-01 (192.168.1.10)
│   └── PC-02 (192.168.1.11)
└── WEB-SERVER (192.168.1.20)
    └── DATABASE-SERVER (192.168.1.30)
```

---

## 5. Integration Guide for Team Members

### 5.1 M2: AI Attacker Integration
M2 uses M1 to discover reachable targets and simulate attack actions.

```python
from cyberguard.network import NetworkSimulationEngine

engine = NetworkSimulationEngine(load_demo=True)

# 1. Select source and target
source = "pc-01"
target = "web-server"

# 2. Check if path is reachable
if engine.are_hosts_routable(source, target):
    # 3. Simulate port scan
    scan_event = engine.simulate_port_scan(source, target, ports_to_scan=[80, 443, 22])
    print("Discovered open ports:", scan_event.metadata["discovered_open_ports"])
```

### 5.2 M3: AI Defender & Detection Integration
M3 subscribes to event streams and inspects host state.

```python
from cyberguard.network import NetworkSimulationEngine, EventType

engine = NetworkSimulationEngine(load_demo=True)

# Subscribe to all simulation events
def on_telemetry(event):
    if event.action == EventType.ACTION_PORT_SCAN.value:
        print(f"[SIEM ALERT] Port scan detected from {event.source_host} -> {event.target_host}")

engine.subscribe_events(on_telemetry)

# Fetch recent event history for ML feature extraction
recent_events = engine.get_events(limit=50)
```

### 5.3 M4: Defense & Response Integration
M4 executes response controls like host isolation or risk escalation.

```python
from cyberguard.network import NetworkSimulationEngine, RiskLevel

engine = NetworkSimulationEngine(load_demo=True)

# Isolate compromised host
engine.isolate_host("web-server")

# Escalate risk level
engine.update_risk_level("web-server", RiskLevel.CRITICAL)

# Restore host when threat is resolved
engine.restore_host("web-server")
```

### 5.4 M5: Backend Gateway Integration
M5 exports complete topology snapshots and exposes REST/WebSocket APIs.

```python
from cyberguard.network import NetworkSimulationEngine

engine = NetworkSimulationEngine(load_demo=True)

# Export complete graph JSON snapshot for API response
snapshot = engine.get_complete_topology()
# Contains: node_count, edge_count, hosts, connections, adjacency
```

---

## 6. How to Run Unit Tests

To run the complete test suite:

```bash
# Activate virtual environment (if created)
source venv/bin/activate

# Run pytest with PYTHONPATH pointing to src
PYTHONPATH=src pytest -v
```

All 18 unit tests cover host models, graph topology, isolation states, event publishing, and edge cases.
