"""
M1 Topology Presets & Initial Demo Environment.

Provides predefined standard simulated network topologies for instant use
by M2 (Attacker), M3 (Defender), M4 (Response), M5 (Backend).
"""

from cyberguard.network.models import HostStatus, RiskLevel, SimulatedHost


def create_demo_hosts() -> list[SimulatedHost]:
    """
    Create the standard default list of 5 simulated hosts:
    - ROUTER (192.168.1.1)
    - PC-01 (192.168.1.10)
    - PC-02 (192.168.1.11)
    - WEB-SERVER (192.168.1.20)
    - DATABASE-SERVER (192.168.1.30)
    """
    router = SimulatedHost(
        host_id="router",
        hostname="ROUTER",
        simulated_ip="192.168.1.1",
        status=HostStatus.ONLINE,
        open_ports=[80, 443],
        services={80: "HTTP-Admin", 443: "HTTPS-Admin"},
        risk_level=RiskLevel.LOW,
        subnet="192.168.1.0/24",
    )

    pc01 = SimulatedHost(
        host_id="pc-01",
        hostname="PC-01",
        simulated_ip="192.168.1.10",
        status=HostStatus.ONLINE,
        open_ports=[22, 139, 445],
        services={22: "SSH", 139: "NetBIOS", 445: "SMB"},
        risk_level=RiskLevel.LOW,
        subnet="192.168.1.0/24",
    )

    pc02 = SimulatedHost(
        host_id="pc-02",
        hostname="PC-02",
        simulated_ip="192.168.1.11",
        status=HostStatus.ONLINE,
        open_ports=[22],
        services={22: "SSH"},
        risk_level=RiskLevel.LOW,
        subnet="192.168.1.0/24",
    )

    web_server = SimulatedHost(
        host_id="web-server",
        hostname="WEB-SERVER",
        simulated_ip="192.168.1.20",
        status=HostStatus.ONLINE,
        open_ports=[80, 443, 22],
        services={80: "HTTP", 443: "HTTPS", 22: "SSH"},
        risk_level=RiskLevel.MEDIUM,
        subnet="192.168.1.0/24",
    )

    db_server = SimulatedHost(
        host_id="database-server",
        hostname="DATABASE-SERVER",
        simulated_ip="192.168.1.30",
        status=HostStatus.ONLINE,
        open_ports=[5432, 22],
        services={5432: "PostgreSQL", 22: "SSH"},
        risk_level=RiskLevel.HIGH,
        subnet="192.168.1.0/24",
    )

    return [router, pc01, pc02, web_server, db_server]


# Explicit topology connections tuple for initial demo
DEMO_CONNECTIONS = [
    ("router", "pc-01"),
    ("pc-01", "pc-02"),
    ("router", "web-server"),
    ("web-server", "database-server"),
]
