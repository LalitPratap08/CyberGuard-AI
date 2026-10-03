"""
M1 Network Simulation Engine.

Provides the unified, high-level API for interacting with the simulated cyber range environment.
Facilitates host state management, graph topology operations, isolation/restoration controls,
and event generation for M2 (Attacker), M3 (Defender), M4 (Response), M5 (Backend).

SAFETY GUARANTEE:
All operations are 100% in-memory state mutations. No real host operations or sockets are used.
"""

from typing import Any, Dict, List, Optional, Union

from cyberguard.network.events import EventSubscriber, SimulationEventBus
from cyberguard.network.models import (
    EventType,
    HostStatus,
    RiskLevel,
    SimulatedHost,
    SimulationEvent,
)
from cyberguard.network.presets import DEMO_CONNECTIONS, create_demo_hosts
from cyberguard.network.topology import NetworkTopologyManager


class NetworkSimulationEngine:
    """
    Main orchestration engine for M1 Network & Simulation.
    Combines NetworkTopologyManager graph state and SimulationEventBus telemetry log.
    """

    def __init__(self, load_demo: bool = False) -> None:
        self.topology: NetworkTopologyManager = NetworkTopologyManager()
        self.event_bus: SimulationEventBus = SimulationEventBus()

        if load_demo:
            self.load_demo_topology()

    def load_demo_topology(self) -> None:
        """Load the standard 5-host demo topology into the simulation engine."""
        for host in create_demo_hosts():
            if not self.topology.has_host(host.host_id):
                self.topology.add_host(host)

        for h1, h2 in DEMO_CONNECTIONS:
            if not self.topology.are_connected(h1, h2):
                self.topology.add_connection(h1, h2)

    # -------------------------------------------------------------------------
    # 1. Host State Management
    # -------------------------------------------------------------------------

    def add_host(self, host: SimulatedHost) -> SimulatedHost:
        """
        Add a new simulated host to the network.

        Raises:
            ValueError: If duplicate host_id exists.
        """
        self.topology.add_host(host)
        return self.get_host(host.host_id)

    def update_host(self, host: SimulatedHost) -> SimulatedHost:
        """
        Update an existing host in the network.
        """
        self.topology.update_host(host)
        return self.get_host(host.host_id)

    def get_host(self, host_id: str) -> SimulatedHost:
        """Get host details by host_id."""
        return self.topology.get_host(host_id)

    def get_all_hosts(self) -> List[SimulatedHost]:
        """Retrieve list of all simulated hosts in the range."""
        return self.topology.get_all_hosts()

    def remove_host(self, host_id: str) -> None:
        """
        Remove a host from the network simulation.
        """
        self.topology.remove_host(host_id)

    def change_host_status(self, host_id: str, new_status: Union[HostStatus, str]) -> SimulatedHost:
        """
        Change operational status of a host (ONLINE, OFFLINE, ISOLATED).

        Logs an ACTION_HOST_STATUS_CHANGE event.
        """
        status_enum = HostStatus(new_status) if isinstance(new_status, str) else new_status
        host = self.get_host(host_id)
        old_status = host.status

        host.status = status_enum
        self.topology.update_host(host)

        # Publish state change event
        event = SimulationEvent(
            source_host="SYSTEM",
            target_host=host_id,
            action=EventType.ACTION_HOST_STATUS_CHANGE.value,
            success=True,
            metadata={
                "previous_status": old_status.value,
                "new_status": status_enum.value,
            },
        )
        self.event_bus.publish(event)
        return self.get_host(host_id)

    def isolate_host(self, host_id: str) -> SimulatedHost:
        """
        Isolate a simulated host from the network.

        Updates simulated host status to ISOLATED and logs ACTION_HOST_ISOLATION event.
        Does NOT alter physical network connections on the host OS.
        """
        host = self.get_host(host_id)
        old_status = host.status
        host.status = HostStatus.ISOLATED
        self.topology.update_host(host)

        event = SimulationEvent(
            source_host="M4_DEFENDER",
            target_host=host_id,
            action=EventType.ACTION_HOST_ISOLATION.value,
            success=True,
            metadata={
                "previous_status": old_status.value,
                "new_status": HostStatus.ISOLATED.value,
                "isolation_reason": "Automated response / threat mitigation",
            },
        )
        self.event_bus.publish(event)
        return self.get_host(host_id)

    def restore_host(self, host_id: str) -> SimulatedHost:
        """
        Restore an isolated or offline host back to ONLINE status.
        """
        return self.change_host_status(host_id, HostStatus.ONLINE)

    def update_risk_level(self, host_id: str, new_risk_level: Union[RiskLevel, str]) -> SimulatedHost:
        """
        Update the threat risk level rating for a host.
        """
        risk_enum = RiskLevel(new_risk_level) if isinstance(new_risk_level, str) else new_risk_level
        host = self.get_host(host_id)
        old_risk = host.risk_level

        host.risk_level = risk_enum
        self.topology.update_host(host)

        event = SimulationEvent(
            source_host="M3_DETECTION",
            target_host=host_id,
            action=EventType.ACTION_RISK_UPDATE.value,
            success=True,
            metadata={
                "previous_risk": old_risk.value,
                "new_risk": risk_enum.value,
            },
        )
        self.event_bus.publish(event)
        return self.get_host(host_id)

    def add_open_port(self, host_id: str, port: int, service_name: Optional[str] = None) -> SimulatedHost:
        """
        Add a simulated open port to a host.
        """
        host = self.get_host(host_id)
        if port not in host.open_ports:
            host.open_ports.append(port)
            host.open_ports.sort()
        if service_name:
            host.services[port] = service_name
        self.topology.update_host(host)
        return self.get_host(host_id)

    def remove_open_port(self, host_id: str, port: int) -> SimulatedHost:
        """
        Remove a simulated open port from a host.
        """
        host = self.get_host(host_id)
        if port in host.open_ports:
            host.open_ports.remove(port)
        if port in host.services:
            del host.services[port]
        self.topology.update_host(host)
        return self.get_host(host_id)

    # -------------------------------------------------------------------------
    # 2. Topology Management
    # -------------------------------------------------------------------------

    def connect_hosts(self, host1_id: str, host2_id: str) -> None:
        """Create a connection link between host1 and host2."""
        self.topology.add_connection(host1_id, host2_id)
        event = SimulationEvent(
            source_host=host1_id,
            target_host=host2_id,
            action=EventType.ACTION_CONNECTION_CHANGE.value,
            success=True,
            metadata={"change_type": "CONNECTED", "host1": host1_id, "host2": host2_id},
        )
        self.event_bus.publish(event)

    def disconnect_hosts(self, host1_id: str, host2_id: str) -> None:
        """Remove connection link between host1 and host2."""
        self.topology.remove_connection(host1_id, host2_id)
        event = SimulationEvent(
            source_host=host1_id,
            target_host=host2_id,
            action=EventType.ACTION_CONNECTION_CHANGE.value,
            success=True,
            metadata={"change_type": "DISCONNECTED", "host1": host1_id, "host2": host2_id},
        )
        self.event_bus.publish(event)

    def are_connected(self, host1_id: str, host2_id: str) -> bool:
        """Check if direct link exists between host1 and host2."""
        return self.topology.are_connected(host1_id, host2_id)

    def are_hosts_routable(self, source_id: str, target_id: str) -> bool:
        """Check if active, non-isolated network routing exists between source and target."""
        return self.topology.are_hosts_routable(source_id, target_id)

    def get_neighbors(self, host_id: str) -> List[SimulatedHost]:
        """Get directly connected neighbor hosts."""
        return self.topology.get_neighbors(host_id)

    def get_reachable_hosts(self, source_id: str) -> List[SimulatedHost]:
        """Get all active, reachable hosts from source_id."""
        return self.topology.get_reachable_hosts(source_id)

    def get_complete_topology(self) -> Dict[str, Any]:
        """Export full graph state snapshot dictionary."""
        return self.topology.get_complete_topology()

    # -------------------------------------------------------------------------
    # 3. Simulation Event Generators for M2, M3, M4, M5
    # -------------------------------------------------------------------------

    def simulate_port_scan(
        self,
        source_host_id: str,
        target_host_id: str,
        ports_to_scan: Optional[List[int]] = None,
    ) -> SimulationEvent:
        """
        Simulate a port scan attack action from source_host to target_host.

        Used by M2 (Attack Simulation) to probe targets safely.
        """
        source_host = self.get_host(source_host_id)
        target_host = self.get_host(target_host_id)

        # Check reachability in network
        is_routable = self.are_hosts_routable(source_host_id, target_host_id)

        scanned = ports_to_scan if ports_to_scan else [21, 22, 80, 139, 445, 443, 3389, 5432, 8080]
        discovered_open = []

        if is_routable:
            discovered_open = [p for p in scanned if p in target_host.open_ports]

        event = SimulationEvent(
            source_host=source_host_id,
            target_host=target_host_id,
            action=EventType.ACTION_PORT_SCAN.value,
            success=is_routable,
            metadata={
                "scanned_ports": scanned,
                "discovered_open_ports": discovered_open,
                "target_ip": target_host.simulated_ip,
                "target_status": target_host.status.value,
            },
        )
        return self.event_bus.publish(event)

    def simulate_login_attempt(
        self,
        source_host_id: str,
        target_host_id: str,
        port: int,
        username: str,
        success: bool = False,
    ) -> SimulationEvent:
        """
        Simulate an authentication login attempt on target port.
        """
        target_host = self.get_host(target_host_id)
        is_routable = self.are_hosts_routable(source_host_id, target_host_id)

        actual_success = success and is_routable and (port in target_host.open_ports)

        event = SimulationEvent(
            source_host=source_host_id,
            target_host=target_host_id,
            action=EventType.ACTION_LOGIN_ATTEMPT.value,
            success=actual_success,
            metadata={
                "port": port,
                "username": username,
                "target_ip": target_host.simulated_ip,
                "is_routable": is_routable,
            },
        )
        return self.event_bus.publish(event)

    def simulate_cred_spray(
        self,
        source_host_id: str,
        target_host_ids: List[str],
        username: str,
        passwords_count: int = 5,
    ) -> List[SimulationEvent]:
        """
        Simulate a credential spraying attack across multiple targets.
        """
        events = []
        for target_id in target_host_ids:
            event = SimulationEvent(
                source_host=source_host_id,
                target_host=target_id,
                action=EventType.ACTION_CRED_SPRAY_ATTEMPT.value,
                success=False,
                metadata={
                    "username": username,
                    "attempts_count": passwords_count,
                    "target_host": target_id,
                },
            )
            events.append(self.event_bus.publish(event))
        return events

    def record_event(self, event: SimulationEvent) -> SimulationEvent:
        """Record a custom externally generated simulation event."""
        return self.event_bus.publish(event)

    def get_events(
        self,
        limit: int = 100,
        host_id: Optional[str] = None,
        action: Optional[Union[EventType, str]] = None,
    ) -> List[SimulationEvent]:
        """Retrieve recent simulation event history."""
        return self.event_bus.get_events(limit=limit, host_id=host_id, action=action)

    def subscribe_events(
        self,
        callback: EventSubscriber,
        event_type: Optional[Union[EventType, str]] = None,
    ) -> None:
        """Subscribe to simulation events."""
        self.event_bus.subscribe(callback, event_type=event_type)
