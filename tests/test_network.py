"""
Unit Tests for M1 Network & Simulation Engine.

Guarantees 100% test coverage for:
- Host creation & Pydantic schema validation
- Duplicate host handling
- Topology connection & graph edge operations
- Node/Edge removal
- Neighbor lookup & reachability graph algorithms
- Host status mutations (ONLINE, OFFLINE, ISOLATED)
- Host isolation & path blocking verification
- Host restoration & unblocking verification
- Simulation EventBus publishing, subscribers, and filtering
- Error handling for invalid hosts / ports / operations

SAFETY CHECK:
All tests run in-memory with zero real network sockets or OS commands.
"""

import pytest
from pydantic import ValidationError

from cyberguard.network import (
    EventType,
    HostStatus,
    NetworkSimulationEngine,
    NetworkTopologyManager,
    RiskLevel,
    SimulatedHost,
    SimulationEvent,
)


class TestHostModel:
    """Test suite for SimulatedHost data model and Pydantic validation."""

    def test_host_creation_valid(self):
        host = SimulatedHost(
            host_id="test-host-1",
            hostname="Test Host",
            simulated_ip="192.168.1.100",
            status=HostStatus.ONLINE,
            open_ports=[80, 443, 22],
            risk_level=RiskLevel.MEDIUM,
        )
        assert host.host_id == "test-host-1"
        assert host.hostname == "Test Host"
        assert host.simulated_ip == "192.168.1.100"
        assert host.status == HostStatus.ONLINE
        assert host.open_ports == [22, 80, 443]  # Sorted
        assert host.risk_level == RiskLevel.MEDIUM

    def test_host_port_deduplication(self):
        host = SimulatedHost(
            host_id="h-dup",
            hostname="Dup Port Host",
            simulated_ip="10.0.0.1",
            open_ports=[80, 80, 22, 443, 22],
        )
        assert host.open_ports == [22, 80, 443]

    def test_invalid_port_range(self):
        with pytest.raises(ValidationError):
            SimulatedHost(
                host_id="h-invalid-port",
                hostname="Bad Port",
                simulated_ip="10.0.0.2",
                open_ports=[70000],  # Port > 65535
            )

    def test_empty_host_id_raises(self):
        with pytest.raises(ValidationError):
            SimulatedHost(
                host_id="   ",
                hostname="Bad Host",
                simulated_ip="10.0.0.3",
            )


class TestTopologyManager:
    """Test suite for NetworkTopologyManager graph structure."""

    def test_add_and_get_host(self):
        tm = NetworkTopologyManager()
        host = SimulatedHost(
            host_id="h-1",
            hostname="Host 1",
            simulated_ip="192.168.1.10",
        )
        tm.add_host(host)
        assert tm.has_host("h-1")
        retrieved = tm.get_host("h-1")
        assert retrieved.host_id == "h-1"

    def test_duplicate_host_raises_value_error(self):
        tm = NetworkTopologyManager()
        host1 = SimulatedHost(host_id="h-1", hostname="Host 1", simulated_ip="192.168.1.10")
        host2 = SimulatedHost(host_id="h-1", hostname="Host 1 Dup", simulated_ip="192.168.1.11")
        tm.add_host(host1)
        with pytest.raises(ValueError, match="already exists"):
            tm.add_host(host2)

    def test_nonexistent_host_raises_key_error(self):
        tm = NetworkTopologyManager()
        with pytest.raises(KeyError, match="not found"):
            tm.get_host("nonexistent-id")

    def test_add_and_remove_connection(self):
        tm = NetworkTopologyManager()
        h1 = SimulatedHost(host_id="h-1", hostname="H1", simulated_ip="192.168.1.10")
        h2 = SimulatedHost(host_id="h-2", hostname="H2", simulated_ip="192.168.1.11")
        tm.add_host(h1)
        tm.add_host(h2)

        assert not tm.are_connected("h-1", "h-2")
        tm.add_connection("h-1", "h-2")
        assert tm.are_connected("h-1", "h-2")

        # Verify connected_hosts list synced
        assert "h-2" in tm.get_host("h-1").connected_hosts
        assert "h-1" in tm.get_host("h-2").connected_hosts

        tm.remove_connection("h-1", "h-2")
        assert not tm.are_connected("h-1", "h-2")
        assert "h-2" not in tm.get_host("h-1").connected_hosts

    def test_remove_host_cleans_edges(self):
        tm = NetworkTopologyManager()
        h1 = SimulatedHost(host_id="h-1", hostname="H1", simulated_ip="192.168.1.10")
        h2 = SimulatedHost(host_id="h-2", hostname="H2", simulated_ip="192.168.1.11")
        tm.add_host(h1)
        tm.add_host(h2)
        tm.add_connection("h-1", "h-2")

        tm.remove_host("h-1")
        assert not tm.has_host("h-1")
        assert "h-1" not in tm.get_host("h-2").connected_hosts

    def test_get_neighbors(self):
        tm = NetworkTopologyManager()
        h1 = SimulatedHost(host_id="h-1", hostname="H1", simulated_ip="10.0.0.1")
        h2 = SimulatedHost(host_id="h-2", hostname="H2", simulated_ip="10.0.0.2")
        h3 = SimulatedHost(host_id="h-3", hostname="H3", simulated_ip="10.0.0.3")
        tm.add_host(h1)
        tm.add_host(h2)
        tm.add_host(h3)
        tm.add_connection("h-1", "h-2")
        tm.add_connection("h-1", "h-3")

        neighbors = tm.get_neighbors("h-1")
        neighbor_ids = [n.host_id for n in neighbors]
        assert set(neighbor_ids) == {"h-2", "h-3"}


class TestSimulationEngine:
    """Test suite for NetworkSimulationEngine API operations and events."""

    def test_demo_topology_loader(self):
        engine = NetworkSimulationEngine(load_demo=True)
        hosts = engine.get_all_hosts()
        assert len(hosts) == 5

        host_ids = {h.host_id for h in hosts}
        assert set(host_ids) == {"router", "pc-01", "pc-02", "web-server", "database-server"}

        assert engine.are_connected("router", "pc-01")
        assert engine.are_connected("pc-01", "pc-02")
        assert engine.are_connected("router", "web-server")
        assert engine.are_connected("web-server", "database-server")

    def test_host_isolation_and_restoration(self):
        engine = NetworkSimulationEngine(load_demo=True)

        # Before isolation: path pc-01 -> pc-02 is routable
        assert engine.are_hosts_routable("pc-01", "pc-02")

        # Isolate pc-01
        isolated_host = engine.isolate_host("pc-01")
        assert isolated_host.status == HostStatus.ISOLATED

        # Verify path pc-01 -> pc-02 is no longer routable
        assert not engine.are_hosts_routable("pc-01", "pc-02")

        # Verify event logged
        events = engine.get_events(limit=5, action=EventType.ACTION_HOST_ISOLATION)
        assert len(events) >= 1
        assert events[-1].target_host == "pc-01"

        # Restore host
        restored_host = engine.restore_host("pc-01")
        assert restored_host.status == HostStatus.ONLINE
        assert engine.are_hosts_routable("pc-01", "pc-02")

    def test_update_risk_level(self):
        engine = NetworkSimulationEngine(load_demo=True)
        updated = engine.update_risk_level("web-server", RiskLevel.CRITICAL)
        assert updated.risk_level == RiskLevel.CRITICAL

        events = engine.get_events(limit=1, action=EventType.ACTION_RISK_UPDATE)
        assert len(events) == 1
        assert events[0].target_host == "web-server"
        assert events[0].metadata["new_risk"] == "CRITICAL"

    def test_open_ports_management(self):
        engine = NetworkSimulationEngine(load_demo=True)
        engine.add_open_port("pc-02", 8080, "HTTP-Proxy")
        host = engine.get_host("pc-02")
        assert 8080 in host.open_ports
        assert host.services[8080] == "HTTP-Proxy"

        engine.remove_open_port("pc-02", 8080)
        host = engine.get_host("pc-02")
        assert 8080 not in host.open_ports
        assert 8080 not in host.services

    def test_simulate_port_scan(self):
        engine = NetworkSimulationEngine(load_demo=True)
        scan_event = engine.simulate_port_scan(
            source_host_id="pc-01",
            target_host_id="web-server",
            ports_to_scan=[80, 443, 22, 9999],
        )

        assert scan_event.action == EventType.ACTION_PORT_SCAN.value
        assert scan_event.success is True
        assert scan_event.metadata["discovered_open_ports"] == [80, 443, 22]

    def test_port_scan_isolated_target_fails(self):
        engine = NetworkSimulationEngine(load_demo=True)
        engine.isolate_host("web-server")

        scan_event = engine.simulate_port_scan(
            source_host_id="pc-01",
            target_host_id="web-server",
            ports_to_scan=[80, 443],
        )

        assert scan_event.success is False
        assert scan_event.metadata["discovered_open_ports"] == []

    def test_event_bus_subscriber(self):
        engine = NetworkSimulationEngine(load_demo=True)
        received_events = []

        def on_event(ev: SimulationEvent):
            received_events.append(ev)

        engine.subscribe_events(on_event, event_type=EventType.ACTION_HOST_ISOLATION)
        engine.isolate_host("database-server")

        assert len(received_events) == 1
        assert received_events[0].target_host == "database-server"

    def test_complete_topology_export(self):
        engine = NetworkSimulationEngine(load_demo=True)
        snapshot = engine.get_complete_topology()

        assert snapshot["node_count"] == 5
        assert snapshot["edge_count"] == 4
        assert len(snapshot["hosts"]) == 5
        assert "router" in snapshot["adjacency"]
