"""
M1 Network Topology Manager using NetworkX.

Represents the simulated cyber-network as an in-memory graph.
Provides graph operations: node/edge creation, neighbor lookups, reachability checks,
and complete topology export.
"""

from typing import Any, Dict, List, Optional, Set
import networkx as nx

from cyberguard.network.models import HostStatus, SimulatedHost


class NetworkTopologyManager:
    """
    Manages host nodes and connection edges of the simulated cyber network graph.
    Powered by NetworkX for graph structure analysis.
    """

    def __init__(self) -> None:
        self._graph: nx.Graph = nx.Graph()
        self._hosts: Dict[str, SimulatedHost] = {}

    def add_host(self, host: SimulatedHost) -> None:
        """
        Add a simulated host to the network graph.

        Raises:
            ValueError: If host with the same host_id already exists.
        """
        if host.host_id in self._hosts:
            raise ValueError(f"Host with host_id '{host.host_id}' already exists in topology.")

        self._hosts[host.host_id] = host.model_copy(deep=True)
        self._graph.add_node(
            host.host_id,
            hostname=host.hostname,
            ip=host.simulated_ip,
            status=host.status.value,
            risk_level=host.risk_level.value,
        )

        # Synchronize edges if connected_hosts list contains existing hosts
        for neighbor_id in host.connected_hosts:
            if neighbor_id in self._hosts and not self._graph.has_edge(host.host_id, neighbor_id):
                self._graph.add_edge(host.host_id, neighbor_id)
                if host.host_id not in self._hosts[neighbor_id].connected_hosts:
                    self._hosts[neighbor_id].connected_hosts.append(host.host_id)

    def update_host(self, host: SimulatedHost) -> None:
        """
        Update state attributes of an existing host.

        Raises:
            KeyError: If host_id is not found in topology.
        """
        if host.host_id not in self._hosts:
            raise KeyError(f"Host '{host.host_id}' not found in topology.")

        self._hosts[host.host_id] = host.model_copy(deep=True)
        self._graph.nodes[host.host_id].update(
            hostname=host.hostname,
            ip=host.simulated_ip,
            status=host.status.value,
            risk_level=host.risk_level.value,
        )

    def get_host(self, host_id: str) -> SimulatedHost:
        """
        Retrieve a simulated host by host_id.

        Raises:
            KeyError: If host_id is not found.
        """
        if host_id not in self._hosts:
            raise KeyError(f"Host '{host_id}' not found in topology.")
        return self._hosts[host_id].model_copy(deep=True)

    def has_host(self, host_id: str) -> bool:
        """Check if a host exists in the topology graph."""
        return host_id in self._hosts

    def get_all_hosts(self) -> List[SimulatedHost]:
        """Return a list of all hosts in the network topology."""
        return [h.model_copy(deep=True) for h in self._hosts.values()]

    def remove_host(self, host_id: str) -> None:
        """
        Remove a host node and all connected links from the topology graph.

        Raises:
            KeyError: If host_id does not exist.
        """
        if host_id not in self._hosts:
            raise KeyError(f"Host '{host_id}' not found in topology.")

        # Remove host_id from neighbors' connected_hosts list
        if host_id in self._graph:
            neighbors = list(self._graph.neighbors(host_id))
            for n_id in neighbors:
                if n_id in self._hosts and host_id in self._hosts[n_id].connected_hosts:
                    self._hosts[n_id].connected_hosts.remove(host_id)
            self._graph.remove_node(host_id)

        del self._hosts[host_id]

    def add_connection(self, host1_id: str, host2_id: str) -> None:
        """
        Create a bidirectional network connection (edge) between two hosts.

        Raises:
            KeyError: If either host does not exist.
            ValueError: If trying to connect a host to itself.
        """
        if host1_id not in self._hosts:
            raise KeyError(f"Host '{host1_id}' not found.")
        if host2_id not in self._hosts:
            raise KeyError(f"Host '{host2_id}' not found.")
        if host1_id == host2_id:
            raise ValueError(f"Cannot connect host '{host1_id}' to itself.")

        self._graph.add_edge(host1_id, host2_id)

        # Sync connected_hosts fields
        if host2_id not in self._hosts[host1_id].connected_hosts:
            self._hosts[host1_id].connected_hosts.append(host2_id)
        if host1_id not in self._hosts[host2_id].connected_hosts:
            self._hosts[host2_id].connected_hosts.append(host1_id)

    def remove_connection(self, host1_id: str, host2_id: str) -> None:
        """
        Remove network link (edge) between two hosts.

        Raises:
            KeyError: If either host does not exist.
        """
        if host1_id not in self._hosts:
            raise KeyError(f"Host '{host1_id}' not found.")
        if host2_id not in self._hosts:
            raise KeyError(f"Host '{host2_id}' not found.")

        if self._graph.has_edge(host1_id, host2_id):
            self._graph.remove_edge(host1_id, host2_id)

        if host2_id in self._hosts[host1_id].connected_hosts:
            self._hosts[host1_id].connected_hosts.remove(host2_id)
        if host1_id in self._hosts[host2_id].connected_hosts:
            self._hosts[host2_id].connected_hosts.remove(host1_id)

    def are_connected(self, host1_id: str, host2_id: str) -> bool:
        """
        Check if an active direct physical/topological connection exists between host1 and host2.

        Raises:
            KeyError: If either host does not exist.
        """
        if host1_id not in self._hosts:
            raise KeyError(f"Host '{host1_id}' not found.")
        if host2_id not in self._hosts:
            raise KeyError(f"Host '{host2_id}' not found.")

        return self._graph.has_edge(host1_id, host2_id)

    def get_neighbors(self, host_id: str) -> List[SimulatedHost]:
        """
        Retrieve all directly connected neighbor hosts for a host_id.

        Raises:
            KeyError: If host_id does not exist.
        """
        if host_id not in self._hosts:
            raise KeyError(f"Host '{host_id}' not found in topology.")

        neighbor_ids = list(self._graph.neighbors(host_id))
        return [self._hosts[nid].model_copy(deep=True) for nid in neighbor_ids if nid in self._hosts]

    def are_hosts_routable(self, source_id: str, target_id: str) -> bool:
        """
        Check if there is a path between source_id and target_id in the graph
        such that no node along the path (including endpoints) is ISOLATED or OFFLINE.

        Raises:
            KeyError: If source or target does not exist.
        """
        if source_id not in self._hosts:
            raise KeyError(f"Host '{source_id}' not found.")
        if target_id not in self._hosts:
            raise KeyError(f"Host '{target_id}' not found.")

        # Check endpoints state
        if self._hosts[source_id].status in (HostStatus.ISOLATED, HostStatus.OFFLINE):
            return False
        if self._hosts[target_id].status in (HostStatus.ISOLATED, HostStatus.OFFLINE):
            return False

        # Create a subgraph of active nodes
        active_nodes = [
            nid for nid, host in self._hosts.items()
            if host.status not in (HostStatus.ISOLATED, HostStatus.OFFLINE)
        ]
        subgraph = self._graph.subgraph(active_nodes)

        return nx.has_path(subgraph, source_id, target_id)

    def get_reachable_hosts(self, source_id: str) -> List[SimulatedHost]:
        """
        Get all hosts reachable from source_id via active (non-isolated, non-offline) paths.
        """
        if source_id not in self._hosts:
            raise KeyError(f"Host '{source_id}' not found.")

        if self._hosts[source_id].status in (HostStatus.ISOLATED, HostStatus.OFFLINE):
            return []

        active_nodes = [
            nid for nid, host in self._hosts.items()
            if host.status not in (HostStatus.ISOLATED, HostStatus.OFFLINE)
        ]
        subgraph = self._graph.subgraph(active_nodes)

        reachable_ids = nx.single_source_shortest_path(subgraph, source_id).keys()
        return [self._hosts[nid].model_copy(deep=True) for nid in reachable_ids if nid != source_id]

    def get_complete_topology(self) -> Dict[str, Any]:
        """
        Export a full dictionary representation of the graph topology.
        Useful for visualization (M6) and API gateway serialization (M5).
        """
        connections = []
        for u, v in self._graph.edges():
            connections.append({"source": u, "target": v})

        adjacency = {}
        for hid in self._hosts:
            adjacency[hid] = list(self._graph.neighbors(hid))

        return {
            "node_count": len(self._hosts),
            "edge_count": self._graph.number_of_edges(),
            "hosts": [host.model_dump() for host in self._hosts.values()],
            "connections": connections,
            "adjacency": adjacency,
        }
