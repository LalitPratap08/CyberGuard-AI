"""
M1 Network & Simulation Module API Package.

Provides virtual host models, graph topology manager, event bus, and NetworkSimulationEngine.
"""

from cyberguard.network.engine import NetworkSimulationEngine
from cyberguard.network.events import SimulationEventBus
from cyberguard.network.models import (
    EventType,
    HostStatus,
    RiskLevel,
    SimulatedHost,
    SimulationEvent,
)
from cyberguard.network.presets import DEMO_CONNECTIONS, create_demo_hosts
from cyberguard.network.topology import NetworkTopologyManager

__all__ = [
    "NetworkSimulationEngine",
    "NetworkTopologyManager",
    "SimulationEventBus",
    "SimulatedHost",
    "SimulationEvent",
    "HostStatus",
    "RiskLevel",
    "EventType",
    "create_demo_hosts",
    "DEMO_CONNECTIONS",
]
