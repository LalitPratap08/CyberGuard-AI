"""
M1 Data Models: Simulated Hosts, Host Status, Risk Levels, and Simulation Events.

IMPORTANT SAFETY NOTICE:
All models in this module represent safe, simulated entities.
No actual network sockets, IP traffic, or OS system commands are executed.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class HostStatus(str, Enum):
    """Status of a simulated host in the network topology."""
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    ISOLATED = "ISOLATED"


class RiskLevel(str, Enum):
    """Simulated risk assessment level for a host."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    """Standard simulated event actions supported across modules."""
    ACTION_PORT_SCAN = "ACTION_PORT_SCAN"
    ACTION_LOGIN_ATTEMPT = "ACTION_LOGIN_ATTEMPT"
    ACTION_CRED_SPRAY_ATTEMPT = "ACTION_CRED_SPRAY_ATTEMPT"
    ACTION_HOST_ISOLATION = "ACTION_HOST_ISOLATION"
    ACTION_CONNECTION_CHANGE = "ACTION_CONNECTION_CHANGE"
    ACTION_HOST_STATUS_CHANGE = "ACTION_HOST_STATUS_CHANGE"
    ACTION_RISK_UPDATE = "ACTION_RISK_UPDATE"


class SimulatedHost(BaseModel):
    """
    Data model representing a simulated machine/node in the Cyber Range network.
    """
    host_id: str = Field(..., description="Unique identifier for the host (e.g. 'host-pc-01')")
    hostname: str = Field(..., description="Human readable hostname (e.g. 'PC-01')")
    simulated_ip: str = Field(..., description="Simulated IP address (e.g. '192.168.1.10')")
    status: HostStatus = Field(default=HostStatus.ONLINE, description="Current operational state")
    open_ports: List[int] = Field(default_factory=list, description="List of simulated open port numbers")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="Assessed risk level")
    connected_hosts: List[str] = Field(default_factory=list, description="List of connected host_ids")
    services: Dict[int, str] = Field(default_factory=dict, description="Mapping of open port to service name")
    subnet: Optional[str] = Field(default=None, description="Subnet identifier (e.g. '192.168.1.0/24' or 'LAN')")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary custom host metadata")

    @field_validator("open_ports")
    @classmethod
    def validate_open_ports(cls, ports: List[int]) -> List[int]:
        """Ensure ports are within valid TCP/UDP port range (1..65535) and deduplicated."""
        valid_ports = []
        for p in ports:
            if not isinstance(p, int) or p < 1 or p > 65535:
                raise ValueError(f"Invalid port number: {p}. Must be between 1 and 65535.")
            if p not in valid_ports:
                valid_ports.append(p)
        return sorted(valid_ports)

    @field_validator("host_id", "hostname")
    @classmethod
    def validate_non_empty_str(cls, value: str, info) -> str:
        """Ensure identifiers are non-empty strings."""
        if not value or not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty.")
        return value.strip()


class SimulationEvent(BaseModel):
    """
    Structured simulated event logged during network interactions.
    Used by M2 (Attacker), M3 (Defender), M4 (Response), M5 (Backend).
    """
    event_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique event ID"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp"
    )
    source_host: str = Field(..., description="host_id or hostname initiating the action")
    target_host: str = Field(..., description="host_id or hostname receiving the action")
    action: str = Field(..., description="Simulated action name or EventType string")
    success: bool = Field(default=True, description="Whether the simulated action succeeded")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Event specific payload metadata (e.g., ports scanned, status changes)"
    )

    @field_validator("source_host", "target_host", "action")
    @classmethod
    def validate_event_strings(cls, value: str, info) -> str:
        """Ensure event source, target, and action fields are non-empty."""
        if not value or not value.strip():
            raise ValueError(f"Event field '{info.field_name}' must not be empty.")
        return value.strip()
