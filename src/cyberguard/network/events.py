"""
M1 Simulation Event Bus & Emitter.

Manages event distribution, event history logging, and subscriber callbacks.
Enables M2, M3, M4, M5 to publish and subscribe to network simulation events.
"""

from typing import Callable, Dict, List, Optional, Union
from cyberguard.network.models import EventType, SimulationEvent

# Callback type signature: receives a SimulationEvent
EventSubscriber = Callable[[SimulationEvent], None]


class SimulationEventBus:
    """
    Event Bus for recording and broadcasting simulated cyber range telemetry events.
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._history: List[SimulationEvent] = []
        self._max_history: int = max_history
        self._subscribers: List[Dict[str, Union[Optional[str], EventSubscriber]]] = []

    def publish(self, event: SimulationEvent) -> SimulationEvent:
        """
        Record a simulation event and notify registered subscribers.

        Args:
            event: SimulationEvent instance.

        Returns:
            The recorded SimulationEvent instance.
        """
        # Append to event history log
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        # Notify subscribers
        for sub in self._subscribers:
            sub_type = sub["event_type"]
            callback = sub["callback"]
            if sub_type is None or sub_type == event.action:
                try:
                    callback(event)
                except Exception as err:  # Keep bus resilient to subscriber errors
                    # In production logs, subscriber exception is logged silently
                    pass

        return event

    def subscribe(
        self,
        callback: EventSubscriber,
        event_type: Optional[Union[EventType, str]] = None,
    ) -> None:
        """
        Subscribe a callback function to simulation events.

        Args:
            callback: Function accepting (event: SimulationEvent).
            event_type: Optional EventType or str filter. If None, subscribes to all events.
        """
        target_action = event_type.value if isinstance(event_type, EventType) else event_type
        self._subscribers.append({"event_type": target_action, "callback": callback})

    def get_events(
        self,
        limit: int = 100,
        host_id: Optional[str] = None,
        action: Optional[Union[EventType, str]] = None,
    ) -> List[SimulationEvent]:
        """
        Retrieve recent recorded simulation events, optionally filtered by host_id or action.

        Args:
            limit: Maximum number of events to return.
            host_id: Optional filter for events where source_host or target_host matches host_id.
            action: Optional filter for specific EventType or action name.

        Returns:
            List of SimulationEvent items (most recent last).
        """
        target_action = action.value if isinstance(action, EventType) else action

        filtered = []
        for ev in reversed(self._history):
            if host_id and (ev.source_host != host_id and ev.target_host != host_id):
                continue
            if target_action and ev.action != target_action:
                continue
            filtered.append(ev)
            if len(filtered) >= limit:
                break

        filtered.reverse()
        return filtered

    def clear_history(self) -> None:
        """Clear recorded event history."""
        self._history.clear()
