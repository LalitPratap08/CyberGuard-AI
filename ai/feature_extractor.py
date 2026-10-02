"""
Feature Extractor Module for CyberGuard AI
------------------------------------------
This module processes simulated cybersecurity event dictionaries and extracts
the numerical features needed by machine learning models (e.g., scikit-learn).

Safe Simulated Project:
- No real network operations or traffic sniffing.
- Purely transforms in-memory simulated event dictionaries into numerical vectors.
"""


def extract_features(event):
    """
    Extract numerical feature vector from a simulated cybersecurity event.

    A typical simulated event dictionary may contain both metadata and metrics:
        - Metadata (ignored for ML vector): event_id, timestamp, attack_type,
          source_ip, target_host
        - Numerical metrics (extracted): failed_attempts, requests_per_second,
          unique_ports, duration

    Parameters:
        event (dict): Simulated event dictionary.

    Returns:
        list of float: A 1D numerical feature vector suitable for scikit-learn:
            [failed_attempts, requests_per_second, unique_ports, duration]
            (Can be directly used with `model.predict([vector])` or `model.fit([vector, ...])`)
    """
    # Guard against non-dictionary inputs to prevent errors
    if not isinstance(event, dict):
        event = {}

    def safe_to_float(value, default=0.0):
        """
        Safely converts a value to a float.
        Returns default (0.0) if the value is None, missing, or invalid.
        """
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # Extract the 4 numerical fields with safe fallback to 0.0 if missing
    failed_attempts = safe_to_float(event.get("failed_attempts"))
    requests_per_second = safe_to_float(event.get("requests_per_second"))
    unique_ports = safe_to_float(event.get("unique_ports"))
    duration = safe_to_float(event.get("duration"))

    # Return the numerical feature vector in fixed order for scikit-learn
    return [failed_attempts, requests_per_second, unique_ports, duration]


# =====================================================================
# Safe Local Tests & Demonstrations
# =====================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("CyberGuard AI - Feature Extractor Test")
    print("=" * 60)

    # Example 1: Full simulated attack event (with metadata & metrics)
    simulated_event_brute_force = {
        "event_id": "EVT-1001",
        "timestamp": "2026-10-02T14:30:00Z",
        "attack_type": "SSH Brute Force",
        "source_ip": "192.168.1.105",
        "target_host": "192.168.1.10",
        "failed_attempts": 15,
        "requests_per_second": 32.5,
        "unique_ports": 1,
        "duration": 45.0,
    }

    # Example 2: Simulated normal traffic event
    simulated_event_normal = {
        "event_id": "EVT-1002",
        "timestamp": "2026-10-02T14:31:00Z",
        "attack_type": "Benign",
        "source_ip": "192.168.1.20",
        "target_host": "192.168.1.10",
        "failed_attempts": 0,
        "requests_per_second": 2.1,
        "unique_ports": 2,
        "duration": 5.0,
    }

    # Example 3: Event with missing or None numerical fields
    simulated_event_incomplete = {
        "event_id": "EVT-1003",
        "attack_type": "Port Scan",
        "unique_ports": 150,
        "duration": None,  # Missing/None values handled safely
        # 'failed_attempts' and 'requests_per_second' are omitted
    }

    # Example 4: Completely empty dictionary
    simulated_event_empty = {}

    test_cases = [
        ("Test 1 - Full Simulated Brute Force Event", simulated_event_brute_force),
        ("Test 2 - Simulated Benign Traffic Event", simulated_event_normal),
        ("Test 3 - Incomplete Event (Missing/None Fields)", simulated_event_incomplete),
        ("Test 4 - Empty Event Dictionary", simulated_event_empty),
    ]

    for label, event_data in test_cases:
        features = extract_features(event_data)
        print(f"\n{label}:")
        print(f"  Input:   {event_data}")
        print(f"  Vector:  {features}")

    print("\n" + "=" * 60)
    print("Feature Vector Format: [failed_attempts, requests_per_second, unique_ports, duration]")
    print("All tests completed safely and successfully!")
    print("=" * 60)
