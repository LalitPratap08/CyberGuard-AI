"""
Feature Extractor Module for CyberGuard AI
------------------------------------------
This module is responsible for converting raw or simulated cybersecurity event
data into numerical feature vectors suitable for Machine Learning models.
"""


def extract_features(event):
    """
    Extract numerical features from a cybersecurity event dictionary.

    Parameters:
        event (dict): Simulated event data containing security metrics.

    Returns:
        list of float: Numerical feature vector in the order:
            [failed_attempts, requests_per_second, unique_ports, duration]
    """
    # Guard against non-dictionary inputs
    if not isinstance(event, dict):
        event = {}

    def safe_to_float(value, default=0.0):
        """Helper to convert values to float safely, returning default on failure."""
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    # Extract required fields with safe fallbacks
    failed_attempts = safe_to_float(event.get("failed_attempts"))
    requests_per_second = safe_to_float(event.get("requests_per_second"))
    unique_ports = safe_to_float(event.get("unique_ports"))
    duration = safe_to_float(event.get("duration"))

    # Return as a numerical feature vector
    return [failed_attempts, requests_per_second, unique_ports, duration]


if __name__ == "__main__":
    print("=" * 50)
    print("CyberGuard AI - Feature Extractor Test")
    print("=" * 50)

    # Test 1: Complete event data
    sample_complete = {
        "failed_attempts": 3,
        "requests_per_second": 45.5,
        "unique_ports": 2,
        "duration": 12.0
    }
    vector_complete = extract_features(sample_complete)
    print(f"\n[Test 1] Complete Event:\n  Input:  {sample_complete}\n  Vector: {vector_complete}")

    # Test 2: Incomplete event data with missing fields
    sample_partial = {
        "failed_attempts": 10,
        "duration": 5.5
        # 'requests_per_second' and 'unique_ports' are missing
    }
    vector_partial = extract_features(sample_partial)
    print(f"\n[Test 2] Partial Event (missing fields):\n  Input:  {sample_partial}\n  Vector: {vector_partial}")

    # Test 3: Empty event data
    sample_empty = {}
    vector_empty = extract_features(sample_empty)
    print(f"\n[Test 3] Empty Event:\n  Input:  {sample_empty}\n  Vector: {vector_empty}")
    print("\nAll tests ran successfully!")
