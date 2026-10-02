"""
CyberGuard AI - Event Severity Assessment Module
------------------------------------------------
This module evaluates simulated cybersecurity events and computes a severity level
(LOW, MEDIUM, HIGH, CRITICAL) by combining the outputs of the Anomaly Detector,
the Attack Classifier, and the underlying event metrics.

Educational Simulation Notice:
- These heuristic severity rules are designed for safe college simulation and ML demonstration.
- They do not represent real-world enterprise cybersecurity compliance or industry standards.
- No real network operations, scanning, exploitation, or attack generation are performed.
"""

# =====================================================================
# Configurable Severity Thresholds
# =====================================================================
# Thresholds for simulated events:
BRUTE_FORCE_CRITICAL_ATTEMPTS = 30     # >= 30 failed logins is considered severe brute force
SUSPICIOUS_LOGIN_HIGH_ATTEMPTS = 8      # >= 8 failed logins elevates suspicious login to HIGH
PORT_SCAN_HIGH_PORTS = 50               # >= 50 unique ports scanned elevates reconnaissance to HIGH
ANOMALY_SCORE_SEVERE_THRESHOLD = -0.02  # Negative anomaly score indicating strong outlier status


def _parse_features(features):
    """
    Safely extract numerical values from feature metrics.
    Supports list/tuple: [failed_attempts, requests_per_second, unique_ports, duration]
    or dict: {'failed_attempts': ..., 'requests_per_second': ..., ...}
    """
    failed_attempts = 0
    requests_per_second = 0.0
    unique_ports = 0
    duration = 0.0

    if isinstance(features, (list, tuple)) and len(features) >= 4:
        try:
            failed_attempts = int(features[0] or 0)
            requests_per_second = float(features[1] or 0.0)
            unique_ports = int(features[2] or 0)
            duration = float(features[3] or 0.0)
        except (ValueError, TypeError):
            pass
    elif isinstance(features, dict):
        try:
            failed_attempts = int(features.get("failed_attempts") or 0)
            requests_per_second = float(features.get("requests_per_second") or 0.0)
            unique_ports = int(features.get("unique_ports") or 0)
            duration = float(features.get("duration") or 0.0)
        except (ValueError, TypeError):
            pass

    return failed_attempts, requests_per_second, unique_ports, duration


def calculate_severity(
    attack_type="normal",
    is_anomaly=False,
    anomaly_score=0.0,
    features=None,
    return_reason=False,
):
    """
    Calculate the severity level of a simulated cybersecurity event.

    Parameters:
        attack_type (str): Predicted category from classifier
            ('normal', 'brute_force', 'port_scan', 'ddos_like', 'suspicious_login').
        is_anomaly (bool): True if flagged as anomalous by the anomaly detector.
        anomaly_score (float): Decision score from Isolation Forest (lower = more abnormal).
        features (list or dict, optional): Event feature metrics:
            [failed_attempts, requests_per_second, unique_ports, duration] or dict.
        return_reason (bool, optional): If True, returns a tuple of (severity, reason).
            Defaults to False.

    Returns:
        str or tuple: Severity string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
            or (severity, reason) if return_reason is True.
    """
    attack = str(attack_type).lower().strip()
    failed_attempts, requests_per_second, unique_ports, duration = _parse_features(features)

    severity = "LOW"
    reason = "Normal benign activity detected within standard thresholds."

    # 1. DDoS-like attacks: Immediate service availability impact
    if attack == "ddos_like":
        severity = "CRITICAL"
        reason = (
            f"Volumetric DDoS pattern detected with extreme request volume "
            f"({requests_per_second:.1f} req/s). Threatens system availability."
        )

    # 2. Brute-force attacks: Repeated credential cracking
    elif attack == "brute_force":
        if failed_attempts >= BRUTE_FORCE_CRITICAL_ATTEMPTS or anomaly_score <= ANOMALY_SCORE_SEVERE_THRESHOLD:
            severity = "CRITICAL"
            reason = (
                f"Severe brute force attack detected with {failed_attempts} failed attempts "
                f"and deep anomaly score ({anomaly_score:+.4f})."
            )
        else:
            severity = "HIGH"
            reason = (
                f"Automated brute force attack detected with {failed_attempts} failed attempts. "
                f"Active credential guessing in progress."
            )

    # 3. Port scan attacks: Systematic network reconnaissance
    elif attack == "port_scan":
        if unique_ports >= PORT_SCAN_HIGH_PORTS or is_anomaly:
            severity = "HIGH"
            reason = (
                f"Wide port reconnaissance detected across {unique_ports} unique ports. "
                f"Target network enumeration in progress."
            )
        else:
            severity = "MEDIUM"
            reason = (
                f"Moderate port scanning probe observed across {unique_ports} ports."
            )

    # 4. Suspicious login activity: Credential stuffing or unauthorized access attempts
    elif attack == "suspicious_login":
        if failed_attempts >= SUSPICIOUS_LOGIN_HIGH_ATTEMPTS:
            severity = "HIGH"
            reason = (
                f"Multiple repeated failed login attempts ({failed_attempts}) exceeding standard warning limit."
            )
        else:
            severity = "MEDIUM"
            reason = (
                f"Abnormal or unauthorized login pattern detected ({failed_attempts} failed attempts)."
            )

    # 5. Normal activity: Benign traffic, with checks for unexpected anomalies
    elif attack == "normal":
        if is_anomaly:
            severity = "MEDIUM"
            reason = (
                f"Nominally benign event flagged as anomalous by Isolation Forest "
                f"(score: {anomaly_score:+.4f}). Requires monitoring."
            )
        else:
            severity = "LOW"
            reason = "Standard baseline traffic within normal operational limits."

    # 6. Fallback for unclassified / unknown events
    else:
        if is_anomaly and anomaly_score <= ANOMALY_SCORE_SEVERE_THRESHOLD:
            severity = "HIGH"
            reason = f"Unclassified anomalous pattern with severe anomaly score ({anomaly_score:+.4f})."
        elif is_anomaly:
            severity = "MEDIUM"
            reason = f"Unclassified event flagged as anomalous by detector."
        else:
            severity = "LOW"
            reason = "Unclassified event operating within standard baselines."

    if return_reason:
        return severity, reason
    return severity


# =====================================================================
# Safe Local Demonstration & Test
# =====================================================================
if __name__ == "__main__":
    print("=" * 65)
    print("CyberGuard AI - Event Severity Assessment")
    print("=" * 65)

    # Test cases representing various simulated security scenarios
    test_cases = [
        (
            "Benign Web Request",
            {"attack_type": "normal", "is_anomaly": False, "anomaly_score": 0.1289, "features": [0, 2.5, 1, 12.0]},
            "Expected: LOW",
        ),
        (
            "Anomalous Benign Traffic",
            {"attack_type": "normal", "is_anomaly": True, "anomaly_score": -0.0050, "features": [1, 4.5, 3, 20.0]},
            "Expected: MEDIUM",
        ),
        (
            "Stealthy Login Probe",
            {"attack_type": "suspicious_login", "is_anomaly": False, "anomaly_score": 0.0200, "features": [5, 0.8, 1, 22.0]},
            "Expected: MEDIUM",
        ),
        (
            "Excessive Failed Logins",
            {"attack_type": "suspicious_login", "is_anomaly": True, "anomaly_score": -0.0120, "features": [9, 1.2, 1, 35.0]},
            "Expected: HIGH",
        ),
        (
            "Host Port Scan Reconnaissance",
            {"attack_type": "port_scan", "is_anomaly": True, "anomaly_score": -0.0084, "features": [1, 35.0, 220, 10.0]},
            "Expected: HIGH",
        ),
        (
            "Moderate SSH Brute Force",
            {"attack_type": "brute_force", "is_anomaly": True, "anomaly_score": -0.0110, "features": [18, 5.0, 1, 45.0]},
            "Expected: HIGH",
        ),
        (
            "Severe SSH Brute Force Storm",
            {"attack_type": "brute_force", "is_anomaly": True, "anomaly_score": -0.0245, "features": [45, 12.0, 1, 140.0]},
            "Expected: CRITICAL",
        ),
        (
            "Volumetric DDoS Attack",
            {"attack_type": "ddos_like", "is_anomaly": True, "anomaly_score": -0.0281, "features": [1, 650.0, 2, 45.0]},
            "Expected: CRITICAL",
        ),
    ]

    print("\nRunning simulated severity evaluations:\n")
    for name, params, expectation in test_cases:
        severity, reason = calculate_severity(
            attack_type=params["attack_type"],
            is_anomaly=params["is_anomaly"],
            anomaly_score=params["anomaly_score"],
            features=params["features"],
            return_reason=True,
        )

        badge = f"[{severity}]"
        print(f"--- {name} ---")
        print(f"  Condition:       {expectation}")
        print(f"  Attack Type:     {params['attack_type']}")
        print(f"  Anomaly Flag:    {params['is_anomaly']} (score: {params['anomaly_score']:+.4f})")
        print(f"  Features:        {params['features']}")
        print(f"  Assigned Level:  {badge}")
        print(f"  Explanation:     {reason}\n")

    print("=" * 65)
    print("Severity assessment module test ran successfully!")
    print("=" * 65)
