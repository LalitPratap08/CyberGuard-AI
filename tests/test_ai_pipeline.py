"""
CyberGuard AI - End-to-End AI Pipeline Test
-------------------------------------------
This test verifies the integration of the four M3 AI modules:
1. ai/feature_extractor.py  -> Extracts numerical feature vectors from events
2. ai/anomaly_detector.py   -> Flags anomalous behavior using Isolation Forest
3. ai/classifier.py         -> Categorizes attack types using Random Forest
4. ai/severity.py           -> Assigns risk severity (LOW, MEDIUM, HIGH, CRITICAL)

Safety Notice:
- Purely evaluates safe synthetic cybersecurity events in-memory.
- No network connections, packet capture, scanning, or real attacks are performed.
"""

from pathlib import Path
import sys

# Ensure project root is in sys.path so 'ai' package can be imported reliably
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.feature_extractor import extract_features
from ai.anomaly_detector import train_detector, predict_anomaly
from ai.classifier import train_classifier, predict_attack_type
from ai.severity import calculate_severity


def run_pipeline(event, anomaly_model, classifier_model):
    """
    Process a single simulated event dictionary through the complete AI pipeline.

    Parameters:
        event (dict): Simulated event containing security metrics.
        anomaly_model: Trained Isolation Forest model.
        classifier_model: Trained Random Forest classifier.

    Returns:
        dict: Complete AI analysis report containing:
            - features: Extracted numerical metrics
            - anomaly_score: Isolation Forest decision score
            - category: Normal or Anomalous classification
            - attack_type: Predicted attack category (e.g. brute_force, normal, etc.)
            - confidence: Classifier confidence percentage
            - severity: Assessed risk level (LOW, MEDIUM, HIGH, CRITICAL)
            - reason: Explanation of the assigned severity
    """
    # Step 1: Feature Extraction
    # Convert raw dictionary into fixed numerical vector:
    # [failed_attempts, requests_per_second, unique_ports, duration]
    features = extract_features(event)

    # Step 2: Anomaly Detection
    # Determine whether the event metrics deviate from normal patterns
    anomaly_output = predict_anomaly(anomaly_model, features)
    is_anomaly = anomaly_output["is_anomaly"]
    anomaly_score = anomaly_output["anomaly_score"]
    category = anomaly_output["label"]  # 'normal' or 'anomalous'

    # Step 3: Attack Classification
    # Predict the specific attack type and confidence score
    class_output = predict_attack_type(classifier_model, features)
    attack_type = class_output["attack_type"]
    confidence = class_output["confidence"]

    # Step 4: Severity Calculation
    # Determine event severity based on anomaly score, attack type, and metrics
    severity, reason = calculate_severity(
        attack_type=attack_type,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        features=features,
        return_reason=True,
    )

    # Return unified AI analysis output
    return {
        "event_id": event.get("event_id", "N/A"),
        "features": features,
        "anomaly_score": anomaly_score,
        "category": category,
        "attack_type": attack_type,
        "confidence": round(confidence * 100, 1),
        "severity": severity,
        "reason": reason,
    }


def main():
    print("=" * 70)
    print("CyberGuard AI - End-to-End M3 AI Pipeline Verification")
    print("=" * 70)

    # 1. Initialize and train AI models using synthetic dataset
    print("\n[Stage 1] Initializing and training AI models...")
    print("  -> Training Anomaly Detector (Isolation Forest)...")
    anomaly_model = train_detector()

    print("  -> Training Attack Classifier (Random Forest)...")
    classifier_model = train_classifier()
    print("  Models trained successfully.\n")

    # 2. Primary Test Event requested in specification:
    # { "failed_attempts": 27, "requests_per_second": 5, "unique_ports": 1, "duration": 60 }
    primary_event = {
        "event_id": "SIM-PRIMARY-001",
        "failed_attempts": 27,
        "requests_per_second": 5,
        "unique_ports": 1,
        "duration": 60,
    }

    print("-" * 70)
    print("TEST CASE 1: Primary Synthetic Event (High Failed Logins)")
    print("-" * 70)
    print(f"Input Event: {primary_event}")

    result_1 = run_pipeline(primary_event, anomaly_model, classifier_model)

    print("\nFinal AI Result:")
    print(f"  - Extracted Features : {result_1['features']}")
    print(f"  - Anomaly Score      : {result_1['anomaly_score']:+.4f}")
    print(f"  - Category           : {result_1['category']}")
    print(f"  - Attack Type        : {result_1['attack_type']}")
    print(f"  - Classifier Conf.   : {result_1['confidence']}%")
    print(f"  - Severity           : [{result_1['severity']}]")
    print(f"  - Severity Rationale : {result_1['reason']}")

    # 3. Additional Test Cases demonstrating other threat categories
    additional_events = [
        (
            "TEST CASE 2: Benign Baseline Event",
            {
                "event_id": "SIM-BENIGN-002",
                "failed_attempts": 0,
                "requests_per_second": 2.5,
                "unique_ports": 1,
                "duration": 15.0,
            },
        ),
        (
            "TEST CASE 3: Volumetric DDoS Traffic Spike",
            {
                "event_id": "SIM-DDOS-003",
                "failed_attempts": 1,
                "requests_per_second": 500.0,
                "unique_ports": 2,
                "duration": 45.0,
            },
        ),
        (
            "TEST CASE 4: Network Port Scan Reconnaissance",
            {
                "event_id": "SIM-SCAN-004",
                "failed_attempts": 1,
                "requests_per_second": 28.0,
                "unique_ports": 210,
                "duration": 8.0,
            },
        ),
    ]

    for title, event in additional_events:
        print("\n" + "-" * 70)
        print(title)
        print("-" * 70)
        print(f"Input Event: {event}")
        res = run_pipeline(event, anomaly_model, classifier_model)
        print(f"  - Extracted Features : {res['features']}")
        print(f"  - Anomaly Score      : {res['anomaly_score']:+.4f}")
        print(f"  - Category           : {res['category']}")
        print(f"  - Attack Type        : {res['attack_type']} ({res['confidence']}%)")
        print(f"  - Severity           : [{res['severity']}]")
        print(f"  - Severity Rationale : {res['reason']}")

    print("\n" + "=" * 70)
    print("ALL M3 AI PIPELINE TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
