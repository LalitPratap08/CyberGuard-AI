# CyberGuard AI - M3 AI Module Architecture

## 1. Important Educational & Safety Notice

> **College Project & Simulation Scope**
> - **Synthetic Data Only:** This project operates entirely on simulated in-memory data generated for educational demonstration.
> - **No Real-World Attack Activity:** This module does **not** perform network sniffing, port scanning, vulnerability exploitation, penetration testing, or live packet interception.
> - **Educational Baseline:** Heuristics, thresholds, and ML classifications in this project demonstrate basic AI concepts and are **not** claimed to be production-ready or suitable for real-world enterprise intrusion detection systems.

---

## 2. Purpose of the AI Module

The **M3 AI Module** provides an automated decision-support pipeline for simulated cybersecurity events. When given a simulated event log, the module:
1. Sanitizes and transforms raw dictionary data into a clean numerical feature vector.
2. Identifies whether the event deviates significantly from standard behavior (**Anomaly Detection**).
3. Classifies the event into an attack category or normal traffic (**Attack Classification**).
4. Computes an explainable risk rating (**Severity Assessment**).

---

## 3. High-Level Architecture Diagram

```text
+-----------------------------------------------------------------------+
|                       Simulated Event Dictionary                      |
|  { "failed_attempts": 27, "requests_per_second": 5, "unique_ports": 1, |
|    "duration": 60, ... }                                              |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                      Stage 1: Feature Extractor                       |
|                       (ai/feature_extractor.py)                       |
|   - Validates input dictionary                                        |
|   - Safely casts missing/None values to defaults                      |
|   - Produces fixed 1D vector: [27.0, 5.0, 1.0, 60.0]                  |
+-----------------------------------------------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
            v                                               v
+-------------------------------+               +-------------------------------+
|   Stage 2: Anomaly Detector   |               |  Stage 3: Attack Classifier   |
|   (ai/anomaly_detector.py)    |               |      (ai/classifier.py)       |
|       Isolation Forest        |               |         Random Forest         |
|   - Evaluates isolation depth |               |   - Evaluates 100 decision    |
|   - Outputs:                  |               |     trees via majority vote   |
|     * category (normal/anom.) |               |   - Outputs:                  |
|     * anomaly_score (decision)|               |     * attack_type             |
+-------------------------------+               |     * confidence (%)          |
            |                                   +-------------------------------+
            |                                               |
            +-----------------------+-----------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                     Stage 4: Severity Assessment                      |
|                          (ai/severity.py)                             |
|   - Combines anomaly flag, decision score, attack class, and metrics  |
|   - Evaluates transparent rule thresholds                             |
|   - Assigns: LOW | MEDIUM | HIGH | CRITICAL                           |
+-----------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------+
|                          Final AI Result                              |
|   { "anomaly_score": +0.0153, "category": "normal",                   |
|     "attack_type": "brute_force", "severity": "HIGH" }                |
+-----------------------------------------------------------------------+
```

---

## 4. End-to-End AI Pipeline

The pipeline follows a sequential, modular process:

1. **Synthetic Event Ingestion:** The system receives a dictionary representing a simulated telemetry record (which may include metadata like timestamps, event IDs, and numerical metrics).
2. **Feature Extraction:** Non-numerical fields are discarded; numerical fields are validated and formatted into a standardized vector.
3. **Anomaly Detection:** The vector is passed to an Isolation Forest to determine whether the behavior is an outlier relative to baseline patterns.
4. **Attack Classification:** Simultaneously, the vector is evaluated by a Random Forest Classifier to assign a specific category label and confidence percentage.
5. **Severity Calculation:** The combined results (anomaly status, anomaly score, predicted attack type, and metric intensities) are evaluated against explainable rules to assign a final risk severity.
6. **Final AI Output:** A consolidated JSON/dictionary response is returned.

---

## 5. File Breakdown

| File Path | Core Role | Key Functions |
| :--- | :--- | :--- |
| `ai/feature_extractor.py` | Extracts numerical metrics from dictionary inputs | `extract_features(event)` |
| `ai/anomaly_detector.py` | Trains and runs unsupervised anomaly detection | `load_dataset()`, `train_detector()`, `predict_anomaly()` |
| `ai/classifier.py` | Trains and runs multi-class attack classification | `load_dataset()`, `train_classifier()`, `predict_attack_type()` |
| `ai/severity.py` | Assigns an explainable risk severity level | `calculate_severity()` |
| `tests/test_ai_pipeline.py` | End-to-end integration test verifying all 4 modules | `run_pipeline()`, `main()` |

### Detailed File Descriptions

* **`ai/feature_extractor.py`**:
  Accepts raw simulated event dictionaries, handles missing or malformed values gracefully (defaulting safely to `0.0`), and produces an ordered numerical list `[failed_attempts, requests_per_second, unique_ports, duration]` ready for machine learning models.
* **`ai/anomaly_detector.py`**:
  Utilizes scikit-learn's `IsolationForest` algorithm trained on numerical event features. Returns both a binary label (`normal` vs `anomalous`) and a continuous `anomaly_score` where lower/negative values indicate greater abnormality.
* **`ai/classifier.py`**:
  Utilizes scikit-learn's `RandomForestClassifier` trained on synthetic event categories. Returns the predicted `attack_type` alongside a probability confidence percentage.
* **`ai/severity.py`**:
  Implements clear, educational heuristic thresholds that synthesize the outputs of the detector and classifier to assign one of four severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **`tests/test_ai_pipeline.py`**:
  An automated test script that feeds multiple synthetic events (benign traffic, brute force, port scans, and volumetric DDoS spikes) through all 4 modules and verifies that the complete pipeline runs cleanly end-to-end.

---

## 6. Synthetic Dataset Overview

* **File Location:** `datasets/processed/simulated_events.csv`
* **Generator Script:** `datasets/raw/generate_dataset.py`
* **Size:** 150 synthetic records (30 samples per category) generated with a fixed random seed (`seed = 42`) for 100% reproducibility.

### Synthetic Feature Definitions

| Feature Name | Type | Description | Typical Normal Range | Typical Attack Range |
| :--- | :--- | :--- | :--- | :--- |
| `failed_attempts` | Integer | Count of failed authentication/login requests | `0 – 1` | `15 – 60` (Brute Force) |
| `requests_per_second` | Float | Frequency of incoming network requests | `0.5 – 5.0` | `150.0 – 800.0` (DDoS-like) |
| `unique_ports` | Integer | Number of distinct destination ports targeted | `1 – 3` | `40 – 300` (Port Scan) |
| `duration` | Float | Total connection/session duration in seconds | `1.0 – 30.0` | `30.0 – 180.0` (Persistent Attack) |

### Simulated Target Classes (`attack_type`)

1. **`normal`**: Low failed attempts, low request rate, minimal ports targeted.
2. **`brute_force`**: Abnormally high failed logins against a single port.
3. **`port_scan`**: High count of probed unique ports in a short timeframe.
4. **`ddos_like`**: Extreme volume of requests per second.
5. **`suspicious_login`**: Low-speed, repeated failed logins (e.g. credential stuffing).

---

## 7. Machine Learning Methods Explained

### 1. Isolation Forest (Anomaly Detection)
* **Library:** `sklearn.ensemble.IsolationForest`
* **Type:** Unsupervised Outlier Detection.
* **Concept:** Instead of modeling what "normal" looks like, Isolation Forest explicitly isolates anomalous points. Because anomalies have unusual values (e.g. 500 requests/sec or 250 ports), they require far fewer random splits to isolate in a decision tree than normal data points.
* **Outputs:**
  - `prediction`: `1` represents an inlier (normal), `-1` represents an outlier (anomaly).
  - `anomaly_score`: Continuous decision score. Higher positive scores indicate typical inliers; negative scores indicate strong anomalies.

### 2. Random Forest Classifier (Attack Classification)
* **Library:** `sklearn.ensemble.RandomForestClassifier`
* **Type:** Supervised Ensemble Classification.
* **Concept:** Combines an ensemble of multiple independent decision trees (default 100 trees). Each tree evaluates a random subset of features and votes on the final class. The majority vote determines the predicted `attack_type`, and the proportion of votes determines the `confidence` score.
* **Outputs:**
  - `attack_type`: Predicted category (`normal`, `brute_force`, `port_scan`, `ddos_like`, `suspicious_login`).
  - `confidence`: Confidence probability between 0.0 and 1.0 (e.g. `100.0%`).

---

## 8. Severity Level Definitions

The severity calculation uses transparent, explainable rules:

| Severity Level | Criteria / Simulated Scenario | Typical Example |
| :--- | :--- | :--- |
| **`LOW`** | Standard benign activity within baseline parameters. | Baseline web request (`failed_attempts=0`, `rps=2.1`) |
| **`MEDIUM`** | Minor anomalies, suspicious login attempts, or unconfirmed anomalous traffic. | Nominal traffic with minor anomaly flag or slow credential trial (`failed_attempts=5`) |
| **`HIGH`** | Active network enumeration, aggressive port scans, or moderate brute force. | Wide port scan (`unique_ports=220`) or moderate brute force (`failed_attempts=18`) |
| **`CRITICAL`** | Direct threats to system availability or severe automated cracking storms. | Volumetric DDoS flood (`rps=600.0`) or intense brute force (`failed_attempts=45`) |

---

## 9. Example Final AI Result

When a simulated event such as:
```json
{
  "failed_attempts": 27,
  "requests_per_second": 5,
  "unique_ports": 1,
  "duration": 60
}
```
is processed through the pipeline, the system outputs:

```json
{
  "anomaly_score": 0.0153,
  "category": "normal",
  "attack_type": "brute_force",
  "confidence": 100.0,
  "severity": "HIGH",
  "reason": "Automated brute force attack detected with 27 failed attempts. Active credential guessing in progress."
}
```

Or in concise format:
```json
{
  "anomaly_score": 0.91,
  "category": "attack",
  "attack_type": "brute_force",
  "severity": "HIGH"
}
```

---

## 10. Summary

The CyberGuard AI M3 module establishes an educational, safe, and fully reproducible pipeline for demonstrating machine learning in a cybersecurity context. Every component is self-contained, operates offline without external network requirements, and is thoroughly documented for classroom and project presentations.
