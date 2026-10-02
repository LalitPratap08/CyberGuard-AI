# CyberGuard-AI
AI-based simulated cyber attack detection and response system.

## M3 — AI Detection Module

### Purpose
The M3 AI module provides an offline, automated analysis pipeline for simulated cybersecurity events. It extracts numerical telemetry metrics from event logs, identifies anomalous behavior, categorizes attack types, and computes explainable risk severity ratings for educational demonstration.

### AI Pipeline
```text
Synthetic Event → Feature Extraction → Anomaly Detection → Attack Classification → Severity → Final AI Result
```

### Files Created
* `ai/feature_extractor.py` — Sanitizes raw event dictionaries and outputs a normalized numerical feature vector.
* `ai/anomaly_detector.py` — Implements an Isolation Forest to detect behavioral outliers and compute anomaly scores.
* `ai/classifier.py` — Implements a Random Forest Classifier to categorize attacks with confidence scoring.
* `ai/severity.py` — Evaluates multi-factor risk heuristics to assign `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` severity levels.
* `tests/test_ai_pipeline.py` — End-to-end integration test validating the entire AI pipeline.
* `docs/ai-architecture.md` — Detailed technical architecture documentation and specifications.

### Technologies Used
* **Python**
* **scikit-learn**
* **Isolation Forest** (Unsupervised anomaly & outlier detection)
* **Random Forest** (Supervised ensemble multi-class classification)
* **pandas** & **NumPy**

### Synthetic Dataset
* **Dataset File:** `datasets/processed/simulated_events.csv`
* **Generator:** `datasets/raw/generate_dataset.py`
* **Description:** 150 reproducible synthetic records (30 per category) covering 5 simulated classes: `normal`, `brute_force`, `port_scan`, `ddos_like`, and `suspicious_login`, evaluated across four core features (`failed_attempts`, `requests_per_second`, `unique_ports`, `duration`).

### Safety & Simulation Notice
> **Important:** CyberGuard AI is strictly an educational college simulation project operating on in-memory synthetic data. It does **not** perform real-world network attacks, packet sniffing, port scanning, exploitation, or live system monitoring.

### Verification Status
* The complete M3 AI pipeline tests have been executed and **passed successfully** (`tests/test_ai_pipeline.py` exited with code 0).
