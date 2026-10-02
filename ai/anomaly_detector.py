"""
CyberGuard AI - Anomaly Detector Module
---------------------------------------
This module uses scikit-learn's Isolation Forest algorithm to detect anomalies
in simulated cybersecurity events based on extracted numerical features.

Safety Notice:
- Purely analyzes simulated synthetic event metrics offline.
- No network operations, sniffing, scanning, or attack generation are performed.
"""

from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest

# Expected numerical features for training and inference
FEATURE_COLUMNS = [
    "failed_attempts",
    "requests_per_second",
    "unique_ports",
    "duration",
]

# Default path to the processed synthetic dataset
DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "processed"
    / "simulated_events.csv"
)


def load_dataset(csv_path=None):
    """
    Load the synthetic cybersecurity events dataset into a pandas DataFrame.

    Parameters:
        csv_path (str or Path, optional): Path to the CSV file.
            Defaults to 'datasets/processed/simulated_events.csv'.

    Returns:
        pandas.DataFrame: Loaded dataset.
    """
    target_path = Path(csv_path) if csv_path else DEFAULT_DATASET_PATH
    if not target_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {target_path}. "
            "Please generate it first by running datasets/raw/generate_dataset.py"
        )
    return pd.read_csv(target_path)


def train_detector(data=None, contamination="auto", random_state=42):
    """
    Train an Isolation Forest model on numerical cybersecurity features.

    Isolation Forest isolates observations by randomly selecting a feature and
    splitting value. Outliers (anomalies) require fewer splits to isolate than normal points.

    Parameters:
        data (pandas.DataFrame or str or Path, optional):
            The training data or path to the CSV file. If None, loads from DEFAULT_DATASET_PATH.
        contamination (float or 'auto', optional):
            Expected proportion of outliers in the dataset. Defaults to 'auto'.
        random_state (int, optional):
            Fixed random seed for reproducible training results. Defaults to 42.

    Returns:
        sklearn.ensemble.IsolationForest: Fitted anomaly detection model.
    """
    # If data is a path or not provided, load via pandas
    if data is None or isinstance(data, (str, Path)):
        df = load_dataset(data)
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        raise TypeError("Expected data to be a pandas DataFrame, file path, or None.")

    # Validate that all required numerical feature columns exist
    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Training data is missing required feature columns: {missing_cols}")

    # Extract only the numerical feature columns
    x_train = df[FEATURE_COLUMNS]

    # Initialize Isolation Forest with a fixed seed for reproducible behavior
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
    )

    # Train model on numerical features
    model.fit(x_train)
    return model


def predict_anomaly(model, feature_vector):
    """
    Evaluate a new simulated event feature vector using the trained Isolation Forest.

    Parameters:
        model (IsolationForest): Trained Isolation Forest model.
        feature_vector (list or numpy.ndarray): Numerical vector with 4 values:
            [failed_attempts, requests_per_second, unique_ports, duration]

    Returns:
        dict: A dictionary containing the interpretation:
            - is_anomaly (bool): True if classified as an anomaly, False if normal.
            - label (str): 'anomalous' or 'normal'.
            - prediction (int): 1 for normal (inlier), -1 for anomaly (outlier).
            - anomaly_score (float): Decision function score.
                * Negative values indicate strong abnormality.
                * Positive values indicate expected/normal behavior.
    """
    # Ensure feature vector matches expected column names to avoid warnings
    if isinstance(feature_vector, pd.DataFrame):
        sample_df = feature_vector[FEATURE_COLUMNS]
    else:
        # Wrap single 1D vector into a DataFrame
        sample_df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)

    # Run inference
    raw_pred = int(model.predict(sample_df)[0])
    raw_score = float(model.decision_function(sample_df)[0])

    # Interpretation: In scikit-learn IsolationForest:
    #   prediction ==  1 -> Inlier (Normal behavior)
    #   prediction == -1 -> Outlier (Anomalous behavior)
    is_anomaly = (raw_pred == -1)
    label = "anomalous" if is_anomaly else "normal"

    return {
        "is_anomaly": is_anomaly,
        "label": label,
        "prediction": raw_pred,
        "anomaly_score": round(raw_score, 4),
    }


# =====================================================================
# Safe Local Demonstration & Test
# =====================================================================
if __name__ == "__main__":
    print("=" * 65)
    print("CyberGuard AI - Anomaly Detector (Isolation Forest)")
    print("=" * 65)

    # 1. Load dataset & train detector
    print(f"\n[1] Loading dataset from: {DEFAULT_DATASET_PATH.name}")
    dataset = load_dataset()
    print(f"    Loaded {len(dataset)} simulated event records.")

    print("\n[2] Training Isolation Forest detector (random_state=42)...")
    detector = train_detector(dataset)
    print("    Training completed successfully.")

    # 2. Test with sample simulated event vectors
    # Format: [failed_attempts, requests_per_second, unique_ports, duration]
    test_samples = [
        (
            "Simulated Normal Traffic",
            [0, 2.5, 1, 12.0],
            "Expected: Low attempts, low RPS, single port -> Normal",
        ),
        (
            "Simulated Volumetric DDoS Flood",
            [1, 650.0, 2, 45.0],
            "Expected: Extreme requests_per_second -> Anomalous",
        ),
        (
            "Simulated SSH Brute Force Burst",
            [45, 12.0, 1, 140.0],
            "Expected: High failed_attempts -> Anomalous",
        ),
        (
            "Simulated Port Scan",
            [1, 35.0, 220, 10.0],
            "Expected: Very high unique_ports probe -> Outlier characteristic",
        ),
    ]

    print("\n[3] Evaluating simulated test vectors:\n")
    for name, vector, description in test_samples:
        result = predict_anomaly(detector, vector)
        status_tag = "[ANOMALY DETECTED]" if result["is_anomaly"] else "[NORMAL EVENT]"

        print(f"--- {name} ---")
        print(f"  Note:          {description}")
        print(f"  Feature Vector:{vector}")
        print(f"  Result:        {status_tag}")
        print(f"  Label:         '{result['label']}' (sklearn raw prediction: {result['prediction']})")
        print(f"  Anomaly Score: {result['anomaly_score']:+.4f} (negative = anomalous, positive = normal)\n")

    print("=" * 65)
    print("All tests completed safely and successfully!")
    print("=" * 65)
