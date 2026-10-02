"""
CyberGuard AI - Attack Type Classifier Module
---------------------------------------------
This module uses scikit-learn's RandomForestClassifier to categorize simulated
cybersecurity events into specific attack classes based on numerical features.

Classified Attack Types:
- normal: Standard benign simulated activity
- brute_force: Repeated failed logins against a single service
- port_scan: Probing numerous ports in a short duration
- ddos_like: Unusually high requests-per-second volumetric flood
- suspicious_login: Slow, deliberate credential guessing attempts

Safety Notice:
- Purely analyzes simulated synthetic event metrics offline.
- No network operations, sniffing, scanning, or attack generation are performed.
"""

from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Numerical features used for classification
FEATURE_COLUMNS = [
    "failed_attempts",
    "requests_per_second",
    "unique_ports",
    "duration",
]

# Target label to predict
TARGET_COLUMN = "attack_type"

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
        pandas.DataFrame: Loaded dataset containing features and target column.
    """
    target_path = Path(csv_path) if csv_path else DEFAULT_DATASET_PATH
    if not target_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at: {target_path}. "
            "Please generate it first by running datasets/raw/generate_dataset.py"
        )
    return pd.read_csv(target_path)


def train_classifier(data=None, n_estimators=100, random_state=42):
    """
    Train a Random Forest classifier on synthetic cybersecurity event data.

    A Random Forest creates an ensemble of multiple decision trees and combines
    their votes to produce an accurate and stable classification.

    Parameters:
        data (pandas.DataFrame or str or Path, optional):
            Training DataFrame or path to CSV. If None, loads from DEFAULT_DATASET_PATH.
        n_estimators (int, optional):
            Number of decision trees in the forest. Defaults to 100.
        random_state (int, optional):
            Fixed random seed for reproducible training results. Defaults to 42.

    Returns:
        sklearn.ensemble.RandomForestClassifier: The trained classification model.
    """
    # 1. Load data if needed
    if data is None or isinstance(data, (str, Path)):
        df = load_dataset(data)
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        raise TypeError("Expected data to be a pandas DataFrame, file path, or None.")

    # 2. Check for required feature and target columns
    required_cols = FEATURE_COLUMNS + [TARGET_COLUMN]
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in dataset: {missing}")

    # 3. Separate features (X) and target labels (y)
    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]

    # 4. Initialize and fit the Random Forest classifier
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
    )
    model.fit(X, y)

    return model


def predict_attack_type(model, feature_vector):
    """
    Predict the attack type for a new simulated event feature vector.

    Parameters:
        model (RandomForestClassifier): Trained Random Forest model.
        feature_vector (list or numpy.ndarray or dict or pandas.DataFrame):
            Numerical vector of 4 features in order:
            [failed_attempts, requests_per_second, unique_ports, duration]

    Returns:
        dict: A dictionary containing:
            - attack_type (str): Predicted category (e.g. 'normal', 'brute_force').
            - confidence (float): Probability confidence score between 0.0 and 1.0.
            - probabilities (dict): Probability distribution across all possible categories.
    """
    # Convert input to DataFrame with feature names to ensure compatibility
    if isinstance(feature_vector, pd.DataFrame):
        sample_df = feature_vector[FEATURE_COLUMNS]
    elif isinstance(feature_vector, dict):
        sample_df = pd.DataFrame([{col: feature_vector.get(col, 0.0) for col in FEATURE_COLUMNS}])
    else:
        # Assumes a 1D list or array of numerical values
        sample_df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)

    # 1. Predict the most likely attack category
    predicted_label = str(model.predict(sample_df)[0])

    # 2. Obtain class probabilities from all ensemble trees
    probabilities_raw = model.predict_proba(sample_df)[0]
    class_probabilities = {
        cls_name: round(float(prob), 4)
        for cls_name, prob in zip(model.classes_, probabilities_raw)
    }

    # 3. Extract the confidence for the predicted class
    confidence = float(max(probabilities_raw))

    return {
        "attack_type": predicted_label,
        "confidence": round(confidence, 4),
        "probabilities": class_probabilities,
    }


# =====================================================================
# Safe Local Demonstration & Test
# =====================================================================
if __name__ == "__main__":
    print("=" * 65)
    print("CyberGuard AI - Attack Type Classifier (Random Forest)")
    print("=" * 65)

    # Step 1: Load dataset and train the model
    print(f"\n[1] Loading synthetic dataset from: {DEFAULT_DATASET_PATH.name}")
    dataset = load_dataset()
    print(f"    Loaded {len(dataset)} records across {dataset[TARGET_COLUMN].nunique()} categories.")

    print("\n[2] Training Random Forest Classifier (random_state=42)...")
    classifier = train_classifier(dataset)
    print(f"    Trained successfully with {len(classifier.classes_)} attack classes:")
    for cls_name in sorted(classifier.classes_):
        print(f"      - {cls_name}")

    # Step 2: Test with simulated event feature vectors
    # Format: [failed_attempts, requests_per_second, unique_ports, duration]
    test_cases = [
        (
            "Simulated Normal Activity",
            [0, 2.1, 2, 8.0],
            "Expected: normal",
        ),
        (
            "Simulated SSH Brute Force",
            [40, 6.5, 1, 110.0],
            "Expected: brute_force",
        ),
        (
            "Simulated Network Port Scan",
            [1, 30.0, 180, 12.0],
            "Expected: port_scan",
        ),
        (
            "Simulated Volumetric DDoS Flood",
            [2, 600.0, 3, 50.0],
            "Expected: ddos_like",
        ),
        (
            "Simulated Stealthy Login",
            [6, 0.8, 1, 22.0],
            "Expected: suspicious_login",
        ),
    ]

    print("\n[3] Testing inference on simulated event vectors:\n")
    for name, vector, note in test_cases:
        prediction = predict_attack_type(classifier, vector)
        attack_label = prediction["attack_type"]
        confidence_pct = prediction["confidence"] * 100

        print(f"--- {name} ---")
        print(f"  Note:           {note}")
        print(f"  Feature Vector: {vector}")
        print(f"  Predicted Type: [ {attack_label.upper()} ]")
        print(f"  Confidence:     {confidence_pct:.1f}%")
        print(f"  Probabilities:  {prediction['probabilities']}\n")

    print("=" * 65)
    print("Classifier test ran successfully!")
    print("=" * 65)
