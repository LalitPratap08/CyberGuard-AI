"""
CyberGuard AI - Synthetic Dataset Generator
-------------------------------------------
This script creates a safe, purely synthetic dataset of simulated cybersecurity
event features for training and testing machine learning models.

Safety Notice:
- This script does NOT perform any network activity, socket connections, or packet scanning.
- No real network logs, sensitive data, or real IP addresses are used.
- All values are mathematically generated pseudo-random numbers with distinct
  statistical distributions representing typical simulated behavior.
"""

import csv
from pathlib import Path
import random

# Fixed random seed for reproducibility
RANDOM_SEED = 42
SAMPLES_PER_CATEGORY = 30  # 5 categories * 30 = 150 total rows


def generate_normal_sample():
    """Generates synthetic features for standard, benign network activity."""
    return {
        "failed_attempts": random.randint(0, 1),
        "requests_per_second": round(random.uniform(0.5, 5.0), 2),
        "unique_ports": random.randint(1, 3),
        "duration": round(random.uniform(1.0, 30.0), 2),
        "attack_type": "normal",
    }


def generate_brute_force_sample():
    """
    Generates synthetic features simulating a brute-force attack.
    Characteristics: High failed attempts against a single service (1-2 ports).
    """
    return {
        "failed_attempts": random.randint(15, 60),
        "requests_per_second": round(random.uniform(3.0, 15.0), 2),
        "unique_ports": random.randint(1, 2),
        "duration": round(random.uniform(30.0, 180.0), 2),
        "attack_type": "brute_force",
    }


def generate_port_scan_sample():
    """
    Generates synthetic features simulating a port scan.
    Characteristics: Probing many unique ports in a short-to-medium timeframe.
    """
    return {
        "failed_attempts": random.randint(0, 2),
        "requests_per_second": round(random.uniform(10.0, 45.0), 2),
        "unique_ports": random.randint(40, 300),
        "duration": round(random.uniform(2.0, 25.0), 2),
        "attack_type": "port_scan",
    }


def generate_ddos_like_sample():
    """
    Generates synthetic features simulating DDoS-like volumetric traffic.
    Characteristics: Exceptionally high request rate targeting standard service ports.
    """
    return {
        "failed_attempts": random.randint(0, 3),
        "requests_per_second": round(random.uniform(150.0, 800.0), 2),
        "unique_ports": random.randint(1, 5),
        "duration": round(random.uniform(10.0, 120.0), 2),
        "attack_type": "ddos_like",
    }


def generate_suspicious_login_sample():
    """
    Generates synthetic features simulating suspicious login activity.
    Characteristics: Low/slow request speed, single port, multiple failed logins.
    """
    return {
        "failed_attempts": random.randint(3, 8),
        "requests_per_second": round(random.uniform(0.1, 1.5), 2),
        "unique_ports": 1,
        "duration": round(random.uniform(5.0, 45.0), 2),
        "attack_type": "suspicious_login",
    }


def generate_dataset(output_filepath, samples_per_category=SAMPLES_PER_CATEGORY):
    """
    Generates the synthetic dataset across all categories and saves it as a CSV.
    """
    # Seed the random generator for reproducible output
    random.seed(RANDOM_SEED)

    generators = [
        generate_normal_sample,
        generate_brute_force_sample,
        generate_port_scan_sample,
        generate_ddos_like_sample,
        generate_suspicious_login_sample,
    ]

    fieldnames = [
        "failed_attempts",
        "requests_per_second",
        "unique_ports",
        "duration",
        "attack_type",
    ]

    rows = []
    for gen in generators:
        for _ in range(samples_per_category):
            rows.append(gen())

    # Shuffle rows so categories are mixed naturally
    random.shuffle(rows)

    # Ensure destination directory exists
    output_path = Path(output_filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write synthetic rows to CSV
    with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


if __name__ == "__main__":
    # Save directly to datasets/processed/simulated_events.csv relative to this script
    base_dir = Path(__file__).resolve().parent.parent
    target_csv = base_dir / "processed" / "simulated_events.csv"

    print("=" * 60)
    print("CyberGuard AI - Synthetic Dataset Generation")
    print("=" * 60)
    print(f"Generating synthetic events with random seed {RANDOM_SEED}...")

    total_rows = generate_dataset(target_csv)

    print(f"SUCCESS: Generated {total_rows} synthetic rows across 5 categories.")
    print(f"Dataset saved to: {target_csv.resolve()}")
    print("=" * 60)
