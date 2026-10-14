import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

INPUT_PATH = "data/request_features.csv"
OUTPUT_PATH = "data/request_anomaly_results.csv"
MODEL_PATH = "data/isolation_forest.pkl"

FEATURES = [
    "url_length",
    "path_length",
    "path_depth",
    "query_param_count",
    "encoded_char_count",
    "special_char_count",
    "encoded_ratio",
    "special_char_ratio",
    "query_length",
    "request_header_count",
    "user_agent_length",
    "total_header_length",
    "max_header_value_length",
    "body_length",
    "status_code",
    "response_body_length",
    "response_header_count",
    "response_body_to_url_ratio",
    "method_encoded"
]

# Load Dataset 1 features
df = pd.read_csv(INPUT_PATH)

# Train only on normal requests
normal_df = df[df["label"] == "Normal"].copy()
X_train = normal_df[FEATURES]

# Create and train Isolation Forest
model = IsolationForest(
    n_estimators=300,
    contamination=0.15,
    random_state=42
)
model.fit(X_train)

# Save the trained model for future reuse
joblib.dump(model, MODEL_PATH)
print(f"\nSaved trained Isolation Forest to: {MODEL_PATH}")

# Predict all Dataset 1 requests
df["anomaly_prediction"] = model.predict(df[FEATURES])

# Evaluate attack detection
attack_df = df[df["label"] != "Normal"]
normal_test_df = df[df["label"] == "Normal"]

detected_attacks = (attack_df["anomaly_prediction"] == -1).sum()
total_attacks = len(attack_df)
missed_attacks = (attack_df["anomaly_prediction"] == 1).sum()

normal_correct = (normal_test_df["anomaly_prediction"] == 1).sum()
false_positives = (normal_test_df["anomaly_prediction"] == -1).sum()

attack_detection_rate = (
    detected_attacks / total_attacks * 100 if total_attacks else 0
)
false_positive_rate = (
    false_positives / len(normal_test_df) * 100
    if len(normal_test_df) else 0
)

print("\n=== REQUEST ANOMALY DETECTION ===")
print(f"Normal requests for training: {len(normal_df)}")
print(f"Total requests evaluated: {len(df)}")

print("\n=== RESULTS ===")
print(f"Total attack requests: {total_attacks}")
print(f"Detected attacks: {detected_attacks}")
print(f"Missed attacks: {missed_attacks}")
print(f"Attack detection rate: {attack_detection_rate:.2f}%")
print(
    f"\nNormal requests correctly identified: "
    f"{normal_correct} / {len(normal_test_df)}"
)
print(f"False positives: {false_positives}")
print(f"False positive rate: {false_positive_rate:.2f}%")

print("\n=== DETECTION BY ATTACK TYPE ===")
for attack_type in sorted(attack_df["label"].unique()):
    subset = attack_df[attack_df["label"] == attack_type]
    detected = (subset["anomaly_prediction"] == -1).sum()
    total = len(subset)
    rate = detected / total * 100 if total else 0
    print(f"{attack_type}: {detected}/{total} detected ({rate:.2f}%)")

# Save predictions
df.to_csv(OUTPUT_PATH, index=False)
print(f"\nSaved results to: {OUTPUT_PATH}")
