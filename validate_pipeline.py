
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

VALIDATION_PATH = "data/validation_features.csv"
TRAIN_PATH = "data/request_features.csv"
CLASSIFIER_PATH = "data/attack_classifier.pkl"
OUTPUT_PATH = "data/validation_pipeline_results.csv"

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

# Load training and validation features
train_df = pd.read_csv(TRAIN_PATH)
val_df = pd.read_csv(VALIDATION_PATH)

# Train Isolation Forest on normal training requests only
normal_df = train_df[train_df["label"] == "Normal"]

anomaly_model = IsolationForest(
    n_estimators=300,
    contamination=0.15,
    random_state=42
)
anomaly_model.fit(normal_df[FEATURES])

# Detect anomalies in validation requests
val_df["anomaly_prediction"] = anomaly_model.predict(
    val_df[FEATURES]
)

# Load the saved attack classifier
classifier = joblib.load(CLASSIFIER_PATH)

# Classify requests detected as anomalous
val_df["predicted_attack_type"] = "Normal"

anomaly_mask = val_df["anomaly_prediction"] == -1

if anomaly_mask.any():
    val_df.loc[anomaly_mask, "predicted_attack_type"] = (
        classifier.predict(val_df.loc[anomaly_mask, FEATURES])
    )

# Display results
print("\n=== VALIDATION PIPELINE RESULTS ===")
print(f"Total validation requests: {len(val_df)}")
print(f"Flagged as anomalous: {anomaly_mask.sum()}")
print(f"Not flagged as anomalous: {(~anomaly_mask).sum()}")

print("\n=== PREDICTED REQUEST CATEGORIES ===")
print(val_df["predicted_attack_type"].value_counts())

print("\n=== ANOMALY PREDICTION COUNTS ===")
print(val_df["anomaly_prediction"].value_counts().rename({
    -1: "Anomaly",
    1: "Not anomalous"
}))

val_df.to_csv(OUTPUT_PATH, index=False)
print(f"\nSaved results to: {OUTPUT_PATH}")
