import pandas as pd
import joblib


# ==========================================
# Paths
# ==========================================

INPUT_PATH = "data/request_anomaly_results.csv"
MODEL_PATH = "data/attack_classifier.pkl"
OUTPUT_PATH = "data/attack_pipeline_results.csv"


# ==========================================
# Load anomaly results
# ==========================================

df = pd.read_csv(INPUT_PATH)


# ==========================================
# Load attack classifier
# ==========================================

model = joblib.load(MODEL_PATH)


# ==========================================
# Features
# ==========================================

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


# ==========================================
# Select anomalous requests
# ==========================================

anomalous_df = df[
    df["anomaly_prediction"] == -1
].copy()


print("\n=== TWO-STAGE ATTACK DETECTION PIPELINE ===")

print(
    f"Total requests: {len(df)}"
)

print(
    f"Anomalous requests: {len(anomalous_df)}"
)


# ==========================================
# Classify anomalous requests
# ==========================================

if len(anomalous_df) > 0:

    X_anomalous = anomalous_df[FEATURES]

    predictions = model.predict(
        X_anomalous
    )

    anomalous_df["predicted_attack_type"] = predictions

else:

    anomalous_df["predicted_attack_type"] = []


# ==========================================
# Save results
# ==========================================

anomalous_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ==========================================
# Display classification results
# ==========================================

print("\n=== PREDICTED ATTACK TYPES ===")

if len(anomalous_df) > 0:

    print(
        anomalous_df[
            "predicted_attack_type"
        ].value_counts()
    )

else:

    print("No anomalous requests detected.")


print(
    f"\nSaved to: {OUTPUT_PATH}"
)