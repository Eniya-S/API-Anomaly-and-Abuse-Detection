import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score


INPUT_PATH = "data/request_features.csv"


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
# Load dataset
# ==========================================

df = pd.read_csv(INPUT_PATH)


# ==========================================
# Train / Test Split
# ==========================================

train_df, test_df = train_test_split(
    df,
    test_size=0.20,
    random_state=42,
    stratify=df["label"]
)


print("\n=== TWO-STAGE PIPELINE EVALUATION ===")
print(f"Total requests: {len(df)}")
print(f"Training requests: {len(train_df)}")
print(f"Testing requests: {len(test_df)}")


# ==========================================
# STAGE 1: Isolation Forest
# Train only on NORMAL requests
# ==========================================

normal_train = train_df[
    train_df["label"] == "Normal"
]

anomaly_model = IsolationForest(
    n_estimators=300,
    contamination=0.20,
    random_state=42
)

anomaly_model.fit(
    normal_train[FEATURES]
)


# ==========================================
# STAGE 2: Random Forest
# Train only on ATTACK requests
# ==========================================

attack_train = train_df[
    train_df["label"] != "Normal"
]

classifier = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced"
)

classifier.fit(
    attack_train[FEATURES],
    attack_train["label"]
)


# ==========================================
# Run complete pipeline on TEST data
# ==========================================

test_df = test_df.copy()

test_df["anomaly_prediction"] = anomaly_model.predict(
    test_df[FEATURES]
)

print("\n=== ANOMALY DETECTION BY ATTACK TYPE ===")

for label in test_df["label"].unique():
    subset = test_df[test_df["label"] == label]

    if label == "Normal":
        continue

    detected = (subset["anomaly_prediction"] == -1).sum()
    total = len(subset)
    detection_rate = detected / total * 100

    print(f"{label}: {detected}/{total} ({detection_rate:.2f}%)")

# ==========================================
# Final pipeline prediction
# ==========================================

test_df["final_prediction"] = "Normal"

anomalies = test_df[
    test_df["anomaly_prediction"] == -1
]

if len(anomalies) > 0:

    predicted_attacks = classifier.predict(
        anomalies[FEATURES]
    )

    test_df.loc[
        anomalies.index,
        "final_prediction"
    ] = predicted_attacks


# ==========================================
# ONE COMBINED PIPELINE ACCURACY
# ==========================================

correct_predictions = (
    test_df["final_prediction"]
    == test_df["label"]
).sum()

total_requests = len(test_df)

overall_accuracy = (
    correct_predictions
    / total_requests
) * 100


# ==========================================
# BINARY ANOMALY METRICS
#
# For comparison with the base paper:
#
# Normal  = 0
# Attack  = 1
# ==========================================

actual_binary = (
    test_df["label"] != "Normal"
).astype(int)

predicted_binary = (
    test_df["final_prediction"] != "Normal"
).astype(int)


precision = precision_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)

recall = recall_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)

f1 = f1_score(
    actual_binary,
    predicted_binary,
    zero_division=0
)


# ==========================================
# Final Results
# ==========================================

print("\n=== FINAL PIPELINE RESULTS ===")

print(
    f"Total test requests: "
    f"{total_requests}"
)

print(
    f"Correctly handled requests: "
    f"{correct_predictions}"
)

print(
    f"Overall Pipeline Accuracy: "
    f"{overall_accuracy:.2f}%"
)

print("\n=== BINARY ANOMALY DETECTION METRICS ===")

print(
    f"Precision: "
    f"{precision * 100:.2f}%"
)

print(
    f"Recall: "
    f"{recall * 100:.2f}%"
)

print(
    f"F1-Score: "
    f"{f1 * 100:.2f}%"
)