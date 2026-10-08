import pandas as pd
from sklearn.ensemble import IsolationForest


INPUT_PATH = "data/request_features.csv"


# ==========================================
# Load features
# ==========================================

df = pd.read_csv(INPUT_PATH)


# ==========================================
# Features used by the model
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
# Train only on normal requests
# ==========================================

normal_df = df[
    df["label"] == "Normal"
].copy()

X_train = normal_df[FEATURES]


# ==========================================
# Isolation Forest
# ==========================================

model = IsolationForest(
    n_estimators=300,
    contamination=0.15,
    random_state=42
)


model.fit(X_train)


# ==========================================
# Predict all requests
# ==========================================

X_all = df[FEATURES]

predictions = model.predict(X_all)

df["anomaly_prediction"] = predictions


# -1 = anomaly
#  1 = normal


# ==========================================
# Evaluate attack detection
# ==========================================

attack_df = df[
    df["label"] != "Normal"
]

normal_df_test = df[
    df["label"] == "Normal"
]


detected_attacks = (
    attack_df["anomaly_prediction"] == -1
).sum()

total_attacks = len(attack_df)

missed_attacks = (
    attack_df["anomaly_prediction"] == 1
).sum()


normal_correct = (
    normal_df_test["anomaly_prediction"] == 1
).sum()

false_positives = (
    normal_df_test["anomaly_prediction"] == -1
).sum()


attack_detection_rate = (
    detected_attacks / total_attacks
) * 100

false_positive_rate = (
    false_positives / len(normal_df_test)
) * 100


# ==========================================
# Results
# ==========================================

print("\n=== REQUEST ANOMALY DETECTION ===")

print(
    f"Normal requests for training: "
    f"{len(normal_df)}"
)

print(
    f"Total requests for testing: "
    f"{len(df)}"
)


print("\n=== RESULTS ===")

print(
    f"Total attack requests: "
    f"{total_attacks}"
)

print(
    f"Detected attacks: "
    f"{detected_attacks}"
)

print(
    f"Missed attacks: "
    f"{missed_attacks}"
)

print(
    f"Attack detection rate: "
    f"{attack_detection_rate:.2f}%"
)


print(
    f"\nNormal requests correctly identified: "
    f"{normal_correct} / {len(normal_df_test)}"
)

print(
    f"False positives: "
    f"{false_positives}"
)

print(
    f"False positive rate: "
    f"{false_positive_rate:.2f}%"
)


# ==========================================
# Detection by attack type
# ==========================================

print("\n=== DETECTION BY ATTACK TYPE ===")

for attack_type in sorted(
    attack_df["label"].unique()
):

    attack_type_df = attack_df[
        attack_df["label"] == attack_type
    ]

    detected = (
        attack_type_df["anomaly_prediction"] == -1
    ).sum()

    total = len(attack_type_df)

    rate = (
        detected / total
    ) * 100

    print(
        f"{attack_type}: "
        f"{detected}/{total} "
        f"detected ({rate:.2f}%)"
    )


# ==========================================
# Save results
# ==========================================

OUTPUT_PATH = "data/request_anomaly_results.csv"

df.to_csv(
    OUTPUT_PATH,
    index=False
)

print(
    f"\nSaved to: {OUTPUT_PATH}"
)