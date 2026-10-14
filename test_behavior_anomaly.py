import json
import pandas as pd
from sklearn.ensemble import IsolationForest

NORMAL_PATH = "data/user_behavior_profiles.json"
ATTACK_PATH = "data/attack_behavior_profiles.json"
OUTPUT_PATH = "data/behavior_detection_results.json"


# ==========================================
# Load normal profiles
# ==========================================

with open(NORMAL_PATH, "r", encoding="utf-8") as f:
    normal_profiles = json.load(f)

with open(ATTACK_PATH, "r", encoding="utf-8") as f:
    attack_profiles = json.load(f)


# ==========================================
# Behavioral features
# ==========================================

FEATURES = [
    "requests",
    "duration_seconds",
    "request_rate_per_minute",
    "average_gap_seconds",
    "endpoint_families",
    "unique_endpoints",
    "endpoint_diversity",
    "repeated_endpoint_ratio",
    "get_ratio",
    "post_ratio",
    "failure_rate"
]


# ==========================================
# Train using NORMAL behavior only
# ==========================================

normal_df = pd.DataFrame(normal_profiles)

X_train = normal_df[FEATURES]


model = IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=42
)

model.fit(X_train)


# ==========================================
# Test on attack-injected profiles
# ==========================================

attack_df = pd.DataFrame(attack_profiles)

X_test = attack_df[FEATURES]


attack_df["prediction"] = model.predict(X_test)

attack_df["anomaly_score"] = model.decision_function(
    X_test
)


attack_df["detected_behavior"] = attack_df[
    "prediction"
].apply(
    lambda x:
        "anomalous"
        if x == -1
        else "normal"
)


# ==========================================
# Compare with ground truth
# ==========================================

attack_df["detection_correct"] = (
    (attack_df["contains_attack"] == True)
    &
    (attack_df["detected_behavior"] == "anomalous")
)


# ==========================================
# Save results
# ==========================================

results = attack_df.to_dict(
    orient="records"
)

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        results,
        f,
        indent=2
    )


# ==========================================
# Results
# ==========================================

attack_users = attack_df[
    attack_df["contains_attack"] == True
]

detected_attacks = attack_users[
    attack_users["detected_behavior"] == "anomalous"
]

missed_attacks = attack_users[
    attack_users["detected_behavior"] == "normal"
]


print("\n=== BEHAVIOR ANOMALY TEST ===")

print(
    f"Normal profiles used for training: "
    f"{len(normal_df)}"
)

print(
    f"Attack-injected profiles tested: "
    f"{len(attack_df)}"
)

print(
    f"Actual attack users: "
    f"{len(attack_users)}"
)

print(
    f"Detected as anomalous: "
    f"{len(detected_attacks)}"
)

print(
    f"Missed attacks: "
    f"{len(missed_attacks)}"
)


detection_rate = (
    len(detected_attacks)
    / len(attack_users)
    * 100
)


print(
    f"\nAttack detection rate: "
    f"{detection_rate:.2f}%"
)


# ==========================================
# Show every attack user
# ==========================================

print("\n=== ATTACK USER RESULTS ===")

for _, row in attack_users.sort_values(
    "anomaly_score"
).iterrows():

    print(
        f"{row['user_id']} | "
        f"Attack: {', '.join(row['attack_types'])} | "
        f"Score: {row['anomaly_score']:.4f} | "
        f"Prediction: {row['detected_behavior']}"
    )


# ==========================================
# Show missed attacks
# ==========================================

if len(missed_attacks) > 0:

    print("\n=== MISSED ATTACKS ===")

    for _, row in missed_attacks.iterrows():

        print(
            f"{row['user_id']} | "
            f"Attack: {', '.join(row['attack_types'])} | "
            f"Score: {row['anomaly_score']:.4f}"
        )


print(
    f"\nSaved to: {OUTPUT_PATH}"
)            