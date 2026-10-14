import json
import pandas as pd
from sklearn.ensemble import IsolationForest


INPUT_PATH = "data/user_behavior_profiles.json"
OUTPUT_PATH = "data/behavior_anomaly_results.json"


# --------------------------------
# Load behavioral profiles
# --------------------------------

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    profiles = json.load(f)

df = pd.DataFrame(profiles)


# --------------------------------
# Behavioral features
# --------------------------------

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

X = df[FEATURES]


# --------------------------------
# Train Isolation Forest
# --------------------------------

model = IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=42
)

model.fit(X)


# --------------------------------
# Predict anomalies
# --------------------------------

df["anomaly_prediction"] = model.predict(X)

df["anomaly_score"] = model.decision_function(X)


# Isolation Forest:
#   1  = normal
#  -1  = anomaly

df["behavior"] = df["anomaly_prediction"].apply(
    lambda x: "anomalous" if x == -1 else "normal"
)


# --------------------------------
# Save results
# --------------------------------

results = df.to_dict(orient="records")

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


# --------------------------------
# Display results
# --------------------------------

print("\n=== BEHAVIORAL ANOMALY DETECTION ===")

print(
    f"Profiles analyzed: {len(df)}"
)

print(
    f"Features used: {len(FEATURES)}"
)

normal_count = (
    df["behavior"] == "normal"
).sum()

anomaly_count = (
    df["behavior"] == "anomalous"
).sum()

print(
    f"Normal users: {normal_count}"
)

print(
    f"Anomalous users: {anomaly_count}"
)


# --------------------------------
# Show most suspicious users
# --------------------------------

print("\n=== MOST SUSPICIOUS USERS ===")

suspicious = df.sort_values(
    "anomaly_score"
).head(10)


for _, row in suspicious.iterrows():

    print(
        f"{row['user_id']} | "
        f"Score: {row['anomaly_score']:.4f} | "
        f"Requests: {row['requests']} | "
        f"Rate: {row['request_rate_per_minute']:.2f}/min | "
        f"Endpoints: {row['endpoint_families']} | "
        f"Failure: {row['failure_rate']:.2f} | "
        f"Behavior: {row['behavior']}"
    )


print(
    f"\nSaved results to: {OUTPUT_PATH}"
)