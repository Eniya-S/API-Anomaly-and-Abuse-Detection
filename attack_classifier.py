import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier


# ==========================================
# Paths
# ==========================================

INPUT_PATH = "data/request_features.csv"
MODEL_PATH = "data/attack_classifier.pkl"


# ==========================================
# Load feature dataset
# ==========================================

df = pd.read_csv(INPUT_PATH)


# ==========================================
# Keep only labelled attack requests
# ==========================================

attack_df = df[
    df["label"] != "Normal"
].copy()


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


X = attack_df[FEATURES]

y = attack_df["label"]


# ==========================================
# Train Random Forest
# ==========================================

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced"
)


model.fit(X, y)


# ==========================================
# Save trained model
# ==========================================

joblib.dump(
    model,
    MODEL_PATH
)


# ==========================================
# Display information
# ==========================================

print("\n=== ATTACK CLASSIFIER TRAINING ===")

print(
    f"Attack requests used: {len(attack_df)}"
)

print("\nAttack classes:")

for attack_type in sorted(y.unique()):

    count = (y == attack_type).sum()

    print(
        f"  {attack_type}: {count}"
    )


print(
    f"\nFeatures used: {len(FEATURES)}"
)

print(
    f"\nModel saved to: {MODEL_PATH}"
)