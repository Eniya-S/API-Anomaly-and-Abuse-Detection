import json
import re
import pandas as pd

DATASET_PATH = "data/dataset_1_train/dataset_1_train.json"


def get_text(record):
    request = record.get("request", {})

    headers = request.get("headers", {})
    url = request.get("url", "")
    body = request.get("body", "")

    header_text = " ".join(
        f"{k}:{v}" for k, v in headers.items()
    )

    return f"{url} {header_text} {body}"


def extract_features(text):
    return {
        "length": len(text),
        "dollar": text.count("$"),
        "open_brace": text.count("{"),
        "close_brace": text.count("}"),
        "colon": text.count(":"),
        "backslash": text.count("\\"),
        "percent": text.count("%"),
        "slash": text.count("/"),
        "expression": len(
            re.findall(r"\$\{.*?\}", text)
        ),
        "nested_expression": len(
            re.findall(r"\$\{.*?\$\{", text)
        ),
        "jndi": len(
            re.findall(r"jndi", text, re.IGNORECASE)
        ),
        "lower": len(
            re.findall(r"lower:", text, re.IGNORECASE)
        ),
        "upper": len(
            re.findall(r"upper:", text, re.IGNORECASE)
        ),
        "env": len(
            re.findall(r"env:", text, re.IGNORECASE)
        ),
    }


# ==========================================
# Load dataset
# ==========================================

with open(DATASET_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


rows = []

for record in data:

    request = record.get("request", {})

    label = request.get(
        "Attack_Tag",
        "Normal"
    )

    text = get_text(record)

    features = extract_features(text)

    features["label"] = label

    rows.append(features)


df = pd.DataFrame(rows)


# ==========================================
# Compare Normal vs LOG4J
# ==========================================

normal = df[
    df["label"] == "Normal"
]

log4j = df[
    df["label"] == "LOG4J"
]


FEATURES = [
    "length",
    "dollar",
    "open_brace",
    "close_brace",
    "colon",
    "backslash",
    "percent",
    "slash",
    "expression",
    "nested_expression",
    "jndi",
    "lower",
    "upper",
    "env"
]


print("\n=== LOG4J FEATURE ANALYSIS ===")

print(
    f"Normal requests: {len(normal)}"
)

print(
    f"LOG4J requests: {len(log4j)}"
)


print("\n=== AVERAGES ===")

for feature in FEATURES:

    normal_avg = normal[feature].mean()
    log4j_avg = log4j[feature].mean()

    print(
        f"{feature:22s} "
        f"Normal: {normal_avg:8.2f}   "
        f"LOG4J: {log4j_avg:8.2f}"
    )


print("\n=== LOG4J FEATURE PRESENCE ===")

for feature in FEATURES:

    normal_pct = (
        (normal[feature] > 0).mean()
        * 100
    )

    log4j_pct = (
        (log4j[feature] > 0).mean()
        * 100
    )

    print(
        f"{feature:22s} "
        f"Normal: {normal_pct:6.2f}%   "
        f"LOG4J: {log4j_pct:6.2f}%"
    )