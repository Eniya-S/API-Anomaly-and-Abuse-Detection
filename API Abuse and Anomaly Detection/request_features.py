import json
import re
import pandas as pd
from urllib.parse import urlparse, parse_qs


INPUT_PATH = "data/dataset_1_train/dataset_1_train.json"
OUTPUT_PATH = "data/request_features.csv"


# ==========================================
# Load dataset
# ==========================================

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# ==========================================
# Feature extraction
# ==========================================

def extract_features(record):

    request = record["request"]
    response = record["response"]

    url = request.get("url", "")
    method = request.get("method", "").upper()

    headers = request.get("headers", {})
    response_headers = response.get("headers", {})

    body = request.get("body", "")

    # --------------------------------------
    # Build combined request text
    # Used for generic security-text features
    # --------------------------------------

    header_text = " ".join(
        f"{key}:{value}"
        for key, value in headers.items()
    )

    request_text = (
        f"{url} {header_text} {body}"
    )

    # --------------------------------------
    # URL parsing
    # --------------------------------------

    parsed_url = urlparse(url)

    path = parsed_url.path
    query = parsed_url.query

    query_params = parse_qs(query)

    query_param_count = len(query_params)

    # --------------------------------------
    # URL characteristics
    # --------------------------------------

    url_length = len(url)

    path_length = len(path)

    path_depth = len([
        part
        for part in path.split("/")
        if part
    ])

    # Percent-encoded characters
    encoded_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url
        )
    )

    # Special characters
    special_char_count = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    # --------------------------------------
    # URL ratios / query characteristics
    # --------------------------------------

    if url_length > 0:
        encoded_ratio = encoded_count / url_length
        special_char_ratio = (
            special_char_count / url_length
        )
    else:
        encoded_ratio = 0
        special_char_ratio = 0

    query_length = len(query)

    # --------------------------------------
    # Request headers
    # --------------------------------------

    request_header_count = len(headers)

    user_agent = headers.get(
        "User-Agent",
        ""
    )

    user_agent_length = len(user_agent)

    # Total length of all request header names
    # and values
    total_header_length = sum(
        len(str(key)) + len(str(value))
        for key, value in headers.items()
    )

    # Longest individual header value
    max_header_value_length = max(
        [len(str(value)) for value in headers.values()],
        default=0
    )

    # --------------------------------------
    # Request body
    # --------------------------------------

    body_length = len(body)

    # --------------------------------------
    # NEW: Generic security-text features
    #
    # These capture expression-like structures
    # without directly assigning an attack label.
    # --------------------------------------

    dollar_count = request_text.count("$")

    brace_count = (
        request_text.count("{")
        + request_text.count("}")
    )

    expression_count = len(
        re.findall(
            r"\$\{.*?\}",
            request_text
        )
    )

    jndi_count = len(
        re.findall(
            r"jndi",
            request_text,
            re.IGNORECASE
        )
    )

    # --------------------------------------
    # Response characteristics
    # --------------------------------------

    status_code = response.get(
        "status_code",
        0
    )

    response_body = response.get(
        "body",
        ""
    )

    response_body_length = len(
        response_body
    )

    response_header_count = len(
        response_headers
    )

    # --------------------------------------
    # Response/request size relationship
    # --------------------------------------

    if url_length > 0:
        response_body_to_url_ratio = (
            response_body_length / url_length
        )
    else:
        response_body_to_url_ratio = 0

    # --------------------------------------
    # Label
    # --------------------------------------

    attack_tag = request.get(
        "Attack_Tag"
    )

    if attack_tag is None:
        label = "Normal"
    else:
        label = attack_tag

    # --------------------------------------
    # Return feature record
    # --------------------------------------

    return {

        # Existing request-level features
        "url_length": url_length,
        "path_length": path_length,
        "path_depth": path_depth,
        "query_param_count": query_param_count,
        "encoded_char_count": encoded_count,
        "special_char_count": special_char_count,

        # Existing URL features
        "encoded_ratio": encoded_ratio,
        "special_char_ratio": special_char_ratio,
        "query_length": query_length,

        # Request method
        "method": method,

        # Request headers
        "request_header_count": request_header_count,
        "user_agent_length": user_agent_length,

        # Existing header features
        "total_header_length": total_header_length,
        "max_header_value_length": max_header_value_length,

        # Request body
        "body_length": body_length,

        # NEW generic security-text features
        "dollar_count": dollar_count,
        "brace_count": brace_count,
        "expression_count": expression_count,
        "jndi_count": jndi_count,

        # Response features
        "status_code": status_code,
        "response_body_length": response_body_length,
        "response_header_count": response_header_count,

        # Existing response/request relationship
        "response_body_to_url_ratio": response_body_to_url_ratio,

        # Ground truth only
        "label": label
    }


# ==========================================
# Extract all features
# ==========================================

features = []

for record in data:

    features.append(
        extract_features(record)
    )


df = pd.DataFrame(features)


# ==========================================
# Encode HTTP method
# ==========================================

df["method_encoded"] = (
    df["method"]
    .map({
        "GET": 0,
        "POST": 1
    })
    .fillna(-1)
)


# Drop original text method
df = df.drop(
    columns=["method"]
)


# ==========================================
# Save
# ==========================================

df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ==========================================
# Display summary
# ==========================================

print("\n=== REQUEST FEATURE EXTRACTION ===")

print(
    f"Total requests: {len(df)}"
)

print(
    f"Total features: "
    f"{len(df.columns) - 1}"
)

print("\nClass distribution:")

print(
    df["label"].value_counts()
)


print("\nFeature columns:")

for column in df.columns:

    print(
        f"  {column}"
    )


print(
    f"\nSaved to: {OUTPUT_PATH}"
)