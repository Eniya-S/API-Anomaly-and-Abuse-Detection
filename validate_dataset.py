
import json
import re
import pandas as pd
from urllib.parse import urlparse, parse_qs

INPUT_PATH = "data/dataset_1_val/dataset_1_val.json"
OUTPUT_PATH = "data/validation_features.csv"

FEATURES = [
    "url_length", "path_length", "path_depth",
    "query_param_count", "encoded_char_count",
    "special_char_count", "encoded_ratio",
    "special_char_ratio", "query_length",
    "request_header_count", "user_agent_length",
    "total_header_length", "max_header_value_length",
    "body_length", "status_code", "response_body_length",
    "response_header_count", "response_body_to_url_ratio",
    "method_encoded"
]

def extract_features(record):
    request = record["request"]
    response = record["response"]

    url = request.get("url", "")
    method = request.get("method", "").upper()
    headers = request.get("headers", {})
    response_headers = response.get("headers", {})
    body = request.get("body", "")

    parsed_url = urlparse(url)
    path = parsed_url.path
    query = parsed_url.query
    query_params = parse_qs(query)

    url_length = len(url)
    path_length = len(path)
    path_depth = len([p for p in path.split("/") if p])

    encoded_count = len(re.findall(r"%[0-9A-Fa-f]{2}", url))
    special_count = len(re.findall(r"[^a-zA-Z0-9]", url))

    header_lengths = [
        len(str(k)) + len(str(v))
        for k, v in headers.items()
    ]
    header_value_lengths = [
        len(str(v)) for v in headers.values()
    ]

    response_body = response.get("body", "")

    return {
        "url_length": url_length,
        "path_length": path_length,
        "path_depth": path_depth,
        "query_param_count": len(query_params),
        "encoded_char_count": encoded_count,
        "special_char_count": special_count,
        "encoded_ratio": encoded_count / url_length if url_length else 0,
        "special_char_ratio": special_count / url_length if url_length else 0,
        "query_length": len(query),
        "request_header_count": len(headers),
        "user_agent_length": len(headers.get("User-Agent", "")),
        "total_header_length": sum(header_lengths),
        "max_header_value_length": max(header_value_lengths, default=0),
        "body_length": len(body),
        "status_code": response.get("status_code", 0),
        "response_body_length": len(response_body),
        "response_header_count": len(response_headers),
        "response_body_to_url_ratio": len(response_body) / url_length if url_length else 0,
        "method_encoded": {"GET": 0, "POST": 1}.get(method, -1)
    }

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    records = json.load(f)

df = pd.DataFrame([extract_features(r) for r in records])
df.to_csv(OUTPUT_PATH, index=False)

print("\n=== VALIDATION FEATURE EXTRACTION ===")
print(f"Validation records: {len(df)}")
print(f"Feature columns: {len(df.columns)}")
print(f"Saved to: {OUTPUT_PATH}")
