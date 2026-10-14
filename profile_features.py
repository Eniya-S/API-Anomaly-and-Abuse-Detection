import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


def extract_features(record):
    req = record["request"]
    resp = record["response"]

    url = req.get("url", "")
    parsed = urlparse(url)

    path = parsed.path
    query = parsed.query

    headers = req.get("headers", {})
    response_headers = resp.get("headers", {})

    return {
        "url_length": len(url),
        "path_length": len(path),
        "path_depth": len([x for x in path.split("/") if x]),
        "query_length": len(query),
        "query_parameter_count": len(parse_qs(query)),
        "encoded_characters": url.count("%"),
        "special_characters": sum(
            1 for c in url
            if c in "!@#$%^&*()[]{}<>|\\'\";=:+"
        ),
        "request_header_count": len(headers),
        "user_agent_length": len(headers.get("User-Agent", "")),
        "response_body_length": len(resp.get("body") or ""),
        "response_header_count": len(response_headers),
    }


groups = defaultdict(list)

for record in data:
    label = record["request"].get("Attack_Tag", "Normal")
    groups[label].append(extract_features(record))


feature_names = list(next(iter(groups.values()))[0].keys())

print("\n=== FEATURE PROFILE BY ATTACK TYPE ===\n")

for label, records in groups.items():

    print(f"\n--- {label} ({len(records)} records) ---")

    for feature in feature_names:
        values = [r[feature] for r in records]
        avg = sum(values) / len(values)

        print(f"{feature:25} avg = {avg:.2f}")