import json
from collections import Counter
from urllib.parse import urlparse, parse_qs, unquote

TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# ============================================================
# 1. URL / QUERY PARAMETER ANALYSIS
# ============================================================

print("=" * 60)
print("URL / QUERY PARAMETER ANALYSIS")
print("=" * 60)

urls_with_query = 0
urls_without_query = 0
query_parameter_counts = []

for record in data:
    url = record["request"].get("url", "")

    parsed = urlparse(url)

    if parsed.query:
        urls_with_query += 1

        params = parse_qs(parsed.query)
        query_parameter_counts.append(len(params))
    else:
        urls_without_query += 1
        query_parameter_counts.append(0)

print("URLs with query parameters:", urls_with_query)
print("URLs without query parameters:", urls_without_query)

print(
    "Maximum query parameters in one URL:",
    max(query_parameter_counts)
)

print(
    "Average query parameters:",
    sum(query_parameter_counts) / len(query_parameter_counts)
)


# ============================================================
# 2. URL ENCODING ANALYSIS
# ============================================================

print("\n" + "=" * 60)
print("URL ENCODING ANALYSIS")
print("=" * 60)

encoded_url_count = 0
encoded_character_counts = []

for record in data:
    url = record["request"].get("url", "")

    count = url.count("%")

    if count > 0:
        encoded_url_count += 1

    encoded_character_counts.append(count)

print("URLs containing percent encoding:", encoded_url_count)

print(
    "Maximum encoded characters in one URL:",
    max(encoded_character_counts)
)

print(
    "Average encoded characters:",
    sum(encoded_character_counts) / len(encoded_character_counts)
)


# ============================================================
# 3. URL CHARACTERISTICS
# ============================================================

print("\n" + "=" * 60)
print("URL CHARACTERISTICS")
print("=" * 60)

path_lengths = []
path_depths = []
special_character_counts = []

special_characters = set(
    "!@#$%^&*()[]{}<>|\\'\";=:+"
)

for record in data:

    url = record["request"].get("url", "")

    parsed = urlparse(url)

    path = parsed.path

    path_lengths.append(len(path))

    # Number of path components
    depth = len(
        [part for part in path.split("/") if part]
    )

    path_depths.append(depth)

    special_count = sum(
        1 for char in url
        if char in special_characters
    )

    special_character_counts.append(special_count)


print(
    "Average path length:",
    sum(path_lengths) / len(path_lengths)
)

print(
    "Maximum path length:",
    max(path_lengths)
)

print(
    "Average path depth:",
    sum(path_depths) / len(path_depths)
)

print(
    "Maximum path depth:",
    max(path_depths)
)

print(
    "Average special characters:",
    sum(special_character_counts)
    / len(special_character_counts)
)

print(
    "Maximum special characters:",
    max(special_character_counts)
)


# ============================================================
# 4. HTTP METHODS
# ============================================================

print("\n" + "=" * 60)
print("HTTP METHODS")
print("=" * 60)

methods = Counter()

for record in data:
    method = record["request"].get("method")
    methods[method] += 1

for method, count in methods.most_common():
    print(f"{method}: {count}")


# ============================================================
# 5. HEADER ANALYSIS
# ============================================================

print("\n" + "=" * 60)
print("HEADER ANALYSIS")
print("=" * 60)

header_counts = []
user_agents = Counter()

for record in data:

    headers = record["request"].get("headers", {})

    header_counts.append(len(headers))

    user_agent = headers.get("User-Agent")

    if user_agent:
        user_agents[user_agent] += 1


print(
    "Average request headers:",
    sum(header_counts) / len(header_counts)
)

print(
    "Maximum request headers:",
    max(header_counts)
)

print(
    "Unique User-Agent values:",
    len(user_agents)
)


# ============================================================
# 6. RESPONSE ANALYSIS
# ============================================================

print("\n" + "=" * 60)
print("RESPONSE ANALYSIS")
print("=" * 60)

response_body_lengths = []
response_header_counts = []

for record in data:

    response = record["response"]

    body = response.get("body", "")
    headers = response.get("headers", {})

    if body is None:
        body = ""

    response_body_lengths.append(len(body))
    response_header_counts.append(len(headers))


print(
    "Average response body length:",
    sum(response_body_lengths)
    / len(response_body_lengths)
)

print(
    "Maximum response body length:",
    max(response_body_lengths)
)

print(
    "Average response headers:",
    sum(response_header_counts)
    / len(response_header_counts)
)


# ============================================================
# 7. DECODED URL EXAMPLES
# ============================================================

print("\n" + "=" * 60)
print("ENCODED URL EXAMPLES")
print("=" * 60)

shown = 0

for record in data:

    url = record["request"].get("url", "")

    if "%" in url:

        decoded = unquote(url)

        print("\nOriginal:")
        print(url)

        print("Decoded:")
        print(decoded)

        shown += 1

        if shown == 5:
            break