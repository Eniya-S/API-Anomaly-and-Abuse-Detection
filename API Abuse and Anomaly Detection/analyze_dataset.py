import json
from collections import Counter

TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# ------------------------------------------
# 1. Basic statistics
# ------------------------------------------

print("=" * 60)
print("BASIC STATISTICS")
print("=" * 60)

print("Total records:", len(data))


# ------------------------------------------
# 2. Attack distribution by HTTP method
# ------------------------------------------

method_attack = {}

for record in data:
    request = record["request"]

    method = request.get("method")
    attack = request.get("Attack_Tag", "Normal")

    if method not in method_attack:
        method_attack[method] = Counter()

    method_attack[method][attack] += 1


print("\n" + "=" * 60)
print("ATTACK DISTRIBUTION BY HTTP METHOD")
print("=" * 60)

for method, attacks in method_attack.items():
    print(f"\n{method}")

    for attack, count in attacks.items():
        print(f"  {attack}: {count}")


# ------------------------------------------
# 3. Response status codes by attack
# ------------------------------------------

status_attack = {}

for record in data:
    request = record["request"]
    response = record["response"]

    attack = request.get("Attack_Tag", "Normal")
    status = response.get("status_code")

    if attack not in status_attack:
        status_attack[attack] = Counter()

    status_attack[attack][status] += 1


print("\n" + "=" * 60)
print("STATUS CODE DISTRIBUTION BY ATTACK")
print("=" * 60)

for attack, statuses in status_attack.items():
    print(f"\n{attack}")

    for status, count in statuses.most_common():
        print(f"  {status}: {count}")


# ------------------------------------------
# 4. URL statistics
# ------------------------------------------

print("\n" + "=" * 60)
print("URL STATISTICS")
print("=" * 60)

url_lengths = []

for record in data:
    url = record["request"].get("url", "")
    url_lengths.append(len(url))

print("Minimum URL length:", min(url_lengths))
print("Maximum URL length:", max(url_lengths))
print("Average URL length:", sum(url_lengths) / len(url_lengths))


# ------------------------------------------
# 5. Body statistics
# ------------------------------------------

body_lengths = []

for record in data:
    body = record["request"].get("body", "")

    if body is None:
        body = ""

    body_lengths.append(len(body))

print("\n" + "=" * 60)
print("REQUEST BODY STATISTICS")
print("=" * 60)

print("Requests with body:", sum(length > 0 for length in body_lengths))
print("Requests without body:", sum(length == 0 for length in body_lengths))
print("Maximum body length:", max(body_lengths))
print("Average body length:", sum(body_lengths) / len(body_lengths))


# ------------------------------------------
# 6. Unique URLs
# ------------------------------------------

urls = set()

for record in data:
    urls.add(record["request"].get("url", ""))

print("\n" + "=" * 60)
print("URL INFORMATION")
print("=" * 60)

print("Unique URLs:", len(urls))
print("Total requests:", len(data))


# ------------------------------------------
# 7. Sample from each attack type
# ------------------------------------------

samples = {}

for record in data:
    attack = record["request"].get("Attack_Tag", "Normal")

    if attack not in samples:
        samples[attack] = record


print("\n" + "=" * 60)
print("ONE SAMPLE FROM EACH CLASS")
print("=" * 60)

for attack, record in samples.items():

    request = record["request"]

    print("\n" + "-" * 50)
    print("ATTACK:", attack)
    print("METHOD:", request.get("method"))
    print("URL:", request.get("url"))
    print("BODY:", request.get("body"))
    print("STATUS:", record["response"].get("status_code"))

print("\n" + "=" * 60)
print("ALL TOP-LEVEL KEYS")
print("=" * 60)

print(data[0].keys())

print("\n" + "=" * 60)
print("FIRST 5 RECORD STRUCTURES")
print("=" * 60)

for i, record in enumerate(data[:5]):
    print(f"\nRecord {i + 1}")
    print("Request keys:", record["request"].keys())
    print("Response keys:", record["response"].keys())