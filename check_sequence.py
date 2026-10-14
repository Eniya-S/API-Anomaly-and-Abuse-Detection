import json

TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


print("=" * 70)
print("FIRST 30 REQUESTS IN DATASET ORDER")
print("=" * 70)

for i, record in enumerate(data[:30]):

    request = record["request"]

    attack = request.get("Attack_Tag", "Normal")
    method = request.get("method")
    url = request.get("url")
    status = record["response"].get("status_code")

    print(
        f"{i + 1:02d}. "
        f"{attack:<20} "
        f"{method:<5} "
        f"status={status:<3} "
        f"{url}"
    )