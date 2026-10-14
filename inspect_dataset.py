import json
from collections import Counter

train_path = "data/dataset_1_train/dataset_1_train.json"
val_path = "data/dataset_1_val/dataset_1_val.json"

with open(train_path, "r", encoding="utf-8") as f:
    train_data = json.load(f)

with open(val_path, "r", encoding="utf-8") as f:
    val_data = json.load(f)


# ==========================================
# BASIC DATASET INFO
# ==========================================

print("TRAINING SET")
print("Records:", len(train_data))

print("\nVALIDATION SET")
print("Records:", len(val_data))


# ==========================================
# TRAINING LABELS
# ==========================================

train_labels = []

for record in train_data:
    attack_tag = record["request"].get("Attack_Tag")

    if attack_tag:
        train_labels.append(attack_tag)
    else:
        train_labels.append("Normal")


print("\n" + "=" * 60)
print("TRAINING LABEL DISTRIBUTION")
print("=" * 60)

label_counts = Counter(train_labels)

for label, count in label_counts.most_common():
    print(f"{label}: {count}")


# ==========================================
# VALIDATION LABEL CHECK
# ==========================================

val_has_attack_tag = 0

for record in val_data:
    if "Attack_Tag" in record["request"]:
        val_has_attack_tag += 1

print("\n" + "=" * 60)
print("VALIDATION LABEL CHECK")
print("=" * 60)

print("Records containing Attack_Tag:", val_has_attack_tag)


# ==========================================
# REQUEST STRUCTURE
# ==========================================

print("\n" + "=" * 60)
print("REQUEST KEYS")
print("=" * 60)

print(train_data[0]["request"].keys())

print("\nRESPONSE KEYS")
print("=" * 60)

print(train_data[0]["response"].keys())


# ==========================================
# HTTP METHODS
# ==========================================

methods = Counter(
    record["request"].get("method")
    for record in train_data
)

print("\n" + "=" * 60)
print("HTTP METHODS")
print("=" * 60)

for method, count in methods.most_common():
    print(f"{method}: {count}")