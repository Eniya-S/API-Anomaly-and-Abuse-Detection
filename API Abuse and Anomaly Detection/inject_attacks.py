import json
import random
import re

NORMAL_PATH = "data/simulated_normal_users.json"
TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"
OUTPUT_PATH = "data/simulated_attack_users.json"

random.seed(42)

# ==============================
# Load data
# ==============================

with open(NORMAL_PATH, "r", encoding="utf-8") as f:
    normal_data = json.load(f)

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    train_data = json.load(f)


# ==============================
# Endpoint family function
# ==============================

def endpoint_family(url):
    return re.sub(r"/\d+(?=/|$)", "/{id}", url)


# ==============================
# Separate attack records
# ==============================

attack_groups = {}

for record in train_data:

    attack_tag = record["request"].get("Attack_Tag")

    if attack_tag is not None:
        attack_groups.setdefault(
            attack_tag,
            []
        ).append(record)


print("=== ATTACK DATA ===")

for attack_type, records in attack_groups.items():
    print(f"{attack_type}: {len(records)} requests")


# ==============================
# Group normal requests by user
# ==============================

users = {}

for record in normal_data:

    users.setdefault(
        record["user_id"],
        []
    ).append(record)


user_ids = sorted(users.keys())


# ==============================
# Select users who will receive attacks
# ==============================

NUM_ATTACK_USERS = 20

attack_users = random.sample(
    user_ids,
    NUM_ATTACK_USERS
)


# ==============================
# Assign attack type to users
# ==============================

attack_types = list(attack_groups.keys())

random.shuffle(attack_types)

user_attack_mapping = {}

for index, user_id in enumerate(attack_users):

    attack_type = attack_types[
        index % len(attack_types)
    ]

    user_attack_mapping[user_id] = attack_type


# ==============================
# Inject attacks
# ==============================

output = []

for user_id in user_ids:

    user_records = users[user_id]

    # Keep original normal behavior
    output.extend(user_records)

    # No attack for this user
    if user_id not in user_attack_mapping:
        continue

    attack_type = user_attack_mapping[user_id]

    attack_records = attack_groups[attack_type]

    last_time = max(
        record["elapsed_seconds"]
        for record in user_records
    )

    attack_count = random.randint(3, 8)

    for _ in range(attack_count):

        source_record = random.choice(
            attack_records
        )

        gap = random.randint(1, 10)

        last_time += gap

        # --------------------------------
        # Copy request WITHOUT Attack_Tag
        # --------------------------------

        clean_request = dict(
            source_record["request"]
        )

        clean_request.pop(
            "Attack_Tag",
            None
        )

        # --------------------------------
        # Calculate actual endpoint family
        # --------------------------------

        url = clean_request.get(
            "url",
            ""
        )

        family = endpoint_family(url)

        # --------------------------------
        # Create simulated attack record
        # --------------------------------

        attack_record = {

            "user_id": user_id,

            "elapsed_seconds": last_time,

            "request": clean_request,

            "response": source_record["response"],

            "endpoint_family": family,

            # Ground-truth metadata
            # NOT used as model feature
            "behavior": "attack",

            "attack_type": attack_type
        }

        output.append(
            attack_record
        )


# ==============================
# Save
# ==============================

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        output,
        f,
        indent=2
    )


# ==============================
# Summary
# ==============================

print(
    "\n=== ATTACK INJECTION COMPLETE ==="
)

print(
    f"Total users: {len(user_ids)}"
)

print(
    f"Attack users: {len(attack_users)}"
)

print(
    f"Normal users: "
    f"{len(user_ids) - len(attack_users)}"
)

print(
    f"Total records: {len(output)}"
)

print(
    f"Saved to: {OUTPUT_PATH}"
)


# ==============================
# Attack mapping
# ==============================

print(
    "\n=== ATTACK USER MAPPING ==="
)

for user_id in sorted(
    user_attack_mapping.keys()
):

    attack_type = user_attack_mapping[
        user_id
    ]

    attack_count = sum(
        1
        for record in output

        if (
            record["user_id"] == user_id
            and record["behavior"] == "attack"
        )
    )

    print(
        f"{user_id} → "
        f"{attack_type} "
        f"({attack_count} attack requests)"
    )