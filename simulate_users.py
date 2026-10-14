import json
import random
import re
from collections import defaultdict

TRAIN_PATH = "data/dataset_1_train/dataset_1_train.json"

NUM_USERS = 100
MIN_REQUESTS = 10
MAX_REQUESTS = 25

random.seed(42)


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# --------------------------------------------------
# Keep ONLY normal requests
# --------------------------------------------------

normal_requests = [
    record
    for record in data
    if record["request"].get("Attack_Tag") is None
]

print(f"Normal requests available: {len(normal_requests)}")


# --------------------------------------------------
# Convert URLs into endpoint families
# --------------------------------------------------

def endpoint_family(url):
    """
    Convert URLs such as:

        /products/123
        /products/456

    into:

        /products/{id}
    """

    return re.sub(r"/\d+(?=/|$)", "/{id}", url)


# --------------------------------------------------
# Group normal requests by endpoint family
# --------------------------------------------------

endpoint_groups = defaultdict(list)

for record in normal_requests:

    url = record["request"].get("url", "")

    family = endpoint_family(url)

    endpoint_groups[family].append(record)


print(f"Endpoint families: {len(endpoint_groups)}")


# --------------------------------------------------
# Keep only families with enough requests
# --------------------------------------------------

usable_groups = {
    family: records
    for family, records in endpoint_groups.items()
    if len(records) >= 5
}

print(f"Usable endpoint families: {len(usable_groups)}")

families = list(usable_groups.keys())


# --------------------------------------------------
# Create synthetic users
# --------------------------------------------------

users = []

for user_id in range(1, NUM_USERS + 1):

    # --------------------------------------------------
    # Each user normally accesses 2–5 endpoint families.
    # --------------------------------------------------

    num_families = random.randint(2, 5)

    selected_families = random.sample(
        families,
        min(num_families, len(families))
    )


    # --------------------------------------------------
    # Choose number of requests for this user.
    # --------------------------------------------------

    requests_per_user = random.randint(
        MIN_REQUESTS,
        MAX_REQUESTS
    )


    # --------------------------------------------------
    # Synthetic activity timeline.
    #
    # The original dataset does NOT provide reliable
    # timestamps, so we use elapsed seconds instead of
    # inventing calendar dates.
    #
    # Every user starts at 0 seconds.
    # --------------------------------------------------

    elapsed_seconds = 0

    user_requests = []


    # --------------------------------------------------
    # Generate requests
    # --------------------------------------------------

    for request_number in range(requests_per_user):

        # Select one of this user's normal endpoint families.
        family = random.choice(selected_families)

        # Select an actual normal request from that family.
        record = random.choice(
            usable_groups[family]
        )


        # --------------------------------------------------
        # Create synthetic user activity record.
        # --------------------------------------------------

        user_requests.append({
            "user_id": f"User_{user_id:03d}",
            "elapsed_seconds": elapsed_seconds,
            "request": record["request"],
            "response": record["response"],
            "endpoint_family": family,
            "behavior": "normal"
        })


        # --------------------------------------------------
        # Simulate time until the next request.
        #
        # Most requests happen relatively close together,
        # while some have longer gaps.
        # --------------------------------------------------

        gap = random.choices(
            [
                random.randint(5, 20),
                random.randint(21, 60),
                random.randint(61, 180)
            ],
            weights=[0.45, 0.40, 0.15]
        )[0]

        elapsed_seconds += gap


    # --------------------------------------------------
    # Add this user's requests.
    # --------------------------------------------------

    users.extend(user_requests)


# --------------------------------------------------
# Save simulated user traffic
# --------------------------------------------------

OUTPUT_PATH = "data/simulated_normal_users.json"

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(users, f, indent=2)


# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n=== SIMULATION COMPLETE ===")

print(f"Users created: {NUM_USERS}")
print(f"Total simulated requests: {len(users)}")
print(f"Saved to: {OUTPUT_PATH}")


# --------------------------------------------------
# Show example users
# --------------------------------------------------

print("\nExample users:")

for user_id in ["User_001", "User_002", "User_003"]:

    user_records = [
        r
        for r in users
        if r["user_id"] == user_id
    ]

    families_used = sorted(
        set(
            r["endpoint_family"]
            for r in user_records
        )
    )

    print(f"\n{user_id}")

    print(f"Requests: {len(user_records)}")

    print("Endpoint families:")

    for family in families_used:
        print(f"  {family}")

    print("Activity timeline:")

    if user_records:
        print(
            f"  Start: {user_records[0]['elapsed_seconds']} seconds"
        )

        print(
            f"  End:   {user_records[-1]['elapsed_seconds']} seconds"
        )

        print(
            f"  Duration: "
            f"{user_records[-1]['elapsed_seconds'] - user_records[0]['elapsed_seconds']} seconds"
        )
