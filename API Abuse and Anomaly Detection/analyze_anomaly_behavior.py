import json
from collections import defaultdict

INPUT_PATH = "data/simulated_attack_users.json"
OUTPUT_PATH = "data/attack_behavior_profiles.json"


# ==========================================
# Load attack-injected user data
# ==========================================

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# ==========================================
# Group requests by user
# ==========================================

users = defaultdict(list)

for record in data:
    users[record["user_id"]].append(record)


# ==========================================
# Build behavioral profiles
# ==========================================

profiles = []

for user_id, records in users.items():

    # Sort by synthetic time
    records = sorted(
        records,
        key=lambda x: x["elapsed_seconds"]
    )

    requests = len(records)

    # --------------------------------------
    # Time-based features
    # --------------------------------------

    start_time = records[0]["elapsed_seconds"]
    end_time = records[-1]["elapsed_seconds"]

    duration_seconds = end_time - start_time

    if duration_seconds > 0:
        request_rate = (
            requests / duration_seconds
        ) * 60
    else:
        request_rate = 0

    gaps = []

    for i in range(1, len(records)):
        gap = (
            records[i]["elapsed_seconds"]
            - records[i - 1]["elapsed_seconds"]
        )
        gaps.append(gap)

    if gaps:
        average_gap = sum(gaps) / len(gaps)
    else:
        average_gap = 0

    # --------------------------------------
    # Endpoint behavior
    # --------------------------------------

    endpoint_families = set()
    endpoints = []

    for record in records:

        family = record.get(
            "endpoint_family",
            ""
        )

        endpoint_families.add(family)

        url = record["request"].get(
            "url",
            ""
        )

        endpoints.append(url)

    unique_endpoints = len(set(endpoints))

    endpoint_family_count = len(
        endpoint_families
    )

    if requests > 0:
        endpoint_diversity = (
            endpoint_family_count / requests
        )
    else:
        endpoint_diversity = 0

    repeated_endpoint_ratio = (
        (requests - unique_endpoints) / requests
        if requests > 0
        else 0
    )

    # --------------------------------------
    # HTTP method behavior
    # --------------------------------------

    methods = [
        record["request"].get(
            "method",
            ""
        ).upper()
        for record in records
    ]

    get_count = methods.count("GET")
    post_count = methods.count("POST")

    get_ratio = (
        get_count / requests
        if requests > 0
        else 0
    )

    post_ratio = (
        post_count / requests
        if requests > 0
        else 0
    )

    # --------------------------------------
    # Response behavior
    # --------------------------------------

    failed_requests = 0

    for record in records:

        status_code = record[
            "response"
        ].get(
            "status_code",
            0
        )

        if status_code >= 400:
            failed_requests += 1

    failure_rate = (
        failed_requests / requests
        if requests > 0
        else 0
    )

    # --------------------------------------
    # Store profile
    # --------------------------------------

    profile = {

        "user_id": user_id,

        "requests": requests,

        "duration_seconds": round(
            duration_seconds,
            3
        ),

        "request_rate_per_minute": round(
            request_rate,
            3
        ),

        "average_gap_seconds": round(
            average_gap,
            3
        ),

        "endpoint_families": endpoint_family_count,

        "unique_endpoints": unique_endpoints,

        "endpoint_diversity": round(
            endpoint_diversity,
            3
        ),

        "repeated_endpoint_ratio": round(
            repeated_endpoint_ratio,
            3
        ),

        "get_ratio": round(
            get_ratio,
            3
        ),

        "post_ratio": round(
            post_ratio,
            3
        ),

        "failure_rate": round(
            failure_rate,
            3
        ),

        # Ground truth only.
        # These will NOT be used
        # as model features.
        "contains_attack": any(
            record.get("behavior") == "attack"
            for record in records
        ),

        "attack_types": sorted(
            set(
                record["attack_type"]
                for record in records
                if record.get("behavior") == "attack"
            )
        )
    }

    profiles.append(profile)


# ==========================================
# Save profiles
# ==========================================

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        profiles,
        f,
        indent=2
    )


# ==========================================
# Display results
# ==========================================

print("\n=== ATTACK BEHAVIOR PROFILES ===")

print(
    f"Users profiled: {len(profiles)}"
)

attack_users = [
    profile
    for profile in profiles
    if profile["contains_attack"]
]

normal_users = [
    profile
    for profile in profiles
    if not profile["contains_attack"]
]

print(
    f"Attack users: {len(attack_users)}"
)

print(
    f"Normal users: {len(normal_users)}"
)


print("\n=== ATTACK USER PROFILES ===")

for profile in attack_users:

    print(
        f"{profile['user_id']} | "
        f"Requests: {profile['requests']} | "
        f"Rate: {profile['request_rate_per_minute']:.2f}/min | "
        f"Endpoints: {profile['endpoint_families']} | "
        f"Failure: {profile['failure_rate']:.2f} | "
        f"Attack: {', '.join(profile['attack_types'])}"
    )


print(
    f"\nSaved to: {OUTPUT_PATH}"
)