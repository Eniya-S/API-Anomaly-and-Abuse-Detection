import json
from collections import defaultdict


INPUT_PATH = "data/simulated_normal_users.json"
OUTPUT_PATH = "data/user_behavior_profiles.json"


# --------------------------------
# Load simulated user requests
# --------------------------------

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)


# --------------------------------
# Group requests by user
# --------------------------------

user_requests = defaultdict(list)

for record in data:
    user_requests[record["user_id"]].append(record)


profiles = []


# --------------------------------
# Build behavioral profile
# --------------------------------

for user_id, records in user_requests.items():

    records.sort(
        key=lambda x: x["elapsed_seconds"]
    )

    request_count = len(records)

    # Time behavior
    start_time = records[0]["elapsed_seconds"]
    end_time = records[-1]["elapsed_seconds"]

    duration_seconds = end_time - start_time

    duration_minutes = duration_seconds / 60

    if duration_minutes > 0:
        request_rate = request_count / duration_minutes
    else:
        request_rate = 0

    # Time gaps
    gaps = []

    for i in range(1, len(records)):
        gap = (
            records[i]["elapsed_seconds"]
            - records[i - 1]["elapsed_seconds"]
        )
        gaps.append(gap)

    average_gap = (
        sum(gaps) / len(gaps)
        if gaps
        else 0
    )

    # --------------------------------
    # Endpoint behavior
    # --------------------------------

    endpoint_families = [
        record["endpoint_family"]
        for record in records
    ]

    unique_endpoint_families = set(
        endpoint_families
    )

    family_count = len(
        unique_endpoint_families
    )

    urls = [
        record["request"].get("url", "")
        for record in records
    ]

    unique_urls = set(urls)

    unique_endpoint_count = len(
        unique_urls
    )

    endpoint_diversity = (
        family_count / request_count
    )

    repeated_requests = (
        request_count - unique_endpoint_count
    )

    repeated_endpoint_ratio = (
        repeated_requests / request_count
    )

    # --------------------------------
    # HTTP method behavior
    # --------------------------------

    get_count = sum(
        1
        for record in records
        if record["request"].get("method") == "GET"
    )

    post_count = sum(
        1
        for record in records
        if record["request"].get("method") == "POST"
    )

    get_ratio = get_count / request_count
    post_ratio = post_count / request_count

    # --------------------------------
    # Response behavior
    # --------------------------------

    failed_requests = sum(
        1
        for record in records
        if record["response"].get(
            "status_code", 0
        ) >= 400
    )

    failure_rate = (
        failed_requests / request_count
    )

    # --------------------------------
    # Final profile
    # --------------------------------

    profile = {
        "user_id": user_id,

        "requests": request_count,

        "duration_seconds": round(
            duration_seconds, 2
        ),

        "request_rate_per_minute": round(
            request_rate, 3
        ),

        "average_gap_seconds": round(
            average_gap, 3
        ),

        "endpoint_families": family_count,

        "unique_endpoints": unique_endpoint_count,

        "endpoint_diversity": round(
            endpoint_diversity, 3
        ),

        "repeated_endpoint_ratio": round(
            repeated_endpoint_ratio, 3
        ),

        "get_ratio": round(
            get_ratio, 3
        ),

        "post_ratio": round(
            post_ratio, 3
        ),

        "failure_rate": round(
            failure_rate, 3
        ),

        "behavior": "normal"
    }

    profiles.append(profile)


# --------------------------------
# Save profiles
# --------------------------------

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


# --------------------------------
# Output summary
# --------------------------------

print("\n=== BEHAVIOR PROFILE DATASET ===")

print(
    f"Users profiled: {len(profiles)}"
)

print(
    f"Saved to: {OUTPUT_PATH}"
)

print("\nExample profile:\n")

print(
    json.dumps(
        profiles[0],
        indent=2
    )
)