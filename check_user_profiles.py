import json
from collections import defaultdict

INPUT_PATH = "data/simulated_normal_users.json"

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

# Group requests by user
user_requests = defaultdict(list)

for record in data:
    user_requests[record["user_id"]].append(record)


profiles = []

for user_id, records in user_requests.items():

    # Sort by synthetic elapsed time
    records.sort(key=lambda x: x["elapsed_seconds"])

    request_count = len(records)

    # -----------------------------
    # Time-based features
    # -----------------------------

    start_time = records[0]["elapsed_seconds"]
    end_time = records[-1]["elapsed_seconds"]

    duration_seconds = end_time - start_time

    duration_minutes = duration_seconds / 60

    if duration_minutes > 0:
        request_rate = request_count / duration_minutes
    else:
        request_rate = 0

    # Calculate gaps between requests
    gaps = []

    for i in range(1, len(records)):
        gap = (
            records[i]["elapsed_seconds"]
            - records[i - 1]["elapsed_seconds"]
        )
        gaps.append(gap)

    avg_gap = sum(gaps) / len(gaps) if gaps else 0

    # -----------------------------
    # Endpoint behavior
    # -----------------------------

    endpoint_families = [
        record["endpoint_family"]
        for record in records
    ]

    unique_families = set(endpoint_families)

    family_count = len(unique_families)

    endpoint_diversity = family_count / request_count

    # Count actual URLs
    urls = [
        record["request"].get("url", "")
        for record in records
    ]

    unique_urls = set(urls)

    unique_endpoint_count = len(unique_urls)

    # Repeated endpoint ratio
    repeated_requests = request_count - unique_endpoint_count

    repeated_endpoint_ratio = repeated_requests / request_count

    # -----------------------------
    # HTTP behavior
    # -----------------------------

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

    # -----------------------------
    # Response behavior
    # -----------------------------

    failed_requests = sum(
        1
        for record in records
        if record["response"].get("status_code", 0) >= 400
    )

    failure_rate = failed_requests / request_count

    # -----------------------------
    # Create profile
    # -----------------------------

    profile = {
        "user_id": user_id,
        "requests": request_count,

        "duration_seconds": round(duration_seconds, 2),
        "request_rate_per_minute": round(request_rate, 2),
        "average_gap_seconds": round(avg_gap, 2),

        "endpoint_families": family_count,
        "unique_endpoints": unique_endpoint_count,
        "endpoint_diversity": round(endpoint_diversity, 3),
        "repeated_endpoint_ratio": round(
            repeated_endpoint_ratio, 3
        ),

        "get_ratio": round(get_ratio, 3),
        "post_ratio": round(post_ratio, 3),

        "failure_rate": round(failure_rate, 3)
    }

    profiles.append(profile)


# -----------------------------
# Display profiles
# -----------------------------

print("\n=== USER BEHAVIOR PROFILES ===\n")

for profile in profiles[:10]:

    print(profile["user_id"])

    print(
        f"  Requests: {profile['requests']}"
    )

    print(
        f"  Duration: {profile['duration_seconds']} seconds"
    )

    print(
        f"  Request rate: "
        f"{profile['request_rate_per_minute']} requests/min"
    )

    print(
        f"  Average gap: "
        f"{profile['average_gap_seconds']} seconds"
    )

    print(
        f"  Endpoint families: "
        f"{profile['endpoint_families']}"
    )

    print(
        f"  Unique endpoints: "
        f"{profile['unique_endpoints']}"
    )

    print(
        f"  Endpoint diversity: "
        f"{profile['endpoint_diversity']}"
    )

    print(
        f"  Repeated endpoint ratio: "
        f"{profile['repeated_endpoint_ratio']}"
    )

    print(
        f"  Failure rate: "
        f"{profile['failure_rate']}"
    )

    print()


# -----------------------------
# Overall statistics
# -----------------------------

print("=== OVERALL STATISTICS ===")

print(f"Users: {len(profiles)}")

avg_requests = sum(
    p["requests"] for p in profiles
) / len(profiles)

avg_rate = sum(
    p["request_rate_per_minute"] for p in profiles
) / len(profiles)

avg_gap = sum(
    p["average_gap_seconds"] for p in profiles
) / len(profiles)

avg_diversity = sum(
    p["endpoint_diversity"] for p in profiles
) / len(profiles)

avg_failure = sum(
    p["failure_rate"] for p in profiles
) / len(profiles)

print(
    f"Average requests/user: "
    f"{avg_requests:.2f}"
)

print(
    f"Average request rate: "
    f"{avg_rate:.2f} requests/min"
)

print(
    f"Average gap: "
    f"{avg_gap:.2f} seconds"
)

print(
    f"Average endpoint diversity: "
    f"{avg_diversity:.3f}"
)

print(
    f"Average failure rate: "
    f"{avg_failure:.3f}"
)