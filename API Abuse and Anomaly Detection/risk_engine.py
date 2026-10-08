import json
import os
import pandas as pd


INPUT_FILE = "data/simulated_attack_users.json"
OUTPUT_FILE = "data/security_events.csv"


ATTACK_SEVERITY = {
    "RCE": 90,
    "LOG4J": 85,
    "SQL Injection": 80,
    "Directory Traversal": 70,
    "Cookie Injection": 60,
    "Log Forging": 50
}


def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def main():

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Count attacks per user
    user_attack_counts = {}

    for record in data:
        if record.get("behavior") == "attack":
            user_id = record.get("user_id")
            user_attack_counts[user_id] = (
                user_attack_counts.get(user_id, 0) + 1
            )

    events = []

    for record in data:

        if record.get("behavior") != "attack":
            continue

        user_id = record.get("user_id")
        attack_type = record.get("attack_type", "Unknown")

        attack_count = user_attack_counts.get(user_id, 1)

        base_score = ATTACK_SEVERITY.get(
            attack_type,
            50
        )

        # Repeated attack contribution
        repeat_bonus = min(
            15,
            max(0, attack_count - 1) * 2
        )

        risk_score = min(
            100,
            base_score + repeat_bonus
        )

        events.append({
            "user_id": user_id,
            "attack_type": attack_type,
            "attack_count": attack_count,
            "base_risk": base_score,
            "repeat_bonus": repeat_bonus,
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score)
        })

    df = pd.DataFrame(events)

    os.makedirs("data", exist_ok=True)

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n=== RISK ENGINE ===")
    print(f"Security events: {len(df)}")

    print("\n=== RISK LEVELS ===")
    print(df["risk_level"].value_counts())

    print("\n=== SAMPLE ===")
    print(df.head(10).to_string(index=False))

    print(f"\nSaved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()