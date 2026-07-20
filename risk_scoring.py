import argparse
import json
from pathlib import Path
from typing import Dict, List

import pandas as pd

SUSPICIOUS_ENDPOINT_TOKENS = (
    "/admin",
    "/.git",
    "/backup",
    "/secrets",
    "/wp-admin",
    "/debug",
    "/config",
    "/env",
    "/phpmyadmin",
    "/cgi-bin",
    "/shell",
    "/setup",
    "/manager",
    "/db",
)


def _coerce_numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default)


def _normalize_endpoint(endpoint_value) -> str:
    if pd.isna(endpoint_value):
        return ""
    return str(endpoint_value)


def _is_suspicious_endpoint(endpoint: str) -> bool:
    if not endpoint:
        return False
    endpoint_lower = endpoint.lower()
    return any(token in endpoint_lower for token in SUSPICIOUS_ENDPOINT_TOKENS)


def _risk_category(score: float) -> str:
    if score >= 85:
        return "Critical Risk"
    if score >= 65:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    return "Low Risk"


def score_requests(input_path: str | Path | None = None, output_csv: str | Path | None = None, output_json: str | Path | None = None) -> pd.DataFrame:
    input_path = Path(input_path or "data/anomaly_results.csv")
    output_csv = Path(output_csv or "data/risk_scores.csv")
    output_json = Path(output_json or "data/risk_scores.json")

    if not input_path.exists():
        raise FileNotFoundError(
            f"Anomaly results file not found at {input_path}. Run behavioral_profiling.py first."
        )

    df = pd.read_csv(input_path)
    if "Anomaly_Label" not in df.columns:
        raise ValueError("Input file is missing the Anomaly_Label column.")

    scored_df = df.copy()
    scored_df["Username"] = scored_df["Username"].fillna("unknown")
    scored_df["Client_IP"] = scored_df["Client_IP"].fillna("unknown")
    scored_df["Endpoint"] = scored_df["Endpoint"].fillna("")

    if "Timestamp" in scored_df.columns:
        scored_df["Timestamp"] = pd.to_datetime(scored_df["Timestamp"], errors="coerce")

    scored_df["HTTP_Status"] = _coerce_numeric(scored_df.get("HTTP_Status", pd.Series([0] * len(scored_df))), default=0).astype(int)
    scored_df["Response_Time_ms"] = _coerce_numeric(scored_df.get("Response_Time_ms", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Requests_Per_User"] = _coerce_numeric(scored_df.get("Requests_Per_User", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Requests_Per_IP"] = _coerce_numeric(scored_df.get("Requests_Per_IP", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Requests_Per_Session"] = _coerce_numeric(scored_df.get("Requests_Per_Session", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Unique_Endpoints_Per_User"] = _coerce_numeric(scored_df.get("Unique_Endpoints_Per_User", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Failure_Rate_Per_User"] = _coerce_numeric(scored_df.get("Failure_Rate_Per_User", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Average_Response_Time_User"] = _coerce_numeric(scored_df.get("Average_Response_Time_User", pd.Series([0] * len(scored_df))), default=0)
    scored_df["Anomaly_Label"] = scored_df["Anomaly_Label"].astype(int)

    user_anomaly_counts = scored_df.groupby("Username")["Anomaly_Label"].apply(lambda s: int((s == -1).sum())).to_dict()
    user_total_requests = scored_df.groupby("Username").size().to_dict()

    response_time_series = scored_df["Response_Time_ms"]
    if response_time_series.empty:
        percentile_90 = 0.0
        percentile_95 = 0.0
    else:
        percentile_90 = response_time_series.quantile(0.90)
        percentile_95 = response_time_series.quantile(0.95)

    reasons: List[str] = []
    risk_scores: List[int] = []
    risk_categories: List[str] = []

    for _, row in scored_df.iterrows():
        score = 0
        reasons_for_row: List[str] = []

        if int(row["Anomaly_Label"]) == -1:
            score += 40
            reasons_for_row.append("Isolation Forest flagged this request as anomalous")

        user = str(row["Username"])
        user_anomalies = user_anomaly_counts.get(user, 0)
        user_request_count = user_total_requests.get(user, 0)
        if user_anomalies >= 3:
            score += 20
            reasons_for_row.append("Multiple anomalous requests from this user")
        elif user_anomalies == 2:
            score += 12
            reasons_for_row.append("Repeated suspicious activity from this user")
        elif user_anomalies == 1:
            score += 6
            reasons_for_row.append("One suspicious request was linked to this user")

        endpoint = _normalize_endpoint(row.get("Endpoint", ""))
        if _is_suspicious_endpoint(endpoint):
            score += 20
            reasons_for_row.append(f"Accessed sensitive endpoint {endpoint}")

        http_status = int(row["HTTP_Status"])
        if http_status in {400, 401, 403, 404, 405}:
            score += 10
            reasons_for_row.append("Received a client-side failure status")
        elif 500 <= http_status <= 599:
            score += 15
            reasons_for_row.append("Received a server-side failure status")

        if user_request_count >= 80:
            score += 10
            reasons_for_row.append("High request volume from this user")
        elif user_request_count >= 40:
            score += 6
            reasons_for_row.append("Elevated request volume from this user")

        response_time = float(row["Response_Time_ms"])
        if response_time >= percentile_95:
            score += 10
            reasons_for_row.append("Response time was unusually high")
        elif response_time >= percentile_90:
            score += 5
            reasons_for_row.append("Response time was above normal range")

        failure_rate = float(row["Failure_Rate_Per_User"])
        if failure_rate >= 50:
            score += 10
            reasons_for_row.append("User has a high failure rate")
        elif failure_rate >= 25:
            score += 6
            reasons_for_row.append("User is showing elevated failure behavior")

        requests_per_ip = float(row["Requests_Per_IP"])
        requests_per_session = float(row["Requests_Per_Session"])
        unique_endpoints = float(row["Unique_Endpoints_Per_User"])
        if requests_per_ip >= 100 or requests_per_session >= 40 or unique_endpoints >= 20:
            score += 8
            reasons_for_row.append("Suspicious request pattern detected")

        score = min(100, max(0, int(score)))
        reasons_for_row = reasons_for_row[:4]
        reasons.append("; ".join(reasons_for_row) if reasons_for_row else "No strong suspicious signals")
        risk_scores.append(score)
        risk_categories.append(_risk_category(score))

    scored_df["Risk_Score"] = risk_scores
    scored_df["Risk_Category"] = risk_categories
    scored_df["Detection_Reason"] = reasons

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    scored_df.to_csv(output_csv, index=False)
    scored_df.to_json(output_json, orient="records", indent=2)

    print(f"Saved request-level risk scores to {output_csv}")
    print(f"Saved JSON risk output to {output_json}")
    return scored_df


def build_user_summary(scored_df: pd.DataFrame) -> pd.DataFrame:
    user_summary = (
        scored_df.groupby("Username", dropna=False)
        .agg(
            Total_Requests=("Username", "size"),
            Anomalous_Requests=("Anomaly_Label", lambda values: int((values == -1).sum())),
            Highest_Risk_Score=("Risk_Score", "max"),
            Risk_Category=("Risk_Category", lambda values: values.iloc[0]),
        )
        .reset_index()
    )
    user_summary["Risk_Category"] = user_summary["Highest_Risk_Score"].apply(_risk_category)
    return user_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate risk scores from anomaly results")
    parser.add_argument("--input", default="data/anomaly_results.csv", help="Path to anomaly_results.csv")
    parser.add_argument("--output-csv", default="data/risk_scores.csv", help="Path to write the risk scoring CSV")
    parser.add_argument("--output-json", default="data/risk_scores.json", help="Path to write the risk scoring JSON")
    args = parser.parse_args()

    scored_df = score_requests(args.input, args.output_csv, args.output_json)
    user_summary = build_user_summary(scored_df)
    print("\nTop risky users:")
    print(user_summary.sort_values("Highest_Risk_Score", ascending=False).head(10).to_string(index=False))


if __name__ == "__main__":
    main()
