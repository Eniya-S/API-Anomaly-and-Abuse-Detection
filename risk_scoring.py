import argparse
import json
import os
import smtplib
from email.message import EmailMessage
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


HIGH_RISK_THRESHOLD = 65


def send_email(to_email: str, subject: str, message: str, smtp_host: str | None = None,
               smtp_port: int | None = None, smtp_username: str | None = None,
               smtp_password: str | None = None, from_email: str | None = None,
               use_tls: bool = True, use_ssl: bool | None = None) -> bool:
    smtp_host = smtp_host or os.getenv("SMTP_HOST")
    smtp_port = smtp_port or int(os.getenv("SMTP_PORT", 587))
    smtp_username = smtp_username or os.getenv("SMTP_USERNAME")
    smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
    from_email = from_email or os.getenv("SMTP_FROM") or os.getenv("SMTP_FROM_EMAIL") or smtp_username
    if use_ssl is None:
        use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() in {"1", "true", "yes"}

    if not smtp_host or not smtp_username or not smtp_password or not to_email:
        return False

    email_message = EmailMessage()
    email_message["Subject"] = subject
    email_message["From"] = from_email or "noreply@localhost"
    email_message["To"] = to_email
    email_message.set_content(message)

    try:
        smtp_connection = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        with smtp_connection(smtp_host, smtp_port, timeout=10) as server:
            if use_tls and not use_ssl:
                server.starttls()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.send_message(email_message)
        return True
    except (OSError, TimeoutError, smtplib.SMTPException) as exc:
        print(f"SMTP send failed for {to_email}: {type(exc).__name__}: {exc}")
        return False


def load_users(users_file: str | Path | None = None) -> dict[str, str]:
    path = Path(users_file or "data/users.json")
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as file:
            users = json.load(file)
    except Exception:
        return {}

    user_emails: dict[str, str] = {}
    for user in users:
        username = str(user.get("username", "")).strip()
        email = str(user.get("email", "")).strip()
        if username and email:
            user_emails[username] = email
    return user_emails


def send_high_risk_alerts(scored_df: pd.DataFrame, users_file: str | Path | None = None,
                         threshold: int = HIGH_RISK_THRESHOLD) -> list[dict]:
    if scored_df.empty:
        return []

    user_emails = load_users(users_file)
    if not user_emails:
        return []

    high_risk_rows = scored_df[scored_df["Risk_Score"] >= threshold].copy()
    if high_risk_rows.empty:
        return []

    alerts_sent: list[dict] = []

    for username, group in high_risk_rows.groupby("Username", dropna=False):
        username_str = str(username).strip()
        if not username_str:
            continue

        email_to = user_emails.get(username_str)
        if not email_to:
            continue

        highest_score = int(group["Risk_Score"].max())
        reasons = group["Detection_Reason"].dropna().astype(str)
        reason_text = "; ".join(reasons.head(3).tolist()) if not reasons.empty else "Repeated suspicious activity"
        subject = f"Security Alert: High Risk Score for {username_str}"
        message = (
            f"Hello {username_str},\n\n"
            f"Your API activity has been flagged as high risk with a score of {highest_score}/100.\n"
            f"Reason(s): {reason_text}\n\n"
            "Please review your recent activity and confirm whether this was authorized."
        )

        if send_email(email_to, subject, message):
            alerts_sent.append({
                "username": username_str,
                "email": email_to,
                "score": highest_score,
                "subject": subject,
                "message": message,
            })

    return alerts_sent


def send_admin_risk_alerts(scored_df: pd.DataFrame, admin_email: str | None = None,
                           threshold: int = HIGH_RISK_THRESHOLD) -> bool:
    """Send the admin one report listing each user above the risk threshold."""
    admin_email = admin_email or os.getenv("ADMIN_EMAIL")
    if not admin_email or scored_df.empty:
        return False

    high_risk_rows = scored_df[scored_df["Risk_Score"] >= threshold].copy()
    if high_risk_rows.empty:
        return False

    highest_risk_by_user = (
        high_risk_rows.sort_values("Risk_Score", ascending=False)
        .drop_duplicates("Username")
    )
    details = []
    for _, row in highest_risk_by_user.iterrows():
        details.append(
            f"Person: {row['Username']}\n"
            f"Risk category: {row['Risk_Category']}\n"
            f"Risk score: {int(row['Risk_Score'])}/100\n"
            f"Reason: {row.get('Detection_Reason', 'Suspicious activity detected')}"
        )

    subject = f"API Risk Alert: {len(details)} user(s) require attention"
    message = (
        "The API anomaly detector identified the following high-risk users.\n\n"
        + "\n\n---\n\n".join(details)
        + "\n\nPlease review the risk dashboard for the related requests."
    )
    return send_email(admin_email, subject, message)


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
            
        # Add attack classification risk weight
        attack_type = row.get("Attack_Type", "Normal")
        if pd.isna(attack_type):
            attack_type = "Normal"
            
        if attack_type == "Brute_Force":
            score += 20
            reasons_for_row.append("Classified as Brute Force attack")
        elif attack_type == "Endpoint_Scanning":
            score += 15
            reasons_for_row.append("Classified as Endpoint Scanning probe")
        elif attack_type == "Request_Flooding":
            score += 10
            reasons_for_row.append("Classified as Request Flooding volume abuse")

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

    admin_alert_sent = send_admin_risk_alerts(scored_df)
    if admin_alert_sent:
        print("Sent risk summary email to the admin.")
    elif (scored_df["Risk_Score"] >= HIGH_RISK_THRESHOLD).any():
        print("Admin risk email was not sent. Set ADMIN_EMAIL and verify SMTP settings.")

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
