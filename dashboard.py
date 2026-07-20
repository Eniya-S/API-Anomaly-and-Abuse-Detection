from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


DEFAULT_RISK_DATA = Path("data/risk_scores.csv")


@st.cache_data(show_spinner=False)
def load_risk_data(path: str | Path = DEFAULT_RISK_DATA) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        st.error("Risk scoring output not found. Run risk_scoring.py first.")
        st.stop()

    df = pd.read_csv(path)
    if "Risk_Score" not in df.columns:
        st.error("The selected file does not contain a risk scoring output schema.")
        st.stop()

    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    return df


def main() -> None:
    st.set_page_config(page_title="API Risk Dashboard", page_icon="🛡️", layout="wide")
    st.title("API Anomaly Risk Dashboard")
    st.caption("Standalone Streamlit dashboard for reviewing anomaly-driven risk scores")

    df = load_risk_data()

    if df.empty:
        st.warning("No risk scoring records were found.")
        return

    total_requests = len(df)
    total_anomalies = int((df["Anomaly_Label"] == -1).sum())
    anomaly_percentage = round((total_anomalies / total_requests) * 100, 2) if total_requests else 0.0
    risky_users = df.groupby("Username")["Risk_Score"].max().ge(65).sum()
    highest_risk_score = int(df["Risk_Score"].max())

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total requests analyzed", f"{total_requests}")
    col2.metric("Total anomalies detected", f"{total_anomalies}")
    col3.metric("Percentage of anomalies", f"{anomaly_percentage}%")
    col4.metric("Number of risky users", f"{risky_users}")

    st.markdown("### Risk overview")
    metric_col, metric_col2 = st.columns(2)
    metric_col.metric("Highest risk score", f"{highest_risk_score}")
    metric_col2.metric("Risk categories", ", ".join(sorted(df["Risk_Category"].unique().tolist())))

    risk_category_counts = df["Risk_Category"].value_counts().reindex(["Low Risk", "Medium Risk", "High Risk", "Critical Risk"], fill_value=0)
    category_pie = px.pie(
        names=risk_category_counts.index,
        values=risk_category_counts.values,
        title="Risk Category Distribution",
        hole=0.4,
    )
    top_users = (
        df.groupby("Username", dropna=False)["Risk_Score"]
        .max()
        .sort_values(ascending=False)
        .head(10)
        .reset_index(name="Risk_Score")
    )
    user_bar = px.bar(top_users, x="Username", y="Risk_Score", color="Risk_Score", title="Top Risky Users")

    suspicious_endpoints = (
        df[df["Risk_Score"] >= 65]["Endpoint"]
        .astype(str)
        .value_counts()
        .head(10)
        .reset_index()
    )
    suspicious_endpoints.columns = ["Endpoint", "Count"]
    endpoint_bar = px.bar(suspicious_endpoints, x="Endpoint", y="Count", color="Count", title="Most Suspicious Endpoints")

    chart_col1, chart_col2 = st.columns(2)
    chart_col1.plotly_chart(category_pie, use_container_width=True)
    chart_col2.plotly_chart(user_bar, use_container_width=True)
    st.plotly_chart(endpoint_bar, use_container_width=True)

    if "Timestamp" in df.columns and df["Timestamp"].notna().any():
        anomaly_timeline = (
            df[df["Anomaly_Label"] == -1]
            .set_index("Timestamp")
            .resample("D")
            .size()
            .reset_index(name="Anomalies")
        )
        timeline_chart = px.line(anomaly_timeline, x="Timestamp", y="Anomalies", title="Timeline of Anomalies")
        st.plotly_chart(timeline_chart, use_container_width=True)
    else:
        st.info("Timestamp data is not available, so the anomaly timeline cannot be rendered.")

    st.markdown("### Suspicious activities")
    display_columns = [
        "Timestamp",
        "Username",
        "Client_IP",
        "Endpoint",
        "HTTP_Status",
        "Anomaly_Label",
        "Risk_Score",
        "Risk_Category",
        "Detection_Reason",
    ]
    table_df = df[display_columns].copy()
    if "Timestamp" in table_df.columns:
        table_df["Timestamp"] = table_df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(table_df.sort_values("Risk_Score", ascending=False), use_container_width=True)


if __name__ == "__main__":
    main()
