from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


DEFAULT_RISK_DATA = Path("data/risk_scores.csv")


# ==========================================================
# LOAD RISK DATA
# ==========================================================

@st.cache_data(show_spinner=False)
def load_risk_data(path: str | Path = DEFAULT_RISK_DATA) -> pd.DataFrame:

    path = Path(path)

    if not path.exists():
        st.error(
            "Risk scoring output not found. "
            "Run risk_scoring.py first."
        )
        st.stop()

    df = pd.read_csv(path)

    if "Risk_Score" not in df.columns:
        st.error(
            "The selected file does not contain a risk scoring output schema."
        )
        st.stop()

    # ------------------------------------------------------
    # Legacy / missing columns support
    # ------------------------------------------------------

    defaults = {
        "Username": "unknown",
        "Client_IP": "unknown",
        "Endpoint": "",
        "HTTP_Method": "unknown",
        "HTTP_Status": 0,
        "Anomaly_Label": 1,
        "Risk_Category": "Low Risk",
        "Detection_Reason": "No strong suspicious signals",
        "Attack_Type": "Normal",
        "Response_Time_ms": 0,
        "Requests_Per_User": 0,
        "Requests_Per_IP": 0,
        "Requests_Per_Session": 0,
        "Unique_Endpoints_Per_User": 0,
        "Failure_Rate_Per_User": 0,
        "Average_Response_Time_User": 0,
    }

    for column, default in defaults.items():

        if column not in df.columns:
            df[column] = default

    # ------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------

    if "Timestamp" in df.columns:

        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )

    # ------------------------------------------------------
    # Attack Type
    # ------------------------------------------------------

    df["Attack_Type"] = (
        df["Attack_Type"]
        .fillna("Normal")
        .astype(str)
    )

    # ------------------------------------------------------
    # Numeric columns
    # ------------------------------------------------------

    numeric_columns = [
        "Risk_Score",
        "HTTP_Status",
        "Anomaly_Label",
        "Response_Time_ms",
        "Requests_Per_User",
        "Requests_Per_IP",
        "Requests_Per_Session",
        "Unique_Endpoints_Per_User",
        "Failure_Rate_Per_User",
        "Average_Response_Time_User",
    ]

    for column in numeric_columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(0)

    # ------------------------------------------------------
    # Risk category if missing / empty
    # ------------------------------------------------------

    def calculate_category(score):

        score = float(score)

        if score >= 85:
            return "Critical Risk"

        if score >= 65:
            return "High Risk"

        if score >= 35:
            return "Medium Risk"

        return "Low Risk"

    df["Risk_Category"] = df.apply(
        lambda row:
        row["Risk_Category"]
        if str(row["Risk_Category"]).strip()
        and str(row["Risk_Category"]).lower() != "nan"
        else calculate_category(row["Risk_Score"]),
        axis=1
    )

    return df


# ==========================================================
# RISK CATEGORY
# ==========================================================

def risk_category(score: float) -> str:

    score = float(score)

    if score >= 85:
        return "Critical Risk"

    if score >= 65:
        return "High Risk"

    if score >= 35:
        return "Medium Risk"

    return "Low Risk"


# ==========================================================
# RISK BREAKDOWN
# ==========================================================

def get_risk_breakdown(
    row: pd.Series,
    df: pd.DataFrame
):

    breakdown = []

    # ------------------------------------------------------
    # 1. Isolation Forest anomaly
    # ------------------------------------------------------

    if int(row["Anomaly_Label"]) == -1:

        breakdown.append(
            (
                "Isolation Forest anomaly",
                40,
                "The Isolation Forest model classified this request as anomalous."
            )
        )

    # ------------------------------------------------------
    # 2. User anomaly behaviour
    # ------------------------------------------------------

    username = str(row["Username"])

    user_rows = df[
        df["Username"].astype(str) == username
    ]

    user_anomalies = int(
        (user_rows["Anomaly_Label"] == -1).sum()
    )

    user_request_count = len(user_rows)

    if user_anomalies >= 3:

        breakdown.append(
            (
                "Multiple anomalous requests",
                20,
                f"This user generated {user_anomalies} anomalous requests."
            )
        )

    elif user_anomalies == 2:

        breakdown.append(
            (
                "Repeated suspicious activity",
                12,
                "Two anomalous requests were linked to this user."
            )
        )

    elif user_anomalies == 1:

        breakdown.append(
            (
                "One suspicious request",
                6,
                "One anomalous request was linked to this user."
            )
        )

    # ------------------------------------------------------
    # 3. Suspicious endpoint
    # ------------------------------------------------------

    endpoint = str(row["Endpoint"])

    suspicious_tokens = (
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

    if any(
        token in endpoint.lower()
        for token in suspicious_tokens
    ):

        breakdown.append(
            (
                "Suspicious endpoint",
                20,
                f"The endpoint {endpoint} matches a sensitive or suspicious endpoint pattern."
            )
        )

    # ------------------------------------------------------
    # 4. HTTP status
    # ------------------------------------------------------

    status = int(row["HTTP_Status"])

    if status in {400, 401, 403, 404, 405}:

        breakdown.append(
            (
                "Client-side failure status",
                10,
                f"The request returned HTTP {status}."
            )
        )

    elif 500 <= status <= 599:

        breakdown.append(
            (
                "Server-side failure status",
                15,
                f"The request returned HTTP {status}."
            )
        )

    # ------------------------------------------------------
    # 5. Request volume
    # ------------------------------------------------------

    if user_request_count >= 80:

        breakdown.append(
            (
                "High request volume",
                10,
                f"This user generated {user_request_count} requests."
            )
        )

    elif user_request_count >= 40:

        breakdown.append(
            (
                "Elevated request volume",
                6,
                f"This user generated {user_request_count} requests."
            )
        )

    # ------------------------------------------------------
    # 6. Response time
    # ------------------------------------------------------

    response_time = float(
        row["Response_Time_ms"]
    )

    response_times = pd.to_numeric(
        df["Response_Time_ms"],
        errors="coerce"
    ).dropna()

    if not response_times.empty:

        percentile_90 = response_times.quantile(0.90)
        percentile_95 = response_times.quantile(0.95)

        if (
            response_time >= percentile_95
            and percentile_95 > 0
        ):

            breakdown.append(
                (
                    "Unusually high response time",
                    10,
                    f"{response_time:.0f} ms is at or above the dataset's 95th percentile."
                )
            )

        elif (
            response_time >= percentile_90
            and percentile_90 > 0
        ):

            breakdown.append(
                (
                    "Above-normal response time",
                    5,
                    f"{response_time:.0f} ms is at or above the dataset's 90th percentile."
                )
            )

    # ------------------------------------------------------
    # 7. Failure rate
    # ------------------------------------------------------

    failure_rate = float(
        row["Failure_Rate_Per_User"]
    )

    if failure_rate >= 50:

        breakdown.append(
            (
                "High failure rate",
                10,
                f"This user's failure rate is {failure_rate:.1f}%."
            )
        )

    elif failure_rate >= 25:

        breakdown.append(
            (
                "Elevated failure behavior",
                6,
                f"This user's failure rate is {failure_rate:.1f}%."
            )
        )

    # ------------------------------------------------------
    # 8. Request pattern
    # ------------------------------------------------------

    requests_per_ip = float(
        row["Requests_Per_IP"]
    )

    requests_per_session = float(
        row["Requests_Per_Session"]
    )

    unique_endpoints = float(
        row["Unique_Endpoints_Per_User"]
    )

    if (
        requests_per_ip >= 100
        or requests_per_session >= 40
        or unique_endpoints >= 20
    ):

        breakdown.append(
            (
                "Suspicious request pattern",
                8,
                "The IP, session, or endpoint diversity crossed a suspicious threshold."
            )
        )

    return breakdown


# ==========================================================
# OVERVIEW PAGE
# ==========================================================

def show_overview(
    df: pd.DataFrame,
    filtered_df: pd.DataFrame
):

    st.title("🛡️ API Anomaly Risk Dashboard")

    st.caption(
        "Standalone Streamlit dashboard for reviewing anomaly-driven risk scores"
    )

    # ======================================================
    # KPI METRICS
    # ======================================================

    total_requests = len(filtered_df)

    total_anomalies = int(
        (filtered_df["Anomaly_Label"] == -1).sum()
    )

    anomaly_percentage = (
        round(
            (total_anomalies / total_requests) * 100,
            2
        )
        if total_requests
        else 0.0
    )

    risky_users = (
        filtered_df
        .groupby("Username")["Risk_Score"]
        .max()
        .ge(65)
        .sum()
    )

    highest_risk_score = int(
        filtered_df["Risk_Score"].max()
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total requests analyzed",
        f"{total_requests}"
    )

    col2.metric(
        "Total anomalies detected",
        f"{total_anomalies}"
    )

    col3.metric(
        "Percentage of anomalies",
        f"{anomaly_percentage}%"
    )

    col4.metric(
        "Number of risky users",
        f"{risky_users}"
    )

    # ======================================================
    # RISK OVERVIEW
    # ======================================================

    st.markdown("### Risk overview")

    metric_col, metric_col2 = st.columns(2)

    metric_col.metric(
        "Highest risk score",
        f"{highest_risk_score}"
    )

    metric_col2.metric(
        "Risk categories",
        ", ".join(
            sorted(
                filtered_df[
                    "Risk_Category"
                ].unique().tolist()
            )
        )
    )

    # ======================================================
    # RISK CATEGORY DISTRIBUTION
    # ======================================================

    risk_category_counts = (
        filtered_df["Risk_Category"]
        .value_counts()
        .reindex(
            [
                "Low Risk",
                "Medium Risk",
                "High Risk",
                "Critical Risk"
            ],
            fill_value=0
        )
    )

    category_pie = px.pie(
        names=risk_category_counts.index,
        values=risk_category_counts.values,
        title="Risk Category Distribution",
        hole=0.4,
    )

    # ======================================================
    # TOP RISKY USERS
    # ======================================================

    top_users = (
        filtered_df
        .groupby(
            "Username",
            dropna=False
        )["Risk_Score"]
        .max()
        .sort_values(
            ascending=False
        )
        .head(10)
        .reset_index(
            name="Risk_Score"
        )
    )

    user_bar = px.bar(
        top_users,
        x="Username",
        y="Risk_Score",
        color="Risk_Score",
        title="Top Risky Users"
    )

    chart_col1, chart_col2 = st.columns(2)

    chart_col1.plotly_chart(
        category_pie,
        use_container_width=True
    )

    chart_col2.plotly_chart(
        user_bar,
        use_container_width=True
    )

    # ======================================================
    # SUSPICIOUS ENDPOINTS
    # ======================================================

    suspicious_endpoints = (
        filtered_df[
            filtered_df["Risk_Score"] >= 65
        ]["Endpoint"]
        .astype(str)
        .value_counts()
        .head(10)
        .reset_index()
    )

    suspicious_endpoints.columns = [
        "Endpoint",
        "Count"
    ]

    if not suspicious_endpoints.empty:

        endpoint_bar = px.bar(
            suspicious_endpoints,
            x="Endpoint",
            y="Count",
            color="Count",
            title="Most Suspicious Endpoints"
        )

        st.plotly_chart(
            endpoint_bar,
            use_container_width=True
        )

    # ======================================================
    # ATTACK TYPE DISTRIBUTION
    # ======================================================

    attack_df = filtered_df[
        filtered_df["Attack_Type"] != "Normal"
    ]

    if not attack_df.empty:

        attack_counts = (
            attack_df["Attack_Type"]
            .value_counts()
            .reset_index()
        )

        attack_counts.columns = [
            "Attack_Type",
            "Count"
        ]

        attack_bar = px.bar(
            attack_counts,
            x="Attack_Type",
            y="Count",
            color="Attack_Type",
            title="Attack Type Distribution (Anomalies Only)",
            labels={
                "Attack_Type": "Attack Type",
                "Count": "Number of Incidents"
            }
        )

        st.plotly_chart(
            attack_bar,
            use_container_width=True
        )

    else:

        st.info(
            "No classified anomaly attack traffic matches the active filters."
        )

    # ======================================================
    # HIGH RISK USERS
    # ======================================================

    st.markdown("---")

    st.markdown(
        "## 🔴 High Risk Users"
    )

    st.caption(
        "Select a risky user to investigate why their risk score is high."
    )

    high_risk_users = (
        filtered_df[
            filtered_df["Risk_Score"] >= 65
        ]
        .groupby(
            "Username",
            dropna=False
        )
        .agg(
            Risk_Score=(
                "Risk_Score",
                "max"
            ),
            Anomalous_Requests=(
                "Anomaly_Label",
                lambda values:
                int((values == -1).sum())
            ),
        )
        .reset_index()
        .sort_values(
            "Risk_Score",
            ascending=False
        )
        .head(10)
    )

    if high_risk_users.empty:

        st.info(
            "No High Risk or Critical Risk users found."
        )

    else:

        for start in range(
            0,
            len(high_risk_users),
            2
        ):

            current_users = high_risk_users.iloc[
                start:start + 2
            ]

            columns = st.columns(2)

            for col, (_, user) in zip(
                columns,
                current_users.iterrows()
            ):

                username = str(
                    user["Username"]
                )

                score = int(
                    user["Risk_Score"]
                )

                if score >= 85:

                    category = "Critical Risk"
                    icon = "🔴"

                else:

                    category = "High Risk"
                    icon = "🟠"

                anomalous_requests = int(
                    user["Anomalous_Requests"]
                )

                with col:

                    # --------------------------------------
                    # USER CARD
                    # --------------------------------------

                    st.markdown(
                        f"### {icon} {username}"
                    )

                    st.metric(
                        "Risk Score",
                        f"{score}/100"
                    )

                    st.write(
                        f"**Risk Level:** {category}"
                    )

                    st.write(
                        f"**Anomalous Requests:** "
                        f"{anomalous_requests}"
                    )

                    # --------------------------------------
                    # INVESTIGATE BUTTON
                    # --------------------------------------

                    if st.button(
                        f"🔎 Investigate {username}",
                        key=f"investigate_{username}",
                        use_container_width=True,
                    ):

                        st.session_state[
                            "selected_username"
                        ] = username

                        st.session_state[
                            "page"
                        ] = "Anomaly Explanation"

                        st.rerun()

    # ======================================================
    # TIMELINE
    # ======================================================

    if (
        "Timestamp" in filtered_df.columns
        and filtered_df["Timestamp"].notna().any()
    ):

        anomaly_timeline = (
            filtered_df[
                filtered_df["Anomaly_Label"] == -1
            ]
            .set_index("Timestamp")
            .resample("min")
            .size()
            .reset_index(
                name="Anomalies"
            )
        )

        if not anomaly_timeline.empty:

            timeline_chart = px.line(
                anomaly_timeline,
                x="Timestamp",
                y="Anomalies",
                title="Timeline of Anomalies"
            )

            st.plotly_chart(
                timeline_chart,
                use_container_width=True
            )

    # ======================================================
    # SUSPICIOUS ACTIVITIES
    # ======================================================

    st.markdown(
        "### Suspicious activities"
    )

    display_columns = [
        "Timestamp",
        "Username",
        "Client_IP",
        "Endpoint",
        "HTTP_Status",
        "Anomaly_Label",
        "Attack_Type",
        "Risk_Score",
        "Risk_Category",
        "Detection_Reason",
    ]

    available_columns = [
        column
        for column in display_columns
        if column in filtered_df.columns
    ]

    table_df = filtered_df[
        available_columns
    ].copy()

    if (
        "Timestamp" in table_df.columns
    ):

        table_df["Timestamp"] = (
            table_df["Timestamp"]
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    st.dataframe(
        table_df.sort_values(
            "Risk_Score",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )


# ==========================================================
# ANOMALY EXPLANATION PAGE
# ==========================================================

def show_explanation(
    df: pd.DataFrame
):

    st.title(
        "🔎 Anomaly Explanation"
    )

    st.caption(
        "Detailed explanation of why the selected user/request received a high risk score."
    )

    selected_username = (
        st.session_state.get(
            "selected_username"
        )
    )

    # ------------------------------------------------------
    # NO USER SELECTED
    # ------------------------------------------------------

    if not selected_username:

        st.info(
            "Go to Overview and select a High Risk user."
        )

        return

    # ------------------------------------------------------
    # FIND USER
    # ------------------------------------------------------

    user_rows = df[
        df["Username"].astype(str)
        == str(selected_username)
    ].copy()

    if user_rows.empty:

        st.error(
            "Selected user was not found in the risk scoring data."
        )

        return

    # ------------------------------------------------------
    # BACK BUTTON
    # ------------------------------------------------------

    if st.button(
        "← Back to Overview"
    ):

        st.session_state[
            "page"
        ] = "Overview"

        st.rerun()

    st.markdown("---")

    # ------------------------------------------------------
    # SELECT HIGHEST RISK REQUEST
    # ------------------------------------------------------

    selected_row = (
        user_rows
        .sort_values(
            [
                "Risk_Score",
                "Anomaly_Label"
            ],
            ascending=[
                False,
                True
            ]
        )
        .iloc[0]
    )

    score = int(
        selected_row["Risk_Score"]
    )

    category = risk_category(
        score
    )

    # ======================================================
    # USER SUMMARY
    # ======================================================

    st.subheader(
        f"👤 {selected_username}"
    )

    summary1, summary2, summary3 = st.columns(3)

    summary1.metric(
        "Risk Score",
        f"{score}/100"
    )

    summary2.metric(
        "Risk Level",
        category
    )

    summary3.metric(
        "Anomaly Label",
        int(
            selected_row[
                "Anomaly_Label"
            ]
        )
    )

    # ======================================================
    # REQUEST DETAILS
    # ======================================================

    st.markdown(
        "### 📋 Request Details"
    )

    details1, details2 = st.columns(2)

    with details1:

        st.write(
            f"**Username:** "
            f"{selected_row['Username']}"
        )

        st.write(
            f"**Client IP:** "
            f"{selected_row['Client_IP']}"
        )

        st.write(
            f"**Endpoint:** "
            f"{selected_row['Endpoint']}"
        )

        st.write(
            f"**HTTP Method:** "
            f"{selected_row['HTTP_Method']}"
        )

    with details2:

        st.write(
            f"**HTTP Status:** "
            f"{int(selected_row['HTTP_Status'])}"
        )

        timestamp = selected_row.get(
            "Timestamp"
        )

        if pd.notna(timestamp):

            st.write(
                f"**Timestamp:** {timestamp}"
            )

        else:

            st.write(
                "**Timestamp:** Not available"
            )

        st.write(
            f"**Risk Category:** "
            f"{selected_row['Risk_Category']}"
        )

        st.write(
            f"**Attack Type:** "
            f"{selected_row['Attack_Type']}"
        )

    # ======================================================
    # WHY FLAGGED
    # ======================================================

    st.markdown(
        "### 🚨 Why Was This Request Flagged?"
    )

    if int(
        selected_row["Anomaly_Label"]
    ) == -1:

        st.error(
            "This request was classified as an anomaly "
            "by the Isolation Forest model because its "
            "behavioral feature pattern was unusual "
            "compared with normal API request behavior."
        )

    else:

        st.info(
            "This request was not directly classified as "
            "an Isolation Forest anomaly, but other "
            "risk-scoring signals contributed to its "
            "risk score."
        )

    st.markdown(
        "**Recorded Detection Reason:**"
    )

    st.info(
        str(
            selected_row[
                "Detection_Reason"
            ]
        )
    )

    # ======================================================
    # EVIDENCE FOUND
    # ======================================================

    st.markdown(
        "### 🔍 Evidence Found"
    )

    evidence = []

    if int(
        selected_row["Anomaly_Label"]
    ) == -1:

        evidence.append(
            "Isolation Forest classified this request as anomalous."
        )

    attack_type = str(
        selected_row["Attack_Type"]
    )

    if attack_type.lower() != "normal":

        evidence.append(
            f"The request is associated with the classified attack type: {attack_type}."
        )

    endpoint = str(
        selected_row["Endpoint"]
    )

    suspicious_tokens = (
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

    if any(
        token in endpoint.lower()
        for token in suspicious_tokens
    ):

        evidence.append(
            f"The request accessed a potentially sensitive endpoint: {endpoint}."
        )

    status = int(
        selected_row["HTTP_Status"]
    )

    if status in {
        400,
        401,
        403,
        404,
        405
    }:

        evidence.append(
            f"The request returned HTTP {status}, indicating a client-side or access-related failure."
        )

    elif 500 <= status <= 599:

        evidence.append(
            f"The request returned HTTP {status}, indicating a server-side failure."
        )

    requests_per_user = float(
        selected_row[
            "Requests_Per_User"
        ]
    )

    if requests_per_user >= 80:

        evidence.append(
            f"The user generated {requests_per_user:.0f} requests, indicating high request activity."
        )

    elif requests_per_user >= 40:

        evidence.append(
            f"The user generated {requests_per_user:.0f} requests, indicating elevated request activity."
        )

    requests_per_ip = float(
        selected_row[
            "Requests_Per_IP"
        ]
    )

    if requests_per_ip >= 100:

        evidence.append(
            f"The client IP generated {requests_per_ip:.0f} requests, indicating high traffic from the same IP."
        )

    requests_per_session = float(
        selected_row[
            "Requests_Per_Session"
        ]
    )

    if requests_per_session >= 40:

        evidence.append(
            f"The session generated {requests_per_session:.0f} requests."
        )

    failure_rate = float(
        selected_row[
            "Failure_Rate_Per_User"
        ]
    )

    if failure_rate >= 50:

        evidence.append(
            f"The user's failure rate is {failure_rate:.1f}%."
        )

    elif failure_rate >= 25:

        evidence.append(
            f"The user's failure rate is elevated at {failure_rate:.1f}%."
        )

    unique_endpoints = float(
        selected_row[
            "Unique_Endpoints_Per_User"
        ]
    )

    if unique_endpoints >= 20:

        evidence.append(
            f"The user accessed {unique_endpoints:.0f} unique endpoints."
        )

    if evidence:

        for index, item in enumerate(
            evidence,
            start=1
        ):

            st.write(
                f"**{index}.** {item}"
            )

    else:

        st.info(
            "No additional strong evidence was identified."
        )

    # ======================================================
    # BEHAVIORAL EVIDENCE
    # ======================================================

    st.markdown(
        "### 📊 Behavioral Evidence"
    )

    evidence_values = {
        "Requests / User":
            f"{float(selected_row['Requests_Per_User']):.0f}",

        "Requests / IP":
            f"{float(selected_row['Requests_Per_IP']):.0f}",

        "Requests / Session":
            f"{float(selected_row['Requests_Per_Session']):.0f}",

        "Unique Endpoints":
            f"{float(selected_row['Unique_Endpoints_Per_User']):.0f}",

        "Failure Rate":
            f"{float(selected_row['Failure_Rate_Per_User']):.1f}%",

        "Response Time":
            f"{float(selected_row['Response_Time_ms']):.0f} ms",

        "Average Response Time":
            f"{float(selected_row['Average_Response_Time_User']):.0f} ms",
    }

    evidence_columns = st.columns(4)

    for index, (
        label,
        value
    ) in enumerate(
        evidence_values.items()
    ):

        with evidence_columns[
            index % 4
        ]:

            st.metric(
                label,
                value
            )

    # ======================================================
    # RISK SCORE ANALYSIS
    # ======================================================

    st.markdown(
        "### 📈 Risk Score Analysis"
    )

    breakdown = get_risk_breakdown(
        selected_row,
        df
    )

    if breakdown:

        breakdown_df = pd.DataFrame(
            [
                {
                    "Risk Signal": signal,
                    "Points": f"+{points}",
                    "Explanation": explanation,
                }

                for signal, points, explanation
                in breakdown
            ]
        )

        st.dataframe(
            breakdown_df,
            use_container_width=True,
            hide_index=True
        )

        calculated_points = sum(
            points
            for _, points, _
            in breakdown
        )

        st.write(
            f"**Detected contributing signals:** "
            f"{calculated_points} points"
            f"  |  "
            f"**Final stored score:** "
            f"{score}/100"
        )

        if calculated_points != score:

            st.caption(
                "Note: The breakdown shown here is an explanatory "
                "view of suspicious signals. The final risk score "
                "is the score already stored by risk_scoring.py."
            )

    else:

        st.info(
            "No strong suspicious signals were found."
        )

    # ======================================================
    # FINAL INTERPRETATION
    # ======================================================

    st.markdown(
        "### 🧠 Final Interpretation"
    )

    if score >= 85:

        st.error(
            f"**Critical Risk — {score}/100**\n\n"
            "Multiple suspicious signals are present. "
            "The observed activity should be investigated."
        )

    elif score >= 65:

        st.warning(
            f"**High Risk — {score}/100**\n\n"
            "The observed API behavior is significantly "
            "different from the expected pattern and "
            "requires investigation."
        )

    elif score >= 35:

        st.info(
            f"**Medium Risk — {score}/100**\n\n"
            "Some suspicious behavioral signals were observed."
        )

    else:

        st.success(
            f"**Low Risk — {score}/100**\n\n"
            "No strong combination of suspicious signals was observed."
        )

    # ======================================================
    # OTHER ANOMALOUS ACTIVITY
    # ======================================================

    st.markdown(
        "### 👀 Other Anomalous Activity From This User"
    )

    user_activity_columns = [
        "Timestamp",
        "Endpoint",
        "HTTP_Status",
        "Risk_Score",
        "Risk_Category",
        "Attack_Type",
        "Detection_Reason",
    ]

    user_activity = user_rows[
        user_rows["Anomaly_Label"] == -1
    ][user_activity_columns].sort_values(
        "Risk_Score",
        ascending=False
    )

    if user_activity.empty:

        st.info(
            "No other anomalous requests were found for this user."
        )

    else:

        if "Timestamp" in user_activity.columns:

            user_activity["Timestamp"] = (
                user_activity["Timestamp"]
                .dt.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

        st.dataframe(
            user_activity,
            use_container_width=True,
            hide_index=True
        )


# ==========================================================
# MAIN

# ==========================================================

def main():

    st.set_page_config(
        page_title="API Risk Dashboard",
        page_icon="🛡️",
        layout="wide"
    )

    # ======================================================
    # LOAD DATA
    # ======================================================

    df = load_risk_data()

    if df.empty:

        st.warning(
            "No risk scoring records were found."
        )

        return

    # ======================================================
    # SESSION STATE
    # ======================================================

    if "page" not in st.session_state:

        st.session_state[
            "page"
        ] = "Overview"

    # ======================================================
    # SIDEBAR
    # ======================================================

    st.sidebar.title(
        "🛡️ API Shield AI"
    )

    st.sidebar.caption(
        "Navigation"
    )

    page = st.sidebar.radio(
        "Go to",
        [
            "Overview",
            "Anomaly Explanation"
        ],
        index=(
            0
            if st.session_state["page"]
            == "Overview"
            else 1
        )
    )

    st.session_state[
        "page"
    ] = page

    st.sidebar.markdown("---")

    st.sidebar.caption(
        "Machine Learning-Based API\n"
        "Anomaly and Abuse Detection"
    )

    # ======================================================
    # FILTERS
    # ======================================================

    # Filters are displayed only on Overview.
    # This prevents filters from interfering with
    # the selected user's explanation page.

    if page == "Overview":

        st.sidebar.markdown("---")

        st.sidebar.header(
            "Filter Results"
        )

        # --------------------------------------------------
        # Attack Type Filter
        # --------------------------------------------------

        all_attacks = sorted(
            df["Attack_Type"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_attacks = st.sidebar.multiselect(
            "Filter by Attack Type (select none for all)",
            options=all_attacks
        )

        # --------------------------------------------------
        # Risk Category Filter
        # --------------------------------------------------

        all_categories = [
            "Low Risk",
            "Medium Risk",
            "High Risk",
            "Critical Risk"
        ]

        selected_categories = (
            st.sidebar.multiselect(
                "Filter by Risk Category (select none for all)",
                options=all_categories
            )
        )

        # --------------------------------------------------
        # Username Search
        # --------------------------------------------------

        user_search = st.sidebar.text_input(
            "Filter by Username (exact/partial)"
        )

        # --------------------------------------------------
        # Endpoint Search
        # --------------------------------------------------

        endpoint_search = st.sidebar.text_input(
            "Filter by Endpoint (exact/partial)"
        )

        # --------------------------------------------------
        # IP Search
        # --------------------------------------------------

        ip_search = st.sidebar.text_input(
            "Filter by Client IP"
        )

        # ==================================================
        # APPLY FILTERS
        # ==================================================

        filtered_df = df.copy()

        if selected_attacks:

            filtered_df = filtered_df[
                filtered_df[
                    "Attack_Type"
                ].isin(selected_attacks)
            ]

        if selected_categories:

            filtered_df = filtered_df[
                filtered_df[
                    "Risk_Category"
                ].isin(selected_categories)
            ]

        if user_search:

            filtered_df = filtered_df[
                filtered_df[
                    "Username"
                ]
                .astype(str)
                .str.contains(
                    user_search,
                    case=False,
                    na=False
                )
            ]

        if endpoint_search:

            filtered_df = filtered_df[
                filtered_df[
                    "Endpoint"
                ]
                .astype(str)
                .str.contains(
                    endpoint_search,
                    case=False,
                    na=False
                )
            ]

        if ip_search:

            filtered_df = filtered_df[
                filtered_df[
                    "Client_IP"
                ]
                .astype(str)
                .str.contains(
                    ip_search,
                    case=False,
                    na=False
                )
            ]

        # ==================================================
        # EMPTY FILTER RESULT
        # ==================================================

        if filtered_df.empty:

            st.warning(
                "No records match the active filters."
            )

            return

        # ==================================================
        # SHOW OVERVIEW
        # ==================================================

        show_overview(
            df,
            filtered_df
        )

    else:

        # ==================================================
        # EXPLANATION PAGE
        # ==================================================

        show_explanation(
            df
        )


# ==========================================================
# RUN
# ==========================================================

if __name__ == "__main__":
    main()