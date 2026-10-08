import html

import altair as alt
import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="API Security Monitor",
    layout="wide"
)


# ============================================================
# DESIGN TOKENS
# ============================================================

BG = "#0d1117"
PANEL = "#161b22"
BORDER = "#21262d"
TEXT = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#38bdf8"

def compact(markup):
    """Strip line indentation so Streamlit's markdown doesn't treat HTML as a code block."""
    return "".join(line.strip() for line in markup.splitlines())


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(f"""
<style>

    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

    html, body, .stApp, [class*="css"] {{
        font-family: 'IBM Plex Sans', -apple-system, 'Segoe UI', sans-serif;
    }}

    .stApp {{ background-color: {BG}; }}

    .block-container {{
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }}

    header[data-testid="stHeader"] {{ background: transparent; }}


        /* Sidebar filter labels */
    section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {{
        color: {TEXT};
        font-weight: 500;
    }}

    /* Sidebar */
    section[data-testid="stSidebar"] {{
        background-color: #010409;
        border-right: 1px solid {BORDER};
    }}

    /* Page header */
    .page-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 18px;
        margin-bottom: 22px;
        border-bottom: 1px solid {BORDER};
    }}
    .page-title {{
        font-size: 50px;
        font-weight: 600;
        color: {TEXT};
        margin: 0;
    }}
    .page-subtitle {{
        font-size: 13px;
        color: {MUTED};
        margin: 4px 0 0 0;
    }}
    /* KPI cards */
    .kpi-card {{
        background: {PANEL};
        border: 1px solid {BORDER};
        border-left: 3px solid var(--accent, {ACCENT});
        border-radius: 6px;
        padding: 16px 18px;
        min-height: 118px;
    }}
    .kpi-title {{
        font-size: 13px;
        color: {MUTED};
        font-weight: 500;
        margin-bottom: 8px;
    }}
    .kpi-value {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 32px;
        font-weight: 500;
        color: {TEXT};
        line-height: 1.1;
    }}
    .kpi-subtitle {{
        font-size: 12px;
        color: {MUTED};
        margin-top: 8px;
    }}

    /* Section headings */
    .section-title {{
        font-size: 16px;
        font-weight: 600;
        color: {TEXT};
        margin: 0 0 2px 0;
    }}
    .section-subtitle {{
        font-size: 12px;
        color: {MUTED};
        margin: 0 0 12px 0;
    }}

    /* Chart panels */
    div[data-testid="stVerticalBlockBorderWrapper"] {{
        background: {PANEL};
        border-color: {BORDER};
        border-radius: 6px;
    }}

    /* Activity table */
    .table-wrap {{
        background: {PANEL};
        border: 1px solid {BORDER};
        border-radius: 6px;
        overflow-x: auto;
    }}
    .activity-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 14px;
    }}
    .activity-table th {{
        background-color: #1c2128;
        color: {MUTED};
        text-align: left;
        padding: 12px 18px;
        font-weight: 500;
        font-size: 13px;
        border-bottom: 1px solid {BORDER};
        white-space: nowrap;
    }}
    .activity-table td {{
        color: {TEXT};
        padding: 12px 18px;
        border-bottom: 1px solid {BORDER};
        vertical-align: middle;
    }}
    .activity-table tr:last-child td {{ border-bottom: none; }}
    .activity-table tbody tr:hover td {{ background-color: #1c2128; }}

    .num {{
        font-family: 'IBM Plex Mono', monospace;
        text-align: right !important;
    }}
    .activity-table th.num {{ font-family: inherit; }}

    /* Risk score bar */
    .score-cell {{
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 12px;
    }}
    .score-bar {{
        width: 90px;
        height: 6px;
        border-radius: 3px;
        background: {BORDER};
        overflow: hidden;
    }}
    .score-fill {{ height: 100%; border-radius: 3px; }}

    /* Risk badges */
    .badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 3px 10px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        border: 1px solid;
    }}
    .badge::before {{
        content: "";
        width: 6px; height: 6px;
        border-radius: 50%;
        background: currentColor;
    }}
    .risk-critical {{ color: #fca5a5; background: rgba(239,68,68,.12);  border-color: rgba(239,68,68,.35); }}
    .risk-high     {{ color: #fdba74; background: rgba(249,115,22,.12); border-color: rgba(249,115,22,.35); }}
    .risk-medium   {{ color: #fde68a; background: rgba(234,179,8,.12);  border-color: rgba(234,179,8,.35); }}
    .risk-low      {{ color: #86efac; background: rgba(34,197,94,.12);  border-color: rgba(34,197,94,.35); }}

</style>
""", unsafe_allow_html=True)


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():
    return pd.read_csv("data/security_events.csv")


df = load_data()


# ============================================================
# TITLE
# ============================================================

st.markdown(
    compact("""
    <div class="page-header">
        <div>
            <p class="page-title">API Security Monitor</p>
            <p class="page-subtitle">API anomaly and abuse detection · Security operations dashboard</p>
        </div>
    </div>
    """),
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR FILTERS
# ============================================================

st.sidebar.markdown(
    "<div class='section-title' style='font-size:20px; margin-bottom:8px;'>Filters</div>",
    unsafe_allow_html=True
)

user_options = ["All"] + sorted(
    df["user_id"].unique().tolist()
)

attack_options = ["All"] + sorted(
    df["attack_type"].unique().tolist()
)

risk_options = [
    "All",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
]

selected_user = st.sidebar.selectbox(
    "User ID",
    user_options
)

selected_attack = st.sidebar.selectbox(
    "Attack Type",
    attack_options
)

selected_risk = st.sidebar.selectbox(
    "Risk Level",
    risk_options
)


# ============================================================
# APPLY FILTERS
# ============================================================

filtered_df = df.copy()

if selected_user != "All":
    filtered_df = filtered_df[
        filtered_df["user_id"] == selected_user
    ]

if selected_attack != "All":
    filtered_df = filtered_df[
        filtered_df["attack_type"] == selected_attack
    ]

if selected_risk != "All":
    filtered_df = filtered_df[
        filtered_df["risk_level"] == selected_risk
    ]


# ============================================================
# AGGREGATE ACTIVITIES
# ============================================================

activity_summary = (
    filtered_df
    .groupby(
        [
            "user_id",
            "attack_type",
            "risk_level",
            "risk_score"
        ]
    )
    .size()
    .reset_index(name="Occurrences")
    .sort_values(
        ["risk_score", "Occurrences"],
        ascending=[False, False]
    )
)


# ============================================================
# KPI VALUES
# ============================================================

suspicious_activities = len(activity_summary)

suspicious_users = (
    activity_summary["user_id"].nunique()
)

critical = len(
    activity_summary[
        activity_summary["risk_level"] == "CRITICAL"
    ]
)

high = len(
    activity_summary[
        activity_summary["risk_level"] == "HIGH"
    ]
)


# ============================================================
# KPI CARDS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


def kpi_card(title, value, subtitle, color=ACCENT):
    return compact(f"""
    <div class="kpi-card" style="--accent:{color}">
        <div class="kpi-title">{title}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-subtitle">{subtitle}</div>
    </div>
    """)


with col1:
    st.markdown(
        kpi_card(
            "Suspicious Activities",
            suspicious_activities,
            "Detected attack patterns",
            ACCENT
        ),
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        kpi_card(
            "Suspicious Users",
            suspicious_users,
            "Users requiring attention",
            ACCENT
        ),
        unsafe_allow_html=True
    )

with col3:
    st.markdown(
        kpi_card(
            "Critical Activities",
            critical,
            "Immediate investigation",
            SEVERITY_COLORS["CRITICAL"]
        ),
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        kpi_card(
            "High Risk",
            high,
            "Requires investigation",
            SEVERITY_COLORS["HIGH"]
        ),
        unsafe_allow_html=True
    )


st.markdown("<br>", unsafe_allow_html=True)


# ============================================================
# CHARTS
# ============================================================

def style_chart(chart):
    return (
        chart
        .properties(height=280, background="transparent")
        .configure_view(strokeWidth=0)
        .configure_axis(
            labelColor=MUTED,
            titleColor=MUTED,
            gridColor=BORDER,
            domainColor=BORDER,
            tickColor=BORDER,
            labelFontSize=12
        )
    )


chart_col1, chart_col2 = st.columns(2)


# -------------------- ATTACK TYPES ----------------------------

with chart_col1:

    with st.container(border=True):

        st.markdown(
            "<div class='section-title'>Attack Types</div>"
            "<div class='section-subtitle'>Suspicious activities per attack type</div>",
            unsafe_allow_html=True
        )

        attack_counts = (
            activity_summary["attack_type"]
            .value_counts()
        )

        attack_chart_df = attack_counts.reset_index()
        attack_chart_df.columns = ["attack_type", "count"]

        attack_chart = (
            alt.Chart(attack_chart_df)
            .mark_bar(color=ACCENT, cornerRadiusEnd=3)
            .encode(
                x=alt.X("count:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                y=alt.Y("attack_type:N", sort="-x", title=None),
                tooltip=["attack_type", "count"]
            )
        )

        st.altair_chart(
            style_chart(attack_chart),
            use_container_width=True
        )


# -------------------- RISK LEVELS -----------------------------

with chart_col2:

    with st.container(border=True):

        st.markdown(
            "<div class='section-title'>Risk Distribution</div>"
            "<div class='section-subtitle'>Suspicious activities per risk level</div>",
            unsafe_allow_html=True
        )

        risk_counts = (
            activity_summary["risk_level"]
            .value_counts()
        )

        risk_chart_df = risk_counts.reset_index()
        risk_chart_df.columns = ["risk_level", "count"]

        risk_chart = (
            alt.Chart(risk_chart_df)
            .mark_bar(cornerRadiusEnd=3)
            .encode(
                x=alt.X("count:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                y=alt.Y("risk_level:N", sort=SEVERITY_ORDER, title=None),
                color=alt.Color(
                    "risk_level:N",
                    scale=alt.Scale(
                        domain=SEVERITY_ORDER,
                        range=[SEVERITY_COLORS[s] for s in SEVERITY_ORDER]
                    ),
                    legend=None
                ),
                tooltip=["risk_level", "count"]
            )
        )

        st.altair_chart(
            style_chart(risk_chart),
            use_container_width=True
        )


st.markdown("<br>", unsafe_allow_html=True)


# ============================================================
# SUSPICIOUS ACTIVITIES TABLE
# ============================================================

st.markdown(
    "<div class='section-title'>Suspicious Activities</div>"
    "<div class='section-subtitle'>"
    "Aggregated attack activity by user and attack type"
    "</div>",
    unsafe_allow_html=True
)


# ============================================================
# BUILD HTML TABLE
# ============================================================

if activity_summary.empty:

    st.info(
        "No suspicious activities match the selected filters."
    )

else:

    max_score = max(float(activity_summary["risk_score"].max()), 1.0)

    table_html = """
    <div class="table-wrap">
    <table class="activity-table">
        <thead>
            <tr>
                <th>User ID</th>
                <th>Attack Type</th>
                <th class="num">Occurrences</th>
                <th class="num">Risk Score</th>
                <th>Risk Level</th>
            </tr>
        </thead>
        <tbody>
    """

    for _, row in activity_summary.iterrows():

        risk = row["risk_level"]

        risk_class = {
            "CRITICAL": "risk-critical",
            "HIGH": "risk-high",
            "MEDIUM": "risk-medium",
            "LOW": "risk-low"
        }.get(risk, "")

        bar_color = SEVERITY_COLORS.get(risk, ACCENT)
        bar_width = float(row["risk_score"]) / max_score * 100

        table_html += f"""
            <tr>
                <td>{html.escape(str(row["user_id"]))}</td>
                <td>{html.escape(str(row["attack_type"]))}</td>
                <td class="num">{row["Occurrences"]}</td>
                <td class="num">
                    <div class="score-cell">
                        <div class="score-bar">
                            <div class="score-fill" style="width:{bar_width:.0f}%; background:{bar_color};"></div>
                        </div>
                        <span>{row["risk_score"]}</span>
                    </div>
                </td>
                <td>
                    <span class="badge {risk_class}">
                        {html.escape(str(risk))}
                    </span>
                </td>
            </tr>
        """

    table_html += """
        </tbody>
    </table>
    </div>
    """

    st.markdown(
        compact(table_html),
        unsafe_allow_html=True
    )