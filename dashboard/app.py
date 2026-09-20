"""
SentinelAI — Real-Time Explainable Hybrid AI IDS
Mini-SOC Dashboard

Run from the dashboard folder:
    streamlit run app.py
"""

import json
import time

import pandas as pd
import psycopg2
import streamlit as st


# ===============================================================
# PAGE CONFIG
# ===============================================================

st.set_page_config(
    page_title="SentinelAI — SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ===============================================================
# DATABASE CONFIG
# ===============================================================

PG_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "security_events",
    "user": "secuser",
    "password": "secpass",
}


# ===============================================================
# CUSTOM CSS
# ===============================================================

st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #080d18;
        border-right: 1px solid #1f2937;
    }

    /* Remove excessive top padding */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    /* Header */
    .soc-header {
        background: linear-gradient(
            135deg,
            #111827 0%,
            #172033 100%
        );
        border: 1px solid #263244;
        border-radius: 14px;
        padding: 22px 28px;
        margin-bottom: 20px;
    }

    .soc-title {
        font-size: 30px;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 4px;
    }

    .soc-subtitle {
        color: #94a3b8;
        font-size: 14px;
    }

    .live-indicator {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 20px;
        background-color: #12351f;
        color: #4ade80;
        font-size: 13px;
        font-weight: 600;
        border: 1px solid #166534;
    }

    /* KPI cards */
    .kpi-card {
        background-color: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 18px;
        min-height: 115px;
    }

    .kpi-label {
        color: #94a3b8;
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .kpi-value {
        color: #f8fafc;
        font-size: 32px;
        font-weight: 700;
        margin-top: 8px;
    }

    .kpi-small {
        color: #64748b;
        font-size: 12px;
        margin-top: 3px;
    }

    /* Threat banners */
    .threat-critical {
        background-color: #3f1117;
        border: 1px solid #991b1b;
        color: #fca5a5;
    }

    .threat-high {
        background-color: #3b2410;
        border: 1px solid #9a3412;
        color: #fdba74;
    }

    .threat-medium {
        background-color: #3a2e0b;
        border: 1px solid #a16207;
        color: #fde68a;
    }

    .threat-low {
        background-color: #10251a;
        border: 1px solid #166534;
        color: #86efac;
    }

    .threat-banner {
        border-radius: 12px;
        padding: 15px 20px;
        margin-bottom: 20px;
        font-weight: 600;
    }

    /* Section headings */
    .section-title {
        font-size: 20px;
        font-weight: 700;
        color: #f8fafc;
        margin-top: 10px;
        margin-bottom: 12px;
    }

    /* Incident cards */
    .incident-card {
        background-color: #111827;
        border: 1px solid #263244;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 10px;
    }

    .incident-title {
        font-size: 18px;
        font-weight: 700;
        color: #f8fafc;
    }

    .incident-meta {
        color: #94a3b8;
        font-size: 13px;
        margin-top: 5px;
    }

    /* Status */
    .status-online {
        color: #4ade80;
        font-weight: 600;
    }

    .status-warning {
        color: #fbbf24;
        font-weight: 600;
    }

    .status-offline {
        color: #f87171;
        font-weight: 600;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #475569;
        font-size: 12px;
        padding-top: 25px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ===============================================================
# DATABASE
# ===============================================================

@st.cache_resource
def get_connection():
    return psycopg2.connect(**PG_CONFIG)


def run_query(query, params=None):
    try:
        conn = get_connection()
        return pd.read_sql_query(query, conn, params=params)
    except Exception:
        # If PostgreSQL restarted, recreate the cached connection.
        get_connection.clear()
        conn = get_connection()
        return pd.read_sql_query(query, conn, params=params)


# ===============================================================
# SIDEBAR
# ===============================================================

st.sidebar.markdown("## 🛡️ SentinelAI")
st.sidebar.caption("Real-Time Explainable Hybrid AI IDS")

st.sidebar.divider()

auto_refresh = st.sidebar.checkbox(
    "🔄 Live monitoring",
    value=True,
)

refresh_seconds = st.sidebar.select_slider(
    "Refresh interval",
    options=[2, 5, 10, 15],
    value=5,
)

event_limit = st.sidebar.slider(
    "Events to display",
    min_value=10,
    max_value=200,
    value=50,
)

st.sidebar.divider()

st.sidebar.markdown("### System Components")

st.sidebar.markdown(
    """
    <span class="status-online">● Kafka</span><br>
    <span class="status-online">● PostgreSQL</span><br>
    <span class="status-online">● Hybrid ML</span><br>
    <span class="status-online">● SHAP</span><br>
    <span class="status-online">● Response Engine</span>
    """,
    unsafe_allow_html=True,
)


# ===============================================================
# LOAD EVENTS
# ===============================================================

events = run_query(
    """
    SELECT
        id,
        event_timestamp,
        flow_id,
        attack_type,
        confidence,
        malicious_probability,
        anomaly_score,
        severity,
        response_status
    FROM security_events
    ORDER BY event_timestamp DESC
    LIMIT %s
    """,
    params=(event_limit,),
)


# ===============================================================
# LOAD WINDOW STATISTICS
# ===============================================================

windows = run_query(
    """
    SELECT
        window_start,
        window_end,
        total_flows,
        malicious_flows,
        ddos_count,
        portscan_count,
        anomaly_count,
        avg_confidence,
        highest_severity,
        top_attack_source
    FROM window_stats
    ORDER BY window_start ASC
    """
)


# ===============================================================
# HEADER
# ===============================================================

st.markdown(
    """
    <div class="soc-header">
        <div class="soc-title">🛡️ SentinelAI</div>
        <div class="soc-subtitle">
            Real-Time Explainable Hybrid AI Intrusion Detection & Automated Response
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ===============================================================
# CURRENT THREAT LEVEL
# ===============================================================

def severity_rank(value):
    return {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }.get(str(value), 0)


if not events.empty:
    highest_severity = max(
        events["severity"].dropna(),
        key=severity_rank,
        default="Low",
    )
else:
    highest_severity = "Low"


threat_class = {
    "Critical": "threat-critical",
    "High": "threat-high",
    "Medium": "threat-medium",
    "Low": "threat-low",
}.get(highest_severity, "threat-low")


st.markdown(
    f"""
    <div class="threat-banner {threat_class}">
        CURRENT THREAT LEVEL &nbsp;•&nbsp;
        {highest_severity.upper()}
        &nbsp;&nbsp; | &nbsp;&nbsp;
        Monitoring {'ACTIVE' if auto_refresh else 'PAUSED'}
    </div>
    """,
    unsafe_allow_html=True,
)


# ===============================================================
# KPI CALCULATIONS
# ===============================================================

total_flows = len(events)

if not events.empty:
    malicious_flows = int(
        (events["attack_type"] != "BENIGN").sum()
    )

    blocked_count = int(
        events["response_status"]
        .fillna("")
        .str.startswith("blocked")
        .sum()
    )

    anomaly_count = int(
        events["anomaly_score"].fillna(0).gt(0.0161936).sum()
    )

    attack_rate = (
        malicious_flows / total_flows * 100
        if total_flows
        else 0
    )

    avg_confidence = (
        events["confidence"].mean() * 100
        if not events.empty
        else 0
    )

else:
    malicious_flows = 0
    blocked_count = 0
    anomaly_count = 0
    attack_rate = 0
    avg_confidence = 0


# ===============================================================
# KPI CARDS
# ===============================================================

k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Flows</div>
            <div class="kpi-value">{total_flows}</div>
            <div class="kpi-small">Events displayed</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k2:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Malicious</div>
            <div class="kpi-value">{malicious_flows}</div>
            <div class="kpi-small">{attack_rate:.1f}% of displayed flows</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Blocked</div>
            <div class="kpi-value">{blocked_count}</div>
            <div class="kpi-small">Automated responses</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">Anomalies</div>
            <div class="kpi-value">{anomaly_count}</div>
            <div class="kpi-small">Autoencoder alerts</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with k5:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">AI Confidence</div>
            <div class="kpi-value">{avg_confidence:.1f}%</div>
            <div class="kpi-small">Average prediction confidence</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


st.divider()


# ===============================================================
# ATTACK ACTIVITY
# ===============================================================

st.markdown(
    '<div class="section-title">📊 Attack Activity — 10-Second Windows</div>',
    unsafe_allow_html=True,
)

if not windows.empty:

    chart_df = windows.copy()

    chart_df["window_start"] = pd.to_datetime(
        chart_df["window_start"]
    )

    chart_df = chart_df.set_index("window_start")

    chart_columns = [
        "total_flows",
        "malicious_flows",
        "ddos_count",
        "portscan_count",
    ]

    chart_columns = [
        col for col in chart_columns
        if col in chart_df.columns
    ]

    if chart_columns:
        st.line_chart(
            chart_df[chart_columns],
            height=300,
        )

else:
    st.info(
        "Waiting for the first 10-second streaming window..."
    )


st.divider()


# ===============================================================
# TWO-COLUMN OVERVIEW
# ===============================================================

left, right = st.columns([1, 1])


# ---------------------------------------------------------------
# ATTACK DISTRIBUTION
# ---------------------------------------------------------------

with left:

    st.markdown(
        '<div class="section-title">🎯 Attack Distribution</div>',
        unsafe_allow_html=True,
    )

    if not events.empty:

        attack_counts = (
            events[
                events["attack_type"] != "BENIGN"
            ]["attack_type"]
            .value_counts()
        )

        if not attack_counts.empty:
            st.bar_chart(
                attack_counts,
                height=280,
            )
        else:
            st.success("No attacks detected.")

    else:
        st.info("No event data available.")


# ---------------------------------------------------------------
# RESPONSE SUMMARY
# ---------------------------------------------------------------

with right:

    st.markdown(
        '<div class="section-title">🛡️ Automated Response</div>',
        unsafe_allow_html=True,
    )

    if not events.empty:

        response_counts = (
            events["response_status"]
            .fillna("none")
            .apply(
                lambda x:
                "Blocked"
                if str(x).startswith("blocked")
                else "No action"
            )
            .value_counts()
        )

        st.bar_chart(
            response_counts,
            height=280,
        )

        st.metric(
            "Response actions",
            blocked_count,
        )

    else:
        st.info("No response events yet.")


st.divider()


# ===============================================================
# LIVE THREAT FEED
# ===============================================================

st.markdown(
    '<div class="section-title">🚨 Live Threat Feed</div>',
    unsafe_allow_html=True,
)

if not events.empty:

    display_df = events.copy()

    display_df["confidence"] = (
        display_df["confidence"] * 100
    ).round(2).astype(str) + "%"

    display_df["malicious_probability"] = (
        display_df["malicious_probability"]
        .round(4)
    )

    display_df["anomaly_score"] = (
        display_df["anomaly_score"]
        .round(6)
    )

    display_df["event_timestamp"] = (
        pd.to_datetime(
            display_df["event_timestamp"]
        ).dt.strftime("%H:%M:%S")
    )

    display_df = display_df[
        [
            "event_timestamp",
            "flow_id",
            "attack_type",
            "confidence",
            "malicious_probability",
            "anomaly_score",
            "severity",
            "response_status",
        ]
    ]

    display_df.columns = [
        "Time",
        "Flow",
        "Attack",
        "Confidence",
        "Malicious Prob.",
        "Anomaly Score",
        "Severity",
        "Response",
    ]

    st.dataframe(
        display_df,
        use_container_width=True,
        height=430,
        hide_index=True,
    )

else:

    st.info(
        "No security events yet. Start the Kafka producer."
    )


st.divider()


# ===============================================================
# SELECTED INCIDENT
# ===============================================================

st.markdown(
    '<div class="section-title">🔎 Latest Incident Analysis</div>',
    unsafe_allow_html=True,
)

if not events.empty:

    latest = events.iloc[0]

    attack_type = latest["attack_type"]
    confidence = float(latest["confidence"])
    malicious_probability = float(
        latest["malicious_probability"]
    )
    anomaly_score = float(latest["anomaly_score"])
    severity = latest["severity"]
    flow_id = latest["flow_id"]
    response = latest["response_status"]

    a, b, c, d = st.columns(4)

    a.metric(
        "Attack",
        attack_type,
    )

    b.metric(
        "Confidence",
        f"{confidence * 100:.2f}%",
    )

    c.metric(
        "Malicious Probability",
        f"{malicious_probability:.4f}",
    )

    d.metric(
        "Response",
        str(response),
    )

    st.markdown(
        f"""
        <div class="incident-card">
            <div class="incident-title">
                {'🔴' if severity == 'Critical'
                 else '🟠' if severity == 'High'
                 else '🟡'}
                Flow {flow_id} — {attack_type}
            </div>
            <div class="incident-meta">
                Severity: {severity}
                &nbsp; | &nbsp;
                Anomaly Score: {anomaly_score:.6f}
                &nbsp; | &nbsp;
                Response: {response}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===============================================================
# SHAP / AI EXPLANATION
# ===============================================================

st.markdown(
    '<div class="section-title">🧠 AI Explainability</div>',
    unsafe_allow_html=True,
)

st.info(
    "SHAP explanations are generated by the ML pipeline and stored "
    "with security events. The dashboard can display them when "
    "the event schema contains the top_features field."
)


# Check whether top_features exists in database.
try:

    columns_df = run_query(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'security_events'
        """
    )

    available_columns = set(
        columns_df["column_name"].tolist()
    )

except Exception:

    available_columns = set()


if "top_features" in available_columns:

    try:

        shap_df = run_query(
            """
            SELECT flow_id, attack_type, top_features
            FROM security_events
            WHERE attack_type != 'BENIGN'
            ORDER BY event_timestamp DESC
            LIMIT 1
            """
        )

        if not shap_df.empty:

            shap_data = shap_df.iloc[0]["top_features"]

            if isinstance(shap_data, str):
                shap_data = json.loads(shap_data)

            if shap_data:

                shap_display = pd.DataFrame(shap_data)

                if (
                    "feature" in shap_display.columns
                    and "shap_value" in shap_display.columns
                ):

                    shap_display = shap_display[
                        ["feature", "shap_value"]
                    ]

                    shap_display = shap_display.set_index(
                        "feature"
                    )

                    st.bar_chart(
                        shap_display,
                        height=300,
                    )

    except Exception:
        st.caption(
            "SHAP data exists but could not be rendered."
        )


# ===============================================================
# BLOCKED SOURCES
# ===============================================================

st.divider()

st.markdown(
    '<div class="section-title">🔒 Blocked Sources</div>',
    unsafe_allow_html=True,
)

if not events.empty:

    blocked = events[
        events["response_status"]
        .fillna("")
        .str.startswith("blocked")
    ].copy()

    if not blocked.empty:

        blocked_summary = (
            blocked["response_status"]
            .str.replace(
                "blocked:",
                "",
                regex=False,
            )
            .value_counts()
            .reset_index()
        )

        blocked_summary.columns = [
            "Source",
            "Times Blocked",
        ]

        st.dataframe(
            blocked_summary,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.success(
            "No sources have been blocked."
        )

else:

    st.info(
        "No response data available."
    )


# ===============================================================
# MODEL PERFORMANCE
# ===============================================================

st.divider()

st.markdown(
    '<div class="section-title">🤖 AI Engine Performance</div>',
    unsafe_allow_html=True,
)

m1, m2 = st.columns(2)

with m1:

    st.markdown("#### Binary XGBoost — Attack Detection")

    perf1 = pd.DataFrame(
        {
            "Metric": [
                "Accuracy",
                "Precision",
                "Recall",
                "F1",
            ],
            "Score": [
                "99.99%",
                "99.94%",
                "100.00%",
                "99.97%",
            ],
        }
    )

    st.dataframe(
        perf1,
        use_container_width=True,
        hide_index=True,
    )

with m2:

    st.markdown(
        "#### Multiclass XGBoost — Attack Classification"
    )

    perf2 = pd.DataFrame(
        {
            "Metric": [
                "Accuracy",
                "Precision",
                "Recall",
                "F1",
            ],
            "Score": [
                "99.88%",
                "99.88%",
                "99.88%",
                "99.88%",
            ],
        }
    )

    st.dataframe(
        perf2,
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "Model metrics are from the held-out CIC-IDS2017 test split."
)


# ===============================================================
# FOOTER
# ===============================================================

st.markdown(
    """
    <div class="footer">
        SentinelAI • Hybrid XGBoost + Autoencoder + SHAP
        • Kafka Streaming • Automated Response
    </div>
    """,
    unsafe_allow_html=True,
)


# ===============================================================
# AUTO REFRESH
# ===============================================================

if auto_refresh:

    time.sleep(refresh_seconds)

    st.rerun()