
import math
import pandas as pd
import streamlit as st
from datetime import timedelta

st.set_page_config(
    page_title="TraceGuard | Security Analytics",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ TraceGuard")
st.caption("Identity Security & Authentication Anomaly Detection")
st.write(
    "Analyse authentication logs, investigate suspicious login patterns, "
    "and prioritise potentially risky events."
)

REQUIRED_COLUMNS = [
    "user", "timestamp", "ip_address", "city",
    "latitude", "longitude", "status"
]


def make_sample_data():
    """Create demonstration authentication events."""
    now = pd.Timestamp.now().floor("s")

    records = [
        # Suspicious travel: Pune to London in 45 minutes.
        ["alex@example.com", now - pd.Timedelta(minutes=60),
         "192.0.2.10", "Pune", 18.5204, 73.8567, "success"],
        ["alex@example.com", now - pd.Timedelta(minutes=15),
         "192.0.2.11", "London", 51.5072, -0.1276, "success"],

        # Multiple failed logins.
        ["priya@example.com", now - pd.Timedelta(minutes=24),
         "198.51.100.21", "Mumbai", 19.0760, 72.8777, "failed"],
        ["priya@example.com", now - pd.Timedelta(minutes=21),
         "198.51.100.21", "Mumbai", 19.0760, 72.8777, "failed"],
        ["priya@example.com", now - pd.Timedelta(minutes=18),
         "198.51.100.21", "Mumbai", 19.0760, 72.8777, "failed"],
        ["priya@example.com", now - pd.Timedelta(minutes=16),
         "198.51.100.21", "Mumbai", 19.0760, 72.8777, "failed"],
        ["priya@example.com", now - pd.Timedelta(minutes=14),
         "198.51.100.21", "Mumbai", 19.0760, 72.8777, "success"],

        # Ordinary activity.
        ["sam@example.com", now - pd.Timedelta(minutes=35),
         "203.0.113.40", "Pune", 18.5204, 73.8567, "success"],
        ["sam@example.com", now - pd.Timedelta(minutes=10),
         "203.0.113.40", "Pune", 18.5204, 73.8567, "success"],
    ]

    return pd.DataFrame(records, columns=REQUIRED_COLUMNS)


def haversine_km(lat1, lon1, lat2, lon2):
    """Calculate the approximate great-circle distance in kilometres."""
    radius = 6371.0
    lat1, lon1, lat2, lon2 = map(
        math.radians, [lat1, lon1, lat2, lon2]
    )
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


def analyse_logins(df, failed_threshold, window_minutes, speed_threshold):
    """Apply explainable rules to authentication events."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["status"] = df["status"].astype(str).str.strip().str.lower()
    df["user"] = df["user"].astype(str).str.strip()
    df["city"] = df["city"].fillna("Unknown").astype(str)
    df["ip_address"] = df["ip_address"].fillna("Unknown").astype(str)

    for col in ["latitude", "longitude"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=["timestamp"])
    df = df[df["status"].isin(["success", "failed"])]
    df = df[df["user"] != ""]
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["failed_attempts_in_window"] = 0
    df["impossible_travel"] = False
    df["travel_speed_kmh"] = float("nan")
    df["risk_score"] = 0
    df["risk_level"] = "Low"
    df["alert_reason"] = "No rule triggered"

    # Detect repeated failed attempts within a rolling time window.
    for user, group in df.groupby("user"):
        failures = group[group["status"] == "failed"]
        for idx, event in failures.iterrows():
            start = event["timestamp"] - pd.Timedelta(
                minutes=window_minutes
            )
            count = failures[
                (failures["timestamp"] >= start)
                & (failures["timestamp"] <= event["timestamp"])
            ].shape[0]
            df.at[idx, "failed_attempts_in_window"] = count

    # Compare consecutive successful logins for each user.
    for _, group in df[df["status"] == "success"].groupby("user"):
        group = group.sort_values("timestamp")
        previous = None

        for idx, event in group.iterrows():
            if previous is not None:
                hours = (
                    event["timestamp"] - previous["timestamp"]
                ).total_seconds() / 3600

                coordinates = [
                    previous["latitude"], previous["longitude"],
                    event["latitude"], event["longitude"],
                ]

                if hours > 0 and all(pd.notna(v) for v in coordinates):
                    distance = haversine_km(*coordinates)
                    speed = distance / hours
                    df.at[idx, "travel_speed_kmh"] = round(speed, 1)

                    if speed > speed_threshold and distance > 100:
                        df.at[idx, "impossible_travel"] = True

            previous = event

    # Transparent, rule-based risk scoring.
    for idx, event in df.iterrows():
        reasons = []
        score = 0

        if event["failed_attempts_in_window"] >= failed_threshold:
            reasons.append(
                f'{int(event["failed_attempts_in_window"])} failed attempts '
                f"within {window_minutes} minutes"
            )
            score = max(score, 80)

        if event["impossible_travel"]:
            reasons.append(
                f'Unusually fast travel ({event["travel_speed_kmh"]} km/h)'
            )
            score = max(score, 95)

        if event["status"] == "failed" and score == 0:
            score = 15
            reasons.append("Failed authentication")

        df.at[idx, "risk_score"] = score
        df.at[idx, "risk_level"] = (
            "High" if score >= 75
            else "Medium" if score >= 40
            else "Low"
        )
        df.at[idx, "alert_reason"] = (
            "; ".join(reasons) if reasons else "No rule triggered"
        )

    return df


with st.sidebar:
    st.header("⚙️ Detection settings")
    failed_threshold = st.slider(
        "Failed attempts to flag",
        min_value=2, max_value=10, value=3
    )
    window_minutes = st.slider(
        "Failed-login time window (minutes)",
        min_value=5, max_value=60, value=15, step=5
    )
    speed_threshold = st.slider(
        "Suspicious travel speed (km/h)",
        min_value=300, max_value=1200, value=900, step=100
    )
    st.divider()
    st.caption(
        "These are configurable demo rules, not proof of account compromise."
    )

st.subheader("1. Choose your authentication logs")
uploaded = st.file_uploader("Upload a CSV file", type=["csv"])

if uploaded is not None:
    try:
        raw = pd.read_csv(uploaded)
    except Exception as exc:
        st.error(f"Could not read this CSV: {exc}")
        st.stop()

    missing = [col for col in REQUIRED_COLUMNS if col not in raw.columns]
    if missing:
        st.error("Missing required columns: " + ", ".join(missing))
        st.info("Download or inspect the expected CSV format in the sample data.")
        st.stop()
    source_label = "Uploaded CSV"
else:
    raw = make_sample_data()
    source_label = "Built-in synthetic demo data"
    st.info(
        "Showing synthetic demo events with examples of repeated failed "
        "logins, suspicious travel, and normal activity. Upload your own "
        "CSV to analyse other events."
    )

analysed = analyse_logins(
    raw,
    failed_threshold=failed_threshold,
    window_minutes=window_minutes,
    speed_threshold=speed_threshold,
)

high_count = int((analysed["risk_level"] == "High").sum())
medium_count = int((analysed["risk_level"] == "Medium").sum())
failed_count = int((analysed["status"] == "failed").sum())
users_count = int(analysed["user"].nunique())

st.caption(f"Data source: {source_label}")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Login events", len(analysed))
m2.metric("Unique accounts", users_count)
m3.metric("Failed logins", failed_count)
m4.metric("High-risk events", high_count)

st.divider()
st.subheader("2. Security alerts")

alerts = analysed[analysed["risk_score"] >= 75].copy()
if alerts.empty:
    st.success("No high-risk events detected with the current settings.")
else:
    st.warning(f"{len(alerts)} high-risk event(s) require review.")
    st.dataframe(
        alerts[
            ["timestamp", "user", "city", "ip_address", "status",
             "risk_score", "risk_level", "alert_reason"]
        ],
        use_container_width=True,
        hide_index=True,
    )

st.subheader("3. Event risk overview")
left, right = st.columns(2)

with left:
    risk_counts = (
        analysed["risk_level"]
        .value_counts()
        .reindex(["High", "Medium", "Low"], fill_value=0)
    )
    st.bar_chart(risk_counts)

with right:
    st.write("**Events by authentication status**")
    status_counts = analysed["status"].value_counts()
    st.bar_chart(status_counts)

st.divider()
st.subheader("4. Investigate login events")

levels = st.multiselect(
    "Filter by risk level",
    options=["High", "Medium", "Low"],
    default=["High", "Medium", "Low"],
)
users = sorted(analysed["user"].unique())
selected_users = st.multiselect(
    "Filter by account",
    options=users,
    default=users,
)
view = analysed[
    analysed["risk_level"].isin(levels)
    & analysed["user"].isin(selected_users)
].copy()

display_columns = [
    "timestamp", "user", "ip_address", "city", "status",
    "failed_attempts_in_window", "travel_speed_kmh",
    "risk_score", "risk_level", "alert_reason"
]
st.dataframe(
    view[display_columns],
    use_container_width=True,
    hide_index=True,
)

csv_bytes = view.to_csv(index=False).encode("utf-8")
st.download_button(
    "⬇️ Download filtered events",
    data=csv_bytes,
    file_name="traceguard_analysis.csv",
    mime="text/csv",
)

with st.expander("CSV format and detection notes"):
    st.markdown(
        """
        Required columns:

        `user`, `timestamp`, `ip_address`, `city`, `latitude`,
        `longitude`, `status`

        - Timestamps should be parseable by Pandas.
        - Status must be `success` or `failed`.
        - Coordinates are decimal latitude/longitude.
        - Repeated failures are counted in a rolling time window.
        - Travel speed is estimated between consecutive successful logins.
        - Missing coordinates prevent travel analysis for that comparison.
        - Risk scores are rule-based indicators, not a trained ML model.
        - IP geolocation is not looked up automatically; locations must
          be supplied in the CSV.
        """
    )

st.caption(
    "TraceGuard prototype • Uses rule-based detection and synthetic demo data. "
    "Review alerts before drawing security conclusions."
)
