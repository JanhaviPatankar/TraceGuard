\# TraceGuard — Identity Security \& Anomaly Detection



TraceGuard is a Python-based security analytics dashboard that analyses authentication logs and flags potentially suspicious login activity using explainable, rule-based detection.



\## Features



\- \*\*Authentication Log Analysis:\*\* Analyse login events using uploaded CSV files or built-in synthetic data.

\- \*\*Repeated Failed-Login Detection:\*\* Flag repeated failed authentication attempts within a configurable time window.

\- \*\*Impossible-Travel Detection:\*\* Identify consecutive successful logins whose geographic distance and timestamps imply unusually high travel speeds.

\- \*\*Risk Scoring:\*\* Assign risk scores and severity levels to suspicious events.

\- \*\*Interactive Dashboard:\*\* View login statistics, risk distributions, alerts, and event history.

\- \*\*Customizable Detection Rules:\*\* Adjust failed-login thresholds, time windows, and suspicious travel-speed thresholds.

\- \*\*CSV Export:\*\* Download filtered event analysis for further investigation.



\## Tech Stack



\- Python

\- Streamlit

\- Pandas

\- Haversine distance calculation

\- Rule-based anomaly detection



\## Run Locally



Install the dependencies:



```bash

pip install -r requirements.txt

```



Run the dashboard:



```bash

python -m streamlit run app.py

```



\## Expected CSV Format



The uploaded CSV must contain these columns:



`user`, `timestamp`, `ip\_address`, `city`, `latitude`, `longitude`, `status`



Use `success` or `failed` for the status field, parseable timestamps, and decimal geographic coordinates.



\## How It Works



TraceGuard evaluates authentication events using configurable rules. It counts failed attempts in a rolling time window and compares consecutive successful logins to estimate travel speed. Suspicious events receive risk scores, severity levels, and explanations.



\## Limitations



The included demo data is synthetic. The current prototype uses rule-based detection rather than a trained machine-learning model. It does not automatically resolve IP addresses to geographic locations, persist events in a database, or prove that an account has been compromised. Geographic anomalies and risk scores require human review.



\## Future Improvements



\- SQLite event storage

\- More advanced anomaly detection

\- IP geolocation integration

\- LLM-assisted alert explanations

\- Authentication and role-based access controls

\- Improved reporting and deployment



\## Disclaimer



TraceGuard is an educational prototype intended for security analytics demonstrations. It is not a replacement for a production security monitoring system.

