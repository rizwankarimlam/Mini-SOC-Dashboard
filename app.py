"""
Mini SOC Dashboard
Run:  streamlit run app.py
"""
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from soc.detectors import SEVERITY_ORDER, Thresholds, ip_risk_table, run_all
from soc.enrich import abuseipdb_check, is_public_ip
from soc.generator import generate
from soc.parsers import parse_logs

st.set_page_config(page_title="Mini SOC Dashboard", page_icon="🛡️", layout="wide")

# ---------- Colors (validated dark-mode palette) ----------
SOURCE_COLORS = {"SSH": "#3987e5", "Web": "#d95926", "Firewall": "#199e70"}
SEVERITY_COLORS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#3987e5"}
SEVERITY_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}
ACCENT = "#3987e5"
TEXT_MUTED = "#c3c2b7"
GRID = "rgba(240,239,236,0.08)"


def style(fig: go.Figure, height: int = 320) -> go.Figure:
    fig.update_layout(
        template="plotly_dark", height=height,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10), font=dict(color=TEXT_MUTED, size=13),
        hoverlabel=dict(bgcolor="#1f1f1d", font_color="#f0efec", bordercolor="#3a3a37"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, title=None),
        barcornerradius=4, bargap=0.35,
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, title=None)
    fig.update_yaxes(gridcolor=GRID, zeroline=False, title=None)
    return fig


# ---------- Data loading ----------
@st.cache_data(show_spinner="Generating sample logs...")
def load_sample() -> tuple[pd.DataFrame, dict]:
    texts = generate()
    return parse_logs(texts), texts


@st.cache_data(show_spinner="Parsing uploaded logs...")
def load_uploaded(contents: tuple[str, ...]) -> pd.DataFrame:
    return parse_logs(list(contents))


@st.cache_data(ttl=3600, show_spinner=False)
def cached_abuse_lookup(ip: str, key: str) -> dict:
    return abuseipdb_check(ip, key)


def default_api_key() -> str:
    try:
        return st.secrets.get("ABUSEIPDB_API_KEY", "")
    except Exception:
        return ""


# ---------- Sidebar ----------
with st.sidebar:
    st.title("🛡️ Mini SOC")
    source = st.radio("Data source", ["Sample data (demo)", "Upload my log files"])

    sample_texts = None
    if source == "Upload my log files":
        files = st.file_uploader(
            "SSH auth.log, Apache/Nginx access.log, UFW firewall log",
            type=["log", "txt"], accept_multiple_files=True,
        )
        if not files:
            st.info("Upload one or more log files to begin.")
            st.stop()
        events = load_uploaded(tuple(f.getvalue().decode("utf-8", errors="ignore") for f in files))
    else:
        events, sample_texts = load_sample()

    if events.empty:
        st.error("No supported log lines were found in these files.")
        st.stop()

    with st.expander("⚙️ Detection thresholds"):
        th = Thresholds(
            brute_force_attempts=st.slider("Brute force: failed logins", 3, 30, 5),
            brute_force_window_min=st.slider("Brute force: window (minutes)", 1, 30, 5),
            port_scan_ports=st.slider("Port scan: distinct ports", 5, 100, 10),
            port_scan_window_sec=st.slider("Port scan: window (seconds)", 10, 300, 60),
            dir_brute_errors=st.slider("Dir brute force: 4xx errors", 5, 100, 20),
            dir_brute_window_sec=st.slider("Dir brute force: window (seconds)", 10, 300, 60),
        )

    tmin, tmax = events["timestamp"].min().to_pydatetime(), events["timestamp"].max().to_pydatetime()
    if tmin < tmax:
        t_from, t_to = st.slider("Time range", min_value=tmin, max_value=tmax,
                                 value=(tmin, tmax), format="MMM DD HH:mm")
    else:
        t_from, t_to = tmin, tmax

    severities = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)

    with st.expander("🌐 Threat intel (optional)"):
        api_key = st.text_input("AbuseIPDB API key", value=default_api_key(), type="password",
                                help="Free key from abuseipdb.com. Used only for IP lookups.")

    if sample_texts:
        st.divider()
        st.caption("Download the sample logs:")
        for name, text in sample_texts.items():
            st.download_button(f"⬇️ {name}", text, file_name=name, width="stretch")

# ---------- Detection + filters ----------
alerts_all = run_all(events, th)
ev = events[(events["timestamp"] >= t_from) & (events["timestamp"] <= t_to)]
alerts = alerts_all[(alerts_all["timestamp"] >= t_from) & (alerts_all["timestamp"] <= t_to)
                    & alerts_all["severity"].astype(str).isin(severities)] if not alerts_all.empty else alerts_all

# ---------- Header + KPIs ----------
st.title("🛡️ Mini SOC Dashboard")
st.caption(f"Security monitoring for SSH, web and firewall logs · {len(ev):,} events · "
           f"{t_from:%d %b %H:%M} → {t_to:%d %b %H:%M}")

n_crit = int((alerts["severity"] == "Critical").sum()) if not alerts.empty else 0
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total events", f"{len(ev):,}")
k2.metric("Failed logins", f"{(ev['event'] == 'failed_login').sum():,}")
k3.metric("Unique source IPs", f"{ev['src_ip'].nunique():,}")
k4.metric("Alerts", f"{len(alerts):,}")
k5.metric("Critical alerts", n_crit)

if n_crit:
    for _, a in alerts[alerts["severity"] == "Critical"].iterrows():
        st.error(f"🔴 **CRITICAL: {a['rule']}** from `{a['src_ip']}` at {a['timestamp']:%d %b %H:%M}: "
                 f"{a['description']}")

tab_over, tab_alerts, tab_ip, tab_logs, tab_about = st.tabs(
    ["📊 Overview", "🚨 Alerts", "🔎 IP Investigation", "📜 Raw Logs", "ℹ️ How it works"])

# ---------- Overview ----------
with tab_over:
    st.subheader("Event activity over time")
    span_h = max((t_to - t_from).total_seconds() / 3600, 1)
    freq = "5min" if span_h <= 3 else "15min" if span_h <= 12 else "30min"
    timeline = (ev.set_index("timestamp").groupby("source").resample(freq).size()
                  .rename("events").reset_index())
    fig = px.line(timeline, x="timestamp", y="events", color="source",
                  color_discrete_map=SOURCE_COLORS,
                  category_orders={"source": ["SSH", "Web", "Firewall"]})
    fig.update_traces(line_width=2, hovertemplate="%{x|%d %b %H:%M}<br>%{y} events")
    fig.update_layout(hovermode="x unified")
    st.plotly_chart(style(fig, 300), width="stretch")

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Alerts by severity")
        if alerts.empty:
            st.success("No alerts in this range ✅")
        else:
            sev = (alerts["severity"].astype(str).value_counts()
                   .reindex(SEVERITY_ORDER, fill_value=0).reset_index())
            sev.columns = ["severity", "alerts"]
            sev["label"] = sev["severity"].map(lambda s: f"{SEVERITY_ICONS[s]} {s}")
            fig = go.Figure(go.Bar(
                x=sev["alerts"], y=sev["label"], orientation="h", text=sev["alerts"],
                textposition="outside", marker_color=sev["severity"].map(SEVERITY_COLORS),
                hovertemplate="%{y}: %{x} alerts<extra></extra>"))
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(style(fig, 260), width="stretch")
    with c2:
        st.subheader("Alerts by detection rule")
        if not alerts.empty:
            rules = alerts["rule"].value_counts().sort_values().reset_index()
            rules.columns = ["rule", "alerts"]
            fig = go.Figure(go.Bar(
                x=rules["alerts"], y=rules["rule"], orientation="h", marker_color=ACCENT,
                text=rules["alerts"], textposition="outside",
                hovertemplate="%{y}: %{x}<extra></extra>"))
            st.plotly_chart(style(fig, 260), width="stretch")

    st.subheader("Top risky IPs")
    risk = ip_risk_table(alerts)
    if risk.empty:
        st.info("No risky IPs in this range.")
    else:
        top = risk.head(10).sort_values("risk_score")
        fig = go.Figure(go.Bar(
            x=top["risk_score"], y=top["src_ip"], orientation="h", marker_color=ACCENT,
            text=top["risk_score"], textposition="outside", customdata=top[["alerts", "rules"]],
            hovertemplate="<b>%{y}</b><br>Risk score: %{x}<br>Alerts: %{customdata[0]}"
                          "<br>%{customdata[1]}<extra></extra>"))
        st.plotly_chart(style(fig, 320), width="stretch")
        st.caption("Risk score = Critical×10 + High×5 + Medium×2 + Low×1")

# ---------- Alerts ----------
with tab_alerts:
    st.subheader(f"🚨 {len(alerts)} alerts")
    if alerts.empty:
        st.success("Nothing suspicious found with the current filters ✅")
    else:
        show = alerts.copy()
        show["severity"] = show["severity"].astype(str).map(lambda s: f"{SEVERITY_ICONS[s]} {s}")
        st.dataframe(
            show, width="stretch", hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", format="DD MMM HH:mm:ss"),
                "severity": "Severity", "rule": "Detection rule", "src_ip": "Source IP",
                "count": st.column_config.NumberColumn("Events"),
                "description": st.column_config.TextColumn("Details", width="large"),
                "mitre": "MITRE ATT&CK",
            })
        st.download_button("⬇️ Download alerts (CSV)", alerts.to_csv(index=False),
                           file_name=f"soc_alerts_{datetime.now():%Y%m%d_%H%M}.csv", mime="text/csv")

# ---------- IP Investigation ----------
with tab_ip:
    st.subheader("🔎 Investigate an IP address")
    flagged = list(ip_risk_table(alerts_all)["src_ip"])
    others = sorted(set(events["src_ip"]) - set(flagged))
    ip = st.selectbox("Choose an IP (flagged IPs are listed first)", flagged + others,
                      format_func=lambda x: f"⚠️ {x}" if x in flagged else x)
    ip_ev = events[events["src_ip"] == ip]
    ip_al = alerts_all[alerts_all["src_ip"] == ip] if not alerts_all.empty else alerts_all

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Events", len(ip_ev))
    m2.metric("Alerts", len(ip_al))
    m3.metric("First seen", f"{ip_ev['timestamp'].min():%d %b %H:%M}")
    m4.metric("Last seen", f"{ip_ev['timestamp'].max():%d %b %H:%M}")

    by_src = ip_ev["source"].value_counts()
    st.caption(" · ".join(f"{s}: {n}" for s, n in by_src.items()))

    if not ip_al.empty:
        st.markdown("**Alerts for this IP**")
        for _, a in ip_al.iterrows():
            st.markdown(f"{SEVERITY_ICONS[str(a['severity'])]} **{a['severity']}: {a['rule']}** "
                        f"({a['timestamp']:%d %b %H:%M}): {a['description']}  \n"
                        f"<small>MITRE: {a['mitre']}</small>", unsafe_allow_html=True)
    else:
        st.success("No alerts for this IP.")

    st.markdown("**Threat intelligence (AbuseIPDB)**")
    if not is_public_ip(ip):
        st.caption("This is a private or reserved IP (the demo data uses reserved documentation ranges), "
                   "so there is nothing to look up on the internet.")
    elif st.button("Check reputation on AbuseIPDB"):
        res = cached_abuse_lookup(ip, api_key)
        if res["ok"]:
            a1, a2, a3, a4 = st.columns(4)
            a1.metric("Abuse score", f"{res.get('abuseConfidenceScore', 0)}%")
            a2.metric("Reports", res.get("totalReports", 0))
            a3.metric("Country", res.get("countryCode") or "?")
            a4.metric("ISP", (res.get("isp") or "?")[:22])
        else:
            st.warning(res["error"])

    st.markdown("**Activity log**")
    st.dataframe(ip_ev[["timestamp", "source", "event", "user", "status", "path", "dst_port", "user_agent"]],
                 width="stretch", hide_index=True, height=300)

# ---------- Raw logs ----------
with tab_logs:
    st.subheader("📜 Parsed log events")
    f1, f2 = st.columns([1, 2])
    srcs = f1.multiselect("Log source", ["SSH", "Web", "Firewall"], default=["SSH", "Web", "Firewall"])
    q = f2.text_input("Search (IP, user, path, user-agent...)", placeholder="e.g. 203.0.113.45 or /admin")
    view = ev[ev["source"].isin(srcs)]
    if q:
        view = view[view["raw"].str.contains(q, case=False, regex=False)]
    st.caption(f"{len(view):,} matching events")
    st.dataframe(view.drop(columns=["raw"]), width="stretch", hide_index=True, height=450)
    with st.expander("Show raw log lines (first 200)"):
        st.code("\n".join(view["raw"].head(200)), language="log")

# ---------- About ----------
with tab_about:
    st.subheader("How the detection works")
    st.markdown("""
| Rule | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|
| **SSH Brute Force** | Many failed SSH logins from one IP in a short window | High | T1110 Brute Force |
| **Possible Account Compromise** | A successful login from an IP that was just brute forcing | Critical | T1078 Valid Accounts |
| **Port Scan** | One IP hits many different ports in seconds (firewall log) | Medium / High | T1046 Network Service Discovery |
| **SQL Injection** | URL contains SQL patterns like `UNION SELECT`, `' OR '1'='1`, `SLEEP(` | High | T1190 Exploit Public-Facing App |
| **Cross-Site Scripting** | URL contains `<script>`, `onerror=`, `javascript:` | High | T1190 |
| **Path Traversal** | URL tries `../` or `/etc/passwd` | High | T1190 |
| **Command Injection** | URL contains `;cat`, `&& whoami`, `| ls` | High | T1190 |
| **Hacking Tool Detected** | User-Agent shows sqlmap, nikto, gobuster, nmap... | Medium | T1595 Active Scanning |
| **Directory Brute Force** | Many 4xx errors from one IP in a short window | Medium | T1595.003 Wordlist Scanning |

Thresholds can be tuned from the sidebar. **Supported log formats:** OpenSSH auth log,
Apache/Nginx combined access log, Linux UFW firewall log.

> ⚠️ Demo data is synthetic. Attacker IPs come from reserved documentation ranges
> (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and do not belong to anyone.
""")
