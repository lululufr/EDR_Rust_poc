import os
import sqlite3
from datetime import datetime
from typing import Optional, Tuple

import pandas as pd
import streamlit as st
import plotly.express as px

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from threading import Thread
import textwrap

def wrap_label(s: str, width: int = 16) -> str:
    # Replace spaces with line breaks to avoid overflow
    return "<br>".join(textwrap.wrap(str(s), width=width))

DB_PATH = os.getenv("DB_PATH", "alerts.db")
API_PORT = int(os.getenv("API_PORT", "8000"))

# ---------- DB / data helpers ----------
@st.cache_resource(show_spinner=False)
def get_conn():
    # One shared connection per process
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn = get_conn()
    # Optional: better concurrency for SQLite
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert TEXT NOT NULL,
            triggered_at TEXT NOT NULL,
            machine TEXT NOT NULL,
            cause TEXT NOT NULL
        )
        """
    )
    conn.commit()

def seed_if_empty():
    conn = get_conn()
    (count,) = conn.execute("SELECT COUNT(1) FROM alerts").fetchone()
    if count == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = [
            ("Suspicious command execution blocked", now, "server-01", "EDR CMD BLOQUÉ: <unknown> (pid=35954)"),
        ]
        conn.executemany(
            "INSERT INTO alerts(alert, triggered_at, machine, cause) VALUES (?,?,?,?)",
            rows,
        )
        conn.commit()

def load_df() -> pd.DataFrame:
    conn = get_conn()
    q = """
        SELECT id, alert, triggered_at, machine, cause
        FROM alerts
        ORDER BY datetime(triggered_at) DESC, id DESC
    """
    df = pd.read_sql_query(q, conn)
    if not df.empty:
        df["triggered_at"] = pd.to_datetime(df["triggered_at"], errors="coerce")
    return df

# ---------- NEW: FastAPI in the same process ----------
api = FastAPI(title="EDR Alerts API")

class AlertIn(BaseModel):
    alert: str
    machine: str
    cause: str
    triggered_at: Optional[str] = None  # ISO8601 or "YYYY-MM-DD HH:MM:SS"

def _normalize_ts(v: Optional[str]) -> str:
    if not v:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        try:
            dt = datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
        except Exception:
            dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

@api.post("/alerts")
def create_alert(a: AlertIn):
    ts = _normalize_ts(a.triggered_at)
    try:
        # Use a short-lived writer connection for safety
        with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
            cur = conn.execute(
                "INSERT INTO alerts(alert, triggered_at, machine, cause) VALUES (?,?,?,?)",
                (a.alert.strip(), ts, a.machine.strip(), a.cause.strip()),
            )
            new_id = cur.lastrowid
            conn.commit()
        return {"id": new_id, "alert": a.alert, "machine": a.machine, "cause": a.cause, "triggered_at": ts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@st.cache_resource(show_spinner=False)
def _start_api():
    config = uvicorn.Config(api, host="0.0.0.0", port=API_PORT, log_level="info")
    server = uvicorn.Server(config)
    server.install_signal_handlers = False
    t = Thread(target=server.run, daemon=True)
    t.start()
    return True

# ---------- UI ----------
st.set_page_config(page_title="EDR Dashboard", page_icon="⚠️", layout="wide")
st.title("⚠️ EDR Dashboard ESGI")
st.caption("PoC EDR ESGI")

# Start API once per process
_start_api()

init_db()
seed_if_empty()
df = load_df()

with st.sidebar:
    st.header("Filters")
    st.markdown(f"**API:** `POST http://localhost:{API_PORT}/alerts`")
    search = st.text_input("Search text", placeholder="alert / machine / cause")

    # Date range filter (computed from data)
    min_dt: Optional[pd.Timestamp] = df["triggered_at"].min() if not df.empty else None
    max_dt: Optional[pd.Timestamp] = df["triggered_at"].max() if not df.empty else None
    if min_dt is not None and max_dt is not None:
        start, end = st.date_input(
            "Triggered date range",
            (min_dt.date(), max_dt.date()),
            min_value=min_dt.date(),
            max_value=max_dt.date(),
        )
    else:
        start, end = None, None

    if st.button("Refresh"):
        st.experimental_rerun()

# Apply filters
filtered = df.copy()
if search:
    mask = (
        filtered["alert"].str.contains(search, case=False, na=False)
        | filtered["machine"].str.contains(search, case=False, na=False)
        | filtered["cause"].str.contains(search, case=False, na=False)
    )
    filtered = filtered[mask]

if start and end:
    filtered = filtered[
        (filtered["triggered_at"].dt.date >= start)
        & (filtered["triggered_at"].dt.date <= end)
    ]

# KPIs
c1, c2, c3 = st.columns(3)
c1.metric("Total Alerts", len(filtered))
if not filtered.empty:
    last_ts = filtered["triggered_at"].max()
    c2.metric("Latest Trigger", last_ts.strftime("%Y-%m-%d %H:%M:%S"))
    c3.metric("Machines affected", filtered["machine"].nunique())
else:
    c2.metric("Latest Trigger", "—")
    c3.metric("Machines affected", 0)

st.divider()

# ---------- Charts (Plotly pies) ----------
# 1) Alerts by Type
def make_pie(df_counts, name_col, value_col, title):
    tmp = df_counts.copy()
    tmp["wrapped"] = tmp[name_col].apply(wrap_label)

    fig = px.pie(
        tmp,
        names="wrapped",
        values=value_col,
        title=title,
        hole=0.35,
    )

    # Clean, readable labels + full info on hover
    fig.update_traces(
        textposition="inside",
        textinfo="percent",
        hovertemplate="<b>%{customdata[0]}</b><br>Count: %{value} (%{percent})<extra></extra>",
        customdata=tmp[[name_col]].values,
    )

    # Layout to prevent crowding
    fig.update_layout(
        height=360,
        margin=dict(t=60, b=20, l=20, r=20),
        legend=dict(orientation="h", yanchor="top", y=-0.1, xanchor="left", x=0),
        uniformtext_minsize=10,
        uniformtext_mode="hide",  # hide slice text when it would be too small
    )
    return fig

if not filtered.empty:
    pie1 = (
        filtered.groupby("alert")["id"].count().reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    fig1 = make_pie(pie1, "alert", "count", "Alerts by Type")

    # 2) Alerts by Machine
    pie2 = (
        filtered.groupby("machine")["id"].count().reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    fig2 = make_pie(pie2, "machine", "count", "Alerts by Machine")

    # 3) Alerts by Cause (top 10 + Other)
    cause_counts = (
        filtered.groupby("cause")["id"].count().reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    if len(cause_counts) > 10:
        top = cause_counts.iloc[:9]
        other = pd.DataFrame([{"cause": "Other", "count": cause_counts.iloc[9:]["count"].sum()}])
        cause_counts = pd.concat([top, other], ignore_index=True)
    fig3 = make_pie(cause_counts, "cause", "count", "Alerts by Cause")

    col_a, col_b, col_c = st.columns(3)
    col_a.plotly_chart(fig1, use_container_width=True)
    col_b.plotly_chart(fig2, use_container_width=True)
    col_c.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No data to chart with the current filters.")

st.divider()

# Table
st.subheader("Alert Rows")
st.dataframe(
    filtered.drop(columns=["id"]) if "id" in filtered.columns else filtered,
    use_container_width=True,
)

# Download
if not filtered.empty:
    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("Download filtered CSV", csv, "alerts_filtered.csv", "text/csv")
