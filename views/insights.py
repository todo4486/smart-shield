"""Host risk and traffic insights: leaderboard with trends, top talkers, time heatmap and traffic paths."""
from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from components import severity
from components.guard import require_principal
from components.theme import COLORS, apply_chart_theme
from components.ui import SOURCE_LABELS, empty_state, format_timestamp, page_header, section_label, source_badge
from services import data_source, host_insights_service as insights, network_map_service
from services.authorization import Permission

principal = require_principal()
page_header("Host insights", "Which hosts look riskiest, who talks the most, when traffic happens and where it goes. "
            "Built from stored flows and open alerts only.", eyebrow="Monitor")

if not principal.has(Permission.VIEW_ALERTS):
    st.info("Your role cannot view host insights.")
    st.stop()
sessions = network_map_service.flow_sessions(principal)
if not sessions:
    empty_state("📊", "No flows captured yet", "Insights need stored flows. Run detection on a dataset, start a replay, "
                "or start live packet capture.")
    st.stop()

by_id = {s["id"]: s for s in sessions}
session_id = st.selectbox(
    "Flow source", list(by_id),
    format_func=lambda i: f"#{i} · {SOURCE_LABELS.get(by_id[i]['source_type'], by_id[i]['source_type'])} · "
                          f"{by_id[i]['flow_count']:,} flows · {format_timestamp(by_id[i]['started_at'])}")
source = data_source.classify(by_id[session_id]["source_type"])
flows = insights.load_flows(principal, session_id)
st.markdown(f"{source_badge(source)} <span style='color:var(--ss-muted);font-size:.8rem'>{len(flows):,} flows"
            + (f" (newest {insights.MAX_ROWS:,})" if len(flows) >= insights.MAX_ROWS else "") + "</span>",
            unsafe_allow_html=True)
if by_id[session_id]["source_type"] == "dataset":
    st.caption("Dataset detection stores only the flows the models flagged, so this source shows flagged traffic, "
               "not all traffic.")

risk_tab, talkers_tab, heat_tab, paths_tab = st.tabs(["Host risk", "Top talkers", "When", "Traffic paths"])

with risk_tab:
    board = insights.host_leaderboard(principal, session_id, flows)
    formula = ("Risk score (same as the Network Map) = 40 per open critical alert naming the host, 20 per high, 8 per "
               "medium, 3 per low, + 30 × the share of its flows flagged by the classifier or anomaly detector, + 15 "
               "if one of those alerts is in an open incident; max 100.")
    if not board:
        st.info("No hosts in this source.")
    else:
        st.dataframe(pd.DataFrame([{
            "Host": r.host, "Risk score": r.score,
            "Open alerts": " · ".join(f"{n} {severity.plain(s)}" for s, n in
                                      sorted(r.alerts.items(), key=lambda kv: -severity.rank(kv[0]))) or "—",
            "Flagged share": None if r.flagged_share is None else round(100 * r.flagged_share, 1),
            "In incident": "yes" if r.in_incident else "",
            "Flagged flows over time": r.trend, "Flows": r.flows, "Bytes": r.bytes} for r in board]),
            hide_index=True, height=min(600, 38 + 35 * len(board)),
            column_config={
                "Risk score": st.column_config.ProgressColumn("Risk score", help=formula, min_value=0, max_value=100,
                                                              format="%d"),
                "Flagged share": st.column_config.NumberColumn("Flagged share (%)", format="%.1f"),
                "Flagged flows over time": st.column_config.LineChartColumn(
                    "Flagged flows over time", help=f"{insights.TREND_BUCKETS} equal buckets across this source's "
                                                    "time span (derived)."),
                "Bytes": st.column_config.NumberColumn(format="compact")})
        st.caption(formula)

with talkers_tab:
    talkers = insights.top_talkers(flows)
    c1, c2, c3 = st.columns(3)
    for column, key, title, label in ((c1, "hosts", "Busiest hosts (bytes sent + received)", "host"),
                                      (c2, "ports", "Top destination ports (flows)", "dst_port"),
                                      (c3, "protocols", "Protocols (flows)", "protocol")):
        with column:
            section_label(title)
            frame = talkers[key]
            if frame.empty:
                st.caption("No data.")
                continue
            value = "bytes" if key == "hosts" else "flows"
            data = frame.iloc[::-1]
            fig = go.Figure(go.Bar(x=data[value], y=data[label].astype(str), orientation="h",
                                   marker_color=COLORS["accent"], hovertemplate="%{y}: %{x:,}<extra></extra>"))
            fig.update_layout(yaxis=dict(type="category", automargin=True), xaxis_title=value,
                              margin=dict(t=10))
            st.plotly_chart(apply_chart_theme(fig, height=320), theme=None, key=f"talkers_{key}")

with heat_tab:
    metric = st.segmented_control("Show", ["bytes", "flagged"], default="bytes",
                                  format_func={"bytes": "Traffic (bytes)", "flagged": "Flagged flows"}.get)
    grid = insights.heatmap(flows, metric or "bytes")
    fig = go.Figure(go.Heatmap(z=grid.values, x=[f"{h:02d}" for h in grid.columns], y=list(grid.index),
                               colorscale=[[0, "rgba(59,130,246,0.04)"], [1, COLORS["critical"] if metric == "flagged"
                                                                           else COLORS["cyan"]]],
                               hovertemplate="%{y} %{x}:00 UTC · %{z:,.0f}<extra></extra>", xgap=2, ygap=2))
    fig.update_layout(title="By hour of day (UTC) and day of week, by flow start time", xaxis_title="Hour (UTC)",
                      yaxis=dict(autorange="reversed"))
    st.plotly_chart(apply_chart_theme(fig, height=320), theme=None, key="insights_heatmap")
    st.caption("Empty cells had no flows in this source. Datasets show the days and hours they were recorded.")

with paths_tab:
    graph = insights.sankey(flows)
    if not graph["labels"]:
        st.info("No flows with byte counts to draw.")
    else:
        colors = {"subnet": COLORS["accent"], "service": COLORS["warn"], "dest": COLORS["cyan"]}
        fig = go.Figure(go.Sankey(
            node=dict(label=graph["labels"], color=[colors[k] for k in graph["kinds"]], pad=14, thickness=14),
            link=dict(source=graph["source"], target=graph["target"], value=graph["value"],
                      color="rgba(139,151,173,0.25)",
                      hovertemplate="%{source.label} → %{target.label}: %{value:,.0f} bytes<extra></extra>")))
        fig.update_layout(title=f"Source subnet → protocol/port → destination (largest {insights.SANKEY_PATHS} paths "
                                "by bytes)")
        st.plotly_chart(apply_chart_theme(fig, height=520), theme=None, key="insights_sankey")
