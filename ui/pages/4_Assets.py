import pandas as pd
import streamlit as st

from ui.api_client import get

st.title("Assets")

# ---------------------------------------------------------------------------
# Load targets for the selector
# ---------------------------------------------------------------------------
try:
    targets = get("/targets")
except Exception as exc:
    st.error(f"Failed to load targets: {exc}")
    st.stop()

if not targets:
    st.warning("No targets found. Create a target first.")
    st.stop()

target_options = {t["name"]: t["id"] for t in targets}
selected_target_name = st.selectbox("Target", options=list(target_options.keys()))
target_id = target_options[selected_target_name]

# ===========================================================================
# Section 1: Asset Overview Dashboard
# ===========================================================================
st.subheader("Overview")

try:
    stats = get("/assets/stats", params={"target_id": target_id})
    total_col, alive_col, dead_col, unprobed_col, new_col = st.columns(5)
    total_col.metric("Total", stats.get("total", 0))
    alive_col.metric("Alive", stats.get("alive", 0))
    dead_col.metric("Dead", stats.get("dead", 0))
    unprobed_col.metric("Unprobed", stats.get("unprobed", 0))
    new_col.metric("New", stats.get("new", 0))

    by_type = stats.get("by_type", {})
    if by_type:
        st.markdown("**Asset type breakdown**")
        type_cols = st.columns(len(by_type))
        for col, (atype, count) in zip(type_cols, by_type.items()):
            col.metric(atype.capitalize(), count)
except Exception as exc:
    st.error(f"Failed to load asset stats: {exc}")

# ===========================================================================
# Section 2: Asset Table
# ===========================================================================
st.subheader("Asset Table")

filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)

with filter_col1:
    type_filter = st.selectbox("Asset type", ["all", "subdomain", "ip", "cidr"])
with filter_col2:
    alive_filter = st.selectbox("Alive status", ["all", "alive", "dead", "unprobed"])
with filter_col3:
    new_only = st.checkbox("New only")
with filter_col4:
    search_value = st.text_input("Search", placeholder="e.g. example.com")

params: dict = {"target_id": target_id}
if type_filter != "all":
    params["asset_type"] = type_filter
if alive_filter == "alive":
    params["is_alive"] = "true"
elif alive_filter == "dead":
    params["is_alive"] = "false"
# "unprobed" → fetch all then filter client-side
if new_only:
    params["is_new"] = "true"
if search_value:
    params["search"] = search_value

try:
    assets = get("/assets", params=params)
except Exception as exc:
    st.error(f"Failed to load assets: {exc}")
    assets = []

# Client-side filter for unprobed (is_alive IS NULL)
if alive_filter == "unprobed":
    assets = [a for a in assets if a.get("is_alive") is None]

if not assets:
    st.info("No assets found for the selected filters.")
else:
    def _alive_icon(val):
        if val is True:
            return "✅"
        if val is False:
            return "❌"
        return "❓"

    rows = []
    for a in assets:
        tech = a.get("tech") or []
        rows.append({
            "ID": a["id"],
            "Value": a["value"],
            "Type": a["asset_type"],
            "Alive": _alive_icon(a.get("is_alive")),
            "Status Code": a.get("status_code"),
            "Title": a.get("title") or "",
            "Tech": ", ".join(tech) if tech else "",
            "First Seen": a.get("first_seen_at", ""),
            "Last Seen": a.get("last_seen_at", ""),
            "New": "🆕" if a.get("is_new") else "",
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    asset_ids = [a["id"] for a in assets]

    # ===========================================================================
    # Section 3: Asset Detail
    # ===========================================================================
    st.subheader("Asset Detail")

    selected_id = st.selectbox("Select asset ID", options=asset_ids)

    if st.button("Load Detail"):
        try:
            detail = get(f"/assets/{selected_id}")
        except Exception as exc:
            st.error(f"Failed to load asset detail: {exc}")
            detail = None

        if detail:
            left_col, right_col = st.columns(2)
            with left_col:
                st.markdown(f"**Value:** {detail['value']}")
                st.markdown(f"**Type:** {detail['asset_type']}")
                st.markdown(f"**Alive:** {_alive_icon(detail.get('is_alive'))}")
                st.markdown(f"**Status Code:** {detail.get('status_code') or '—'}")
                st.markdown(f"**Title:** {detail.get('title') or '—'}")
                st.markdown(f"**Web Server:** {detail.get('web_server') or '—'}")
            with right_col:
                st.markdown(f"**CDN:** {detail.get('cdn') or '—'}")
                st.markdown(f"**Content Length:** {detail.get('content_length') or '—'}")
                st.markdown(f"**First Seen:** {detail.get('first_seen_at') or '—'}")
                st.markdown(f"**Last Seen:** {detail.get('last_seen_at') or '—'}")
                st.markdown(f"**New:** {'🆕 Yes' if detail.get('is_new') else 'No'}")
                st.markdown(f"**Notes:** {detail.get('notes') or '—'}")

            # Resolved IPs
            resolved_ips = detail.get("resolved_ips") or []
            st.markdown("**Resolved IPs**")
            if resolved_ips:
                for ip in resolved_ips:
                    st.write(f"- {ip}")
            else:
                st.write("—")

            # Technologies
            tech = detail.get("tech") or []
            st.markdown("**Technologies**")
            if tech:
                st.write(" ".join(f"`{t}`" for t in tech))
            else:
                st.write("—")

            # Open ports
            ports = detail.get("ports") or []
            st.markdown("**Open Ports**")
            if ports:
                ports_df = pd.DataFrame(
                    [
                        {
                            "Port": p.get("port"),
                            "Protocol": p.get("protocol", ""),
                            "Service": p.get("service", ""),
                            "Version": p.get("version", ""),
                        }
                        for p in ports
                    ]
                )
                st.dataframe(ports_df, use_container_width=True, hide_index=True)
            else:
                st.write("—")

            # Endpoints for this asset
            st.markdown("**Endpoints**")
            try:
                endpoints = get(f"/assets/{selected_id}/endpoints")
            except Exception as exc:
                st.error(f"Failed to load endpoints: {exc}")
                endpoints = []

            if endpoints:
                ep_df = pd.DataFrame(
                    [
                        {
                            "ID": e["id"],
                            "URL": e["url"],
                            "Method": e["method"],
                            "Status Code": e.get("status_code"),
                            "Source": e.get("source", ""),
                            "Interesting": "⭐" if e.get("is_interesting") else "",
                            "New": "🆕" if e.get("is_new") else "",
                        }
                        for e in endpoints
                    ]
                )
                st.dataframe(ep_df, use_container_width=True, hide_index=True)
            else:
                st.info("No endpoints found for this asset.")
