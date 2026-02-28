import streamlit as st

from ui.api_client import get

st.title("Endpoints")

_INTERESTING_PARAM_PATTERNS = {
    "redirect", "url", "uri", "path", "file", "filename", "next", "dest",
    "destination", "return", "returnurl", "callback", "token", "key", "id",
    "ref", "src", "source", "target", "page", "load", "fetch", "open",
    "host", "port", "to", "from", "link", "goto", "dir", "data",
}

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_SOURCES = ["httpx", "katana", "gau", "waybackurls", "burp", "zap", "manual"]

# Load targets for dropdowns used across tabs
try:
    _targets = get("/targets")
except Exception as _exc:
    st.error(f"Failed to load targets: {_exc}")
    st.stop()

if not _targets:
    st.warning("No targets found. Create a target first.")
    st.stop()

_target_options = {t["name"]: t["id"] for t in _targets}

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Stats",
    "📋 Endpoint Table",
    "⚠️ Interesting",
    "🔍 Parameter Analysis",
    "🔎 Endpoint Detail",
])

# ── Tab 1: Endpoint Stats ──────────────────────────────────────────────────
with tab1:
    st.subheader("Endpoint Stats")
    selected_target_name = st.selectbox(
        "Target", options=list(_target_options.keys()), key="stats_target"
    )
    target_id = _target_options[selected_target_name]

    try:
        stats = get("/endpoints/stats", params={"target_id": target_id})
    except Exception as exc:
        st.error(f"Failed to load stats: {exc}")
        stats = None

    if stats:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Endpoints", stats.get("total", 0))
        col2.metric("Interesting", stats.get("interesting", 0))
        col3.metric("New", stats.get("new", 0))

        st.metric("Unique Params", stats.get("unique_params", 0))

        st.markdown("**By Source**")
        by_source = stats.get("by_source", {})
        if by_source:
            st.dataframe(
                [{"Source": k, "Count": v} for k, v in by_source.items()],
                use_container_width=True,
            )
        else:
            st.info("No source data available.")

        st.markdown("**By Method**")
        by_method = stats.get("by_method", {})
        if by_method:
            st.dataframe(
                [{"Method": k, "Count": v} for k, v in by_method.items()],
                use_container_width=True,
            )
        else:
            st.info("No method data available.")
    elif stats is not None:
        st.info("No endpoint data for this target.")

# ── Tab 2: Endpoint Table with Filters ────────────────────────────────────
with tab2:
    st.subheader("Endpoint Table")
    selected_target_name2 = st.selectbox(
        "Target", options=list(_target_options.keys()), key="table_target"
    )
    target_id2 = _target_options[selected_target_name2]

    with st.expander("Filters", expanded=True):
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            f_source = st.selectbox("Source", options=["all"] + _SOURCES, key="f_source")
            f_method = st.selectbox("Method", options=["all"] + _METHODS, key="f_method")
            f_interesting = st.checkbox("Interesting only", key="f_interesting")
        with f_col2:
            f_path = st.text_input("Path contains", key="f_path")
            f_param = st.text_input("Param name contains", key="f_param")
            sc_col1, sc_col2 = st.columns(2)
            f_sc_min = sc_col1.number_input("Status min", min_value=0, max_value=599, value=0, step=1, key="f_sc_min")
            f_sc_max = sc_col2.number_input("Status max", min_value=0, max_value=599, value=0, step=1, key="f_sc_max")

    params: dict = {"target_id": target_id2}
    if f_source != "all":
        params["source"] = f_source
    if f_method != "all":
        params["method"] = f_method
    if f_interesting:
        params["is_interesting"] = True
    if f_path:
        params["path_contains"] = f_path
    if f_param:
        params["param_name_contains"] = f_param
    if f_sc_min > 0:
        params["status_code_min"] = int(f_sc_min)
    if f_sc_max > 0:
        params["status_code_max"] = int(f_sc_max)

    try:
        endpoints = get("/endpoints", params=params)
    except Exception as exc:
        st.error(f"Failed to load endpoints: {exc}")
        endpoints = []

    if endpoints:
        rows = []
        for ep in endpoints:
            rows.append({
                "⚠️": "⚠️" if ep.get("is_interesting") else "",
                "URL": ep.get("url", ""),
                "Method": ep.get("method", ""),
                "Status": ep.get("status_code", ""),
                "Source": ep.get("source", ""),
                "Interesting": ep.get("is_interesting", False),
                "Reason": ep.get("interesting_reason") or "",
                "First Seen": ep.get("first_seen_at", ""),
                "New": ep.get("is_new", False),
            })
        st.dataframe(rows, use_container_width=True)
        st.caption(f"{len(rows)} endpoint(s) found.")
    else:
        st.info("No endpoints match the current filters.")

# ── Tab 3: Interesting Endpoints ──────────────────────────────────────────
with tab3:
    st.subheader("Interesting Endpoints")
    selected_target_name3 = st.selectbox(
        "Target", options=list(_target_options.keys()), key="interesting_target"
    )
    target_id3 = _target_options[selected_target_name3]

    try:
        interesting = get("/endpoints/interesting", params={"target_id": target_id3})
    except Exception as exc:
        st.error(f"Failed to load interesting endpoints: {exc}")
        interesting = []

    if interesting:
        rows3 = []
        for ep in interesting:
            reason = ep.get("interesting_reason") or ""
            method = ep.get("method", "GET")
            url = ep.get("url", "")

            if "redirect" in reason.lower() or "open" in reason.lower():
                action = "Test for open redirect / SSRF"
            elif "upload" in reason.lower() or "file" in reason.lower():
                action = "Test for file upload / path traversal"
            elif "admin" in url.lower() or "manage" in url.lower():
                action = "Test for broken access control"
            elif method in ("POST", "PUT", "PATCH", "DELETE"):
                action = "Test for CSRF / improper authorization"
            else:
                action = "Review manually"

            rows3.append({
                "URL": url,
                "Method": method,
                "Reason": reason,
                "Suggested Action": action,
            })

        st.dataframe(rows3, use_container_width=True)
        st.caption(f"{len(rows3)} interesting endpoint(s).")
    else:
        st.info("No interesting endpoints found for this target.")

# ── Tab 4: Parameter Analysis ─────────────────────────────────────────────
with tab4:
    st.subheader("⚠️ Parameter Analysis")
    st.markdown(
        "Parameters matching known sensitive patterns are flagged with ⚠️. "
        "These are high-value targets for injection, SSRF, and open-redirect testing."
    )
    selected_target_name4 = st.selectbox(
        "Target", options=list(_target_options.keys()), key="params_target"
    )
    target_id4 = _target_options[selected_target_name4]

    try:
        param_data = get("/endpoints/params", params={"target_id": target_id4})
    except Exception as exc:
        st.error(f"Failed to load parameter data: {exc}")
        param_data = []

    if param_data:
        rows4 = []
        for item in param_data:
            name = item.get("name", "")
            flag = "⚠️" if name.lower() in _INTERESTING_PARAM_PATTERNS else ""
            rows4.append({
                "⚠️": flag,
                "Name": name,
                "Count": item.get("count", 0),
                "Types": ", ".join(item.get("types", [])),
            })
        st.dataframe(rows4, use_container_width=True)
        flagged = sum(1 for r in rows4 if r["⚠️"])
        st.caption(f"{len(rows4)} unique parameter(s) — {flagged} flagged as potentially interesting.")
    else:
        st.info("No parameter data found for this target.")

# ── Tab 5: Endpoint Detail ─────────────────────────────────────────────────
with tab5:
    st.subheader("Endpoint Detail")
    endpoint_id = st.number_input("Endpoint ID", min_value=1, step=1, key="detail_id")
    if st.button("Load Detail"):
        try:
            ep_detail = get(f"/endpoints/{int(endpoint_id)}")
        except Exception as exc:
            st.error(f"Failed to load endpoint: {exc}")
            ep_detail = None

        if ep_detail:
            st.markdown(f"**URL:** {ep_detail.get('url', '')}")
            st.markdown(f"**Method:** {ep_detail.get('method', '')}")
            st.markdown(f"**Status Code:** {ep_detail.get('status_code', 'N/A')}")
            st.markdown(f"**Content Type:** {ep_detail.get('content_type', 'N/A')}")
            st.markdown(f"**Source:** {ep_detail.get('source', '')}")
            st.markdown(f"**Interesting:** {'Yes ⚠️' if ep_detail.get('is_interesting') else 'No'}")
            if ep_detail.get("interesting_reason"):
                st.markdown(f"**Reason:** {ep_detail['interesting_reason']}")

            params5 = ep_detail.get("params") or []
            st.markdown("**Parameters:**")
            if params5:
                st.dataframe(params5, use_container_width=True)
            else:
                st.info("No parameters recorded.")

            tags = ep_detail.get("tags") or []
            if tags:
                st.markdown(f"**Tags:** {', '.join(tags)}")

            if ep_detail.get("notes"):
                st.markdown(f"**Notes:** {ep_detail['notes']}")

            req_headers = ep_detail.get("request_headers")
            resp_headers = ep_detail.get("response_headers")
            if req_headers or resp_headers:
                hcol1, hcol2 = st.columns(2)
                if req_headers:
                    with hcol1:
                        st.markdown("**Request Headers:**")
                        st.dataframe(
                            [{"Header": k, "Value": v} for k, v in req_headers.items()],
                            use_container_width=True,
                        )
                if resp_headers:
                    with hcol2:
                        st.markdown("**Response Headers:**")
                        st.dataframe(
                            [{"Header": k, "Value": v} for k, v in resp_headers.items()],
                            use_container_width=True,
                        )

