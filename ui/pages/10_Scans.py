import json

import streamlit as st

from ui.api_client import get, post


def _parse_tags(text: str) -> list[str]:
    """Parse a comma-separated tags string into a list of non-empty stripped tags."""
    return [t.strip() for t in text.split(",") if t.strip()]

st.title("Scans")
st.caption("⚠️ Scanner results require manual verification before submission as findings.")

# ── Load targets ──────────────────────────────────────────────────────────────
try:
    targets = get("/targets")
except Exception as exc:
    st.error(f"Failed to load targets: {exc}")
    st.stop()

if not targets:
    st.warning("No targets found. Create a target first.")
    st.stop()

target_options = {f"[{t['id']}] {t['name']}": t["id"] for t in targets}

tab_scan, tab_results = st.tabs(["Scan", "Scan Results"])

# ── Tab 1: Scan ───────────────────────────────────────────────────────────────
with tab_scan:
    st.subheader("Launch a Scan")

    selected_label = st.selectbox("Target", options=list(target_options.keys()), key="scan_target")
    target_id = target_options[selected_label]

    # Show asset / endpoint counts for the chosen target
    col_assets, col_endpoints = st.columns(2)
    with col_assets:
        try:
            asset_stats = get("/assets/stats", params={"target_id": target_id})
            st.metric("Assets", asset_stats.get("total", 0))
        except Exception:
            st.metric("Assets", "—")
    with col_endpoints:
        try:
            ep_stats = get("/endpoints/stats", params={"target_id": target_id})
            st.metric("Endpoints", ep_stats.get("total", 0))
        except Exception:
            st.metric("Endpoints", "—")

    # Advanced options
    with st.expander("Advanced options", expanded=False):
        concurrency = st.number_input(
            "Concurrency", min_value=1, max_value=100, value=10,
            help="Number of parallel scan workers"
        )
        rate_limit = st.number_input(
            "Rate limit (req/s)", min_value=1, max_value=1000, value=150,
            help="Maximum requests per second"
        )
        timeout = st.number_input(
            "Timeout (s)", min_value=5, max_value=600, value=30,
            help="Per-request timeout in seconds"
        )
        tags_allow_text = st.text_input(
            "Tags allow-list (comma-separated)",
            help="Only run templates with these tags, e.g. cve,oast"
        )
        tags_deny_text = st.text_input(
            "Tags deny-list (comma-separated)",
            help="Skip templates with these tags, e.g. dos,fuzz"
        )

    if st.button("▶ Start Scan", type="primary"):
        tags_allow = _parse_tags(tags_allow_text)
        tags_deny = _parse_tags(tags_deny_text)
        config: dict = {
            "concurrency": concurrency,
            "rate_limit": rate_limit,
            "timeout": timeout,
        }
        if tags_allow:
            config["tags_allow"] = tags_allow
        if tags_deny:
            config["tags_deny"] = tags_deny

        try:
            result = post("/scans", {"target_id": target_id, "config": config})
            st.success(f"Scan #{result['id']} queued for target {selected_label}.")
        except Exception as exc:
            st.error(f"Failed to start scan: {exc}")

    # ── Scan list for target ──────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("Scans for this target")

    try:
        scans = get("/scans", params={"target_id": target_id})
    except Exception as exc:
        st.error(f"Failed to load scans: {exc}")
        scans = []

    if not scans:
        st.info("No scans found for this target.")
    else:
        _STATUS_ICONS = {
            "queued": "🕐",
            "running": "🔄",
            "succeeded": "✅",
            "failed": "❌",
        }
        for scan in scans:
            icon = _STATUS_ICONS.get(scan.get("status", ""), "❓")
            label = (
                f"{icon} Scan #{scan['id']} — {scan['status']} "
                f"({scan.get('scanner', '?')}) — "
                f"{str(scan.get('created_at', ''))[:19]}"
            )
            with st.expander(label, expanded=False):
                st.write(f"**Status:** {scan.get('status')}")
                if scan.get("progress") is not None:
                    st.progress(int(scan["progress"]) / 100)
                log = scan.get("log_text") or ""
                st.text_area("Logs", value=log, height=150, disabled=True,
                             key=f"log_{scan['id']}")

# ── Tab 2: Scan Results ───────────────────────────────────────────────────────
with tab_results:
    st.subheader("Scan Results")
    st.info("⚠️ These are raw scanner findings. Review carefully before promoting to a verified Finding.")

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        result_target_label = st.selectbox(
            "Target", options=list(target_options.keys()), key="result_target"
        )
        result_target_id = target_options[result_target_label]
    with col2:
        filter_severity = st.selectbox(
            "Severity",
            options=["all", "critical", "high", "medium", "low", "info", "informational"],
            key="result_severity",
        )
    with col3:
        filter_scan_id = st.number_input(
            "Scan ID (0 = all)", min_value=0, step=1, value=0, key="result_scan_id"
        )

    params: dict = {"target_id": result_target_id}
    if filter_severity != "all":
        params["severity"] = filter_severity
    if filter_scan_id > 0:
        params["scan_id"] = int(filter_scan_id)

    try:
        scan_results = get("/scan-results", params=params)
    except Exception as exc:
        st.error(f"Failed to load scan results: {exc}")
        scan_results = []

    if not scan_results:
        st.info("No scan results match the current filters.")
    else:
        _SEV_BADGES = {
            "critical": "🔴 critical",
            "high": "🟠 high",
            "medium": "🟡 medium",
            "low": "🔵 low",
            "info": "⚫ info",
            "informational": "⚫ info",
        }

        for sr in scan_results:
            sev = sr.get("severity", "")
            badge = _SEV_BADGES.get(sev.lower(), sev)
            header = (
                f"{badge} | **{sr.get('title', '—')}** "
                f"(#{sr['id']} — scan #{sr.get('scan_id')})"
            )
            with st.expander(header, expanded=False):
                st.write(f"**Tool:** {sr.get('tool', '—')}")
                st.write(f"**Template:** {sr.get('template_id') or '—'}")
                st.write(f"**URL:** {sr.get('matched_url') or '—'}")
                try:
                    tags = json.loads(sr.get("tags_json") or "[]")
                    st.write(f"**Tags:** {', '.join(tags) if tags else '—'}")
                except (json.JSONDecodeError, TypeError):
                    pass
                try:
                    evidence = json.loads(sr.get("evidence_json") or "{}")
                    if evidence:
                        st.json(evidence)
                except (json.JSONDecodeError, TypeError):
                    pass

                promote_key = f"promote_{sr['id']}"
                if st.button("📌 Promote to Finding", key=promote_key):
                    try:
                        resp = post(f"/scan-results/{sr['id']}/promote", {})
                        st.success(
                            f"Finding #{resp['finding_id']} created from scan result #{sr['id']}. "
                            "Open Findings to complete details."
                        )
                    except Exception as exc:
                        st.error(f"Failed to promote: {exc}")
