import streamlit as st

from ui.api_client import get, post

st.title("Detection")

_CONFIDENCE_EMOJI = {
    "high": "⚠️",
    "medium": "ℹ️",
    "low": "❔",
}


def _signals_to_rows(signals: list) -> list:
    rows = []
    for sig in signals:
        conf = sig.get("confidence", "")
        emoji = _CONFIDENCE_EMOJI.get(conf, "")
        rows.append(
            {
                "Type": sig.get("type", ""),
                "Vuln Type": sig.get("vuln_type", ""),
                "Detail": sig.get("detail", ""),
                "Severity Hint": sig.get("severity_hint", ""),
                "Confidence": f"{emoji} {conf}",
                "Endpoint/Asset ID": sig.get("endpoint_id") or sig.get("asset_id") or "",
            }
        )
    return rows

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "Run Detection",
        "High-Confidence Signals",
        "All Signals",
        "Auto-Generate Findings",
        "Single Item Analysis",
    ]
)

# ── Section 1: Run Detection ─────────────────────────────────────────────────
with tab1:
    st.subheader("Run Detection")

    try:
        targets = get("/targets")
    except Exception as exc:
        st.error(f"Failed to load targets: {exc}")
        targets = []

    if not targets:
        st.warning("No targets found. Create a target first.")
    else:
        target_options = {f"[{t['id']}] {t['name']}": t["id"] for t in targets}
        selected_target_label = st.selectbox(
            "Target", options=list(target_options.keys()), key="det_target"
        )
        selected_target_id = target_options[selected_target_label]

        # Optional run selector filtered to succeeded runs for selected target
        try:
            all_runs = get("/runs")
            succeeded_runs = [
                r
                for r in all_runs
                if r.get("target_id") == selected_target_id and r.get("status") == "succeeded"
            ]
        except Exception as exc:
            st.warning(f"Could not load runs: {exc}")
            succeeded_runs = []

        run_options = {"(All data — no specific run)": None}
        for r in succeeded_runs:
            label = f"Run #{r['id']} ({r.get('finished_at', '')[:19] if r.get('finished_at') else 'n/a'})"
            run_options[label] = r["id"]

        selected_run_label = st.selectbox(
            "Run (optional)", options=list(run_options.keys()), key="det_run"
        )
        selected_run_id = run_options[selected_run_label]

        if st.button("Run Detection"):
            payload: dict = {"target_id": selected_target_id, "run_id": selected_run_id}
            try:
                report = post("/detection/run", payload)
                st.session_state["detection_report"] = report
            except Exception as exc:
                st.error(f"Detection failed: {exc}")

        report = st.session_state.get("detection_report")
        if report:
            st.markdown("---")
            st.markdown("### Detection Report")

            total = report.get("total_signals", 0)
            st.metric("Total Signals", total)

            by_conf = report.get("signals_by_confidence", {})
            c_high, c_med, c_low = st.columns(3)
            with c_high:
                st.metric("⚠️ High", by_conf.get("high", 0))
            with c_med:
                st.metric("ℹ️ Medium", by_conf.get("medium", 0))
            with c_low:
                st.metric("❔ Low", by_conf.get("low", 0))

            by_vuln = report.get("signals_by_vuln_type", {})
            if by_vuln:
                st.markdown("#### Signals by Vulnerability Type")
                vuln_rows = [{"Vuln Type": k, "Count": v} for k, v in by_vuln.items()]
                st.bar_chart({row["Vuln Type"]: row["Count"] for row in vuln_rows})

            ep_flagged = report.get("endpoints_flagged", 0)
            asset_flagged = report.get("assets_flagged", 0)
            ef_col, af_col = st.columns(2)
            with ef_col:
                st.metric("Endpoints Flagged", ep_flagged)
            with af_col:
                st.metric("Assets Flagged", asset_flagged)

# ── Section 2: High-Confidence Signals ──────────────────────────────────────
with tab2:
    st.subheader("High-Confidence Signals")

    report = st.session_state.get("detection_report")
    if not report:
        st.info("Run Detection first (in the 'Run Detection' tab) to see signals here.")
    else:
        high_signals = report.get("high_confidence_signals", [])
        if not high_signals:
            st.info(
                "No signals detected — this could mean the target is well-secured or more recon data is needed."
            )
        else:
            st.dataframe(_signals_to_rows(high_signals), use_container_width=True)

# ── Section 3: All Signals ───────────────────────────────────────────────────
with tab3:
    st.subheader("All Signals")

    report = st.session_state.get("detection_report")
    if not report:
        st.info("Run Detection first (in the 'Run Detection' tab) to see signals here.")
    else:
        all_signals = report.get("all_signals", [])
        if not all_signals:
            st.info(
                "No signals detected — this could mean the target is well-secured or more recon data is needed."
            )
        else:
            vuln_types = sorted({s.get("vuln_type", "") for s in all_signals})
            confidences = ["all", "high", "medium", "low"]

            f_col1, f_col2 = st.columns(2)
            with f_col1:
                filter_vuln = st.selectbox(
                    "Filter by Vuln Type",
                    options=["all"] + vuln_types,
                    key="all_sig_vuln",
                )
            with f_col2:
                filter_conf = st.selectbox(
                    "Filter by Confidence",
                    options=confidences,
                    key="all_sig_conf",
                )

            filtered = all_signals
            if filter_vuln != "all":
                filtered = [s for s in filtered if s.get("vuln_type") == filter_vuln]
            if filter_conf != "all":
                filtered = [s for s in filtered if s.get("confidence") == filter_conf]

            _conf_order = {"high": 0, "medium": 1, "low": 2}
            _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            filtered = sorted(
                filtered,
                key=lambda s: (
                    _conf_order.get(s.get("confidence", ""), 99),
                    _sev_order.get(s.get("severity_hint", ""), 99),
                ),
            )

            with st.expander(f"All Signals ({len(filtered)} shown)", expanded=False):
                st.dataframe(_signals_to_rows(filtered), use_container_width=True)

# ── Section 4: Auto-Generate Findings ───────────────────────────────────────
with tab4:
    st.subheader("Auto-Generate Draft Findings")

    st.warning(
        "⚠️ Auto-generated findings are DRAFTS. You MUST review and verify each one "
        "before submitting to a bug bounty program."
    )

    try:
        targets_af = get("/targets")
    except Exception as exc:
        st.error(f"Failed to load targets: {exc}")
        targets_af = []

    if not targets_af:
        st.warning("No targets found. Create a target first.")
    else:
        target_options_af = {f"[{t['id']}] {t['name']}": t["id"] for t in targets_af}
        selected_target_af_label = st.selectbox(
            "Target",
            options=list(target_options_af.keys()),
            key="af_target",
        )
        selected_target_af_id = target_options_af[selected_target_af_label]

        min_confidence = st.selectbox(
            "Minimum Confidence",
            options=["high", "medium", "low"],
            key="af_min_conf",
        )

        if st.button("Auto-Generate Draft Findings"):
            try:
                result = post(
                    "/detection/auto-findings",
                    {"target_id": selected_target_af_id, "min_confidence": min_confidence},
                )
                findings_created = result.get("findings_created", 0)
                finding_ids = result.get("finding_ids", [])
                st.success(f"Created {findings_created} draft finding(s).")
                if finding_ids:
                    st.markdown("**Finding IDs created:**")
                    for fid in finding_ids:
                        st.markdown(f"- [Finding #{fid}](/Findings?finding_id={fid})")
            except Exception as exc:
                st.error(f"Failed to auto-generate findings: {exc}")

# ── Section 5: Single Item Analysis ─────────────────────────────────────────
with tab5:
    st.subheader("Single Item Analysis")

    analyze_tab1, analyze_tab2 = st.tabs(["Analyze Endpoint", "Analyze Asset"])

    with analyze_tab1:
        st.markdown("#### Analyze Endpoint")
        endpoint_id = st.number_input(
            "Endpoint ID", min_value=1, step=1, key="analyze_endpoint_id"
        )
        if st.button("Analyze", key="analyze_endpoint_btn"):
            try:
                result = post(f"/detection/analyze-endpoint/{int(endpoint_id)}", {})
                signals = result.get("signals", result if isinstance(result, list) else [])
                if not signals:
                    st.info(
                        "No signals detected — this could mean the target is well-secured or more recon data is needed."
                    )
                else:
                    st.dataframe(_signals_to_rows(signals), use_container_width=True)
            except Exception as exc:
                st.error(f"Failed to analyze endpoint: {exc}")

    with analyze_tab2:
        st.markdown("#### Analyze Asset")
        asset_id = st.number_input(
            "Asset ID", min_value=1, step=1, key="analyze_asset_id"
        )
        if st.button("Analyze", key="analyze_asset_btn"):
            try:
                result = post(f"/detection/analyze-asset/{int(asset_id)}", {})
                signals = result.get("signals", result if isinstance(result, list) else [])
                if not signals:
                    st.info(
                        "No signals detected — this could mean the target is well-secured or more recon data is needed."
                    )
                else:
                    st.dataframe(_signals_to_rows(signals), use_container_width=True)
            except Exception as exc:
                st.error(f"Failed to analyze asset: {exc}")
