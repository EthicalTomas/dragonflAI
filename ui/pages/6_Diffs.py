import pandas as pd
import streamlit as st

from ui.api_client import get

st.title("Diffs")

# ---------------------------------------------------------------------------
# Load targets for selectors
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


# ---------------------------------------------------------------------------
# Helper: render a color-highlighted findings table
# ---------------------------------------------------------------------------
def _findings_table(findings: list, color: str) -> None:
    rows = [
        {
            "ID": f.get("id"),
            "Title": f.get("title", ""),
            "Type": f.get("vulnerability_type", ""),
            "Severity": f.get("severity", ""),
            "Status": f.get("status", ""),
            "URL": f.get("url", ""),
            "Parameter": f.get("parameter", ""),
        }
        for f in findings
    ]
    df = pd.DataFrame(rows)
    st.dataframe(
        df.style.apply(
            lambda _: [f"background-color: {color}"] * len(df.columns), axis=1
        ),
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------------------------
# Helper: render a full diff report
# ---------------------------------------------------------------------------
def _display_diff_report(diff: dict) -> None:
    new_findings = diff.get("new_findings", [])
    resolved_findings = diff.get("resolved_findings", [])
    persisted_findings = diff.get("persisted_findings", [])

    run_a_id = diff.get("run_a_id", "?")
    run_b_id = diff.get("run_b_id", "?")

    st.markdown(f"**Comparing Run #{run_a_id} → Run #{run_b_id}**")

    # Highlights
    st.markdown("#### 📊 Highlights")
    st.markdown(f"- 🟢 **{len(new_findings)}** new finding(s)")
    st.markdown(f"- 🔴 **{len(resolved_findings)}** resolved finding(s)")
    st.markdown(f"- 🟡 **{len(persisted_findings)}** persisted finding(s)")

    # New findings — green
    st.markdown("#### 🟢 New Findings")
    if new_findings:
        _findings_table(new_findings, "#d4edda")
    else:
        st.info("No new findings.")

    # Resolved findings — red
    st.markdown("#### 🔴 Resolved Findings")
    if resolved_findings:
        _findings_table(resolved_findings, "#f8d7da")
    else:
        st.info("No resolved findings.")

    # Persisted findings — yellow
    st.markdown("#### 🟡 Persisted Findings")
    if persisted_findings:
        _findings_table(persisted_findings, "#fff3cd")
    else:
        st.info("No persisted findings.")


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["Latest Diff", "Compare Specific Runs", "Single Run Diff"])

# ===========================================================================
# Tab 1: Latest Diff
# ===========================================================================
with tab1:
    st.subheader("Latest Diff")

    target_name_1 = st.selectbox(
        "Target", options=list(target_options.keys()), key="tab1_target"
    )
    target_id_1 = target_options[target_name_1]

    if st.button("Show Latest Diff", key="tab1_btn"):
        try:
            result = get(f"/diffs/targets/{target_id_1}/latest")
            if result.get("diff") is None and "message" in result:
                st.info(result["message"])
            else:
                _display_diff_report(result)
        except Exception as exc:
            st.error(f"Failed to load latest diff: {exc}")

# ===========================================================================
# Tab 2: Compare Specific Runs
# ===========================================================================
with tab2:
    st.subheader("Compare Specific Runs")

    target_name_2 = st.selectbox(
        "Target", options=list(target_options.keys()), key="tab2_target"
    )
    target_id_2 = target_options[target_name_2]

    try:
        all_runs = get("/runs")
        succeeded_runs = [
            r
            for r in all_runs
            if r["target_id"] == target_id_2 and r["status"] == "succeeded"
        ]
    except Exception as exc:
        st.error(f"Failed to load runs: {exc}")
        succeeded_runs = []

    if not succeeded_runs:
        st.warning("No succeeded runs found for this target.")
    else:
        run_options = {
            f"Run #{r['id']} ({r['created_at']})": r["id"] for r in succeeded_runs
        }
        run_labels = list(run_options.keys())

        col1, col2 = st.columns(2)
        with col1:
            run_a_label = st.selectbox(
                "Run A (base)", options=run_labels, key="tab2_run_a"
            )
        with col2:
            run_b_label = st.selectbox(
                "Run B (compare)", options=run_labels, key="tab2_run_b"
            )

        if st.button("Compare", key="tab2_btn"):
            run_id_a = run_options[run_a_label]
            run_id_b = run_options[run_b_label]
            if run_id_a == run_id_b:
                st.warning("Please select two different runs to compare.")
            else:
                try:
                    result = get(f"/diffs/runs/{run_id_a}/compare/{run_id_b}")
                    _display_diff_report(result)
                except Exception as exc:
                    st.error(f"Failed to compare runs: {exc}")

# ===========================================================================
# Tab 3: Single Run Diff
# ===========================================================================
with tab3:
    st.subheader("Single Run Diff")

    target_name_3 = st.selectbox(
        "Target", options=list(target_options.keys()), key="tab3_target"
    )
    target_id_3 = target_options[target_name_3]

    try:
        all_runs_3 = get("/runs")
        target_runs_3 = [r for r in all_runs_3 if r["target_id"] == target_id_3]
    except Exception as exc:
        st.error(f"Failed to load runs: {exc}")
        target_runs_3 = []

    if not target_runs_3:
        st.warning("No runs found for this target.")
    else:
        run_options_3 = {
            f"Run #{r['id']} — {r['status']} ({r['created_at']})": r["id"]
            for r in target_runs_3
        }
        selected_run_label_3 = st.selectbox(
            "Run", options=list(run_options_3.keys()), key="tab3_run"
        )

        if st.button("Show Diff", key="tab3_btn"):
            run_id_3 = run_options_3[selected_run_label_3]
            try:
                result = get(f"/diffs/runs/{run_id_3}")
                if result.get("diff") is None and "message" in result:
                    st.info(result["message"])
                else:
                    _display_diff_report(result)
            except Exception as exc:
                st.error(f"Failed to load run diff: {exc}")
