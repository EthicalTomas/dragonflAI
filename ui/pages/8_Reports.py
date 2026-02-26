import streamlit as st

from ui.api_client import get, post

st.title("Reports")

tab1, tab2, tab3 = st.tabs(["Single Report Viewer", "Batch Report Dashboard", "Report History"])

with tab1:
    st.subheader("Single Report Viewer")
    finding_id = st.number_input("Finding ID", min_value=1, step=1, value=1, key="single_finding_id")
    if st.button("Load Report"):
        try:
            finding = get(f"/findings/{int(finding_id)}")
            report = finding.get("report_markdown")
            if report:
                st.markdown(report)
                if st.toggle("View Raw Markdown"):
                    st.code(report, language="markdown")
                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        label="Download Markdown (.md)",
                        data=report.encode("utf-8"),
                        file_name=f"finding_{int(finding_id)}_report.md",
                        mime="text/markdown",
                    )
                with col2:
                    st.download_button(
                        label="Download Plain Text (.txt)",
                        data=report.encode("utf-8"),
                        file_name=f"finding_{int(finding_id)}_report.txt",
                        mime="text/plain",
                    )
            else:
                st.warning("No report generated yet. Go to the Findings page to generate one.")
        except Exception as exc:
            st.error(f"Failed to load finding: {exc}")

with tab2:
    st.subheader("Batch Report Dashboard")
    try:
        findings = get("/findings")

        st.markdown("### Findings by Severity")
        severities = ["critical", "high", "medium", "low", "informational"]
        severity_counts = {s: 0 for s in severities}
        for f in findings:
            sev = f.get("severity", "informational").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sev_cols = st.columns(len(severities))
        for col, sev in zip(sev_cols, severities):
            with col:
                st.metric(label=sev.capitalize(), value=severity_counts.get(sev, 0))

        st.markdown("### Findings by Status")
        status_counts: dict[str, int] = {}
        for f in findings:
            status = f.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        if status_counts:
            status_cols = st.columns(len(status_counts))
            for col, (status, count) in zip(status_cols, status_counts.items()):
                with col:
                    st.metric(label=status.capitalize(), value=count)

        if findings:
            if st.button("Generate Full Assessment Report"):
                finding_ids = [f["id"] for f in findings]
                try:
                    result = post(
                        "/findings/batch-report",
                        {"finding_ids": finding_ids, "template": "summary"},
                    )
                    batch_report = result.get("report_markdown", "")
                    if batch_report:
                        st.markdown(batch_report)
                        st.download_button(
                            label="Download Full Report (.md)",
                            data=batch_report.encode("utf-8"),
                            file_name="full_assessment_report.md",
                            mime="text/markdown",
                        )
                except Exception as exc:
                    st.error(f"Failed to generate batch report: {exc}")
        else:
            st.info("No findings available to generate a report.")
    except Exception as exc:
        st.error(f"Failed to load findings: {exc}")

with tab3:
    st.subheader("Report History")
    try:
        findings = get("/findings")
        findings_with_reports = []
        for f in findings:
            try:
                detail = get(f"/findings/{f['id']}")
                if detail.get("report_markdown"):
                    findings_with_reports.append(
                        {
                            "ID": detail["id"],
                            "Title": detail["title"],
                            "Severity": detail["severity"],
                            "Template used": "N/A",
                            "Generated date": detail.get("updated_at") or detail.get("created_at", ""),
                        }
                    )
            except Exception:
                continue

        if findings_with_reports:
            st.dataframe(findings_with_reports, use_container_width=True)
            st.markdown("---")
            selected_id = st.number_input(
                "Enter Finding ID to view its report",
                min_value=1,
                step=1,
                value=findings_with_reports[0]["ID"],
                key="history_finding_id",
            )
            if st.button("View Report", key="view_history_report"):
                try:
                    detail = get(f"/findings/{int(selected_id)}")
                    report = detail.get("report_markdown")
                    if report:
                        st.markdown(report)
                    else:
                        st.warning("No report available for this finding.")
                except Exception as exc:
                    st.error(f"Failed to load report: {exc}")
        else:
            st.info("No reports found. Generate reports from the Findings page.")
    except Exception as exc:
        st.error(f"Failed to load report history: {exc}")
