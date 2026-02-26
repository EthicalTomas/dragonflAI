import os

import httpx
import streamlit as st

from ui.api_client import get, post

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
_TIMEOUT = 30.0

st.title("Findings")

_VULN_TYPES = [
    "XSS",
    "SSRF",
    "IDOR",
    "Open Redirect",
    "SQL Injection",
    "CSRF",
    "RCE",
    "Information Disclosure",
    "Broken Authentication",
    "Insecure Deserialization",
    "Other",
]

_SEVERITIES = ["critical", "high", "medium", "low", "informational"]

_SEVERITY_BADGES = {
    "critical": "🔴 critical",
    "high": "🟠 high",
    "medium": "🟡 medium",
    "low": "🔵 low",
    "informational": "⚫ info",
}

tab1, tab2, tab3, tab4 = st.tabs(
    ["Create Finding", "List Findings", "Finding Detail & Reports", "Batch Report"]
)

# ── Section 1: Create Finding ────────────────────────────────────────────────
with tab1:
    st.subheader("Create Finding")

    try:
        targets = get("/targets")
    except Exception as exc:
        st.error(f"Failed to load targets: {exc}")
        targets = []

    if not targets:
        st.warning("No targets found. Create a target first.")
    else:
        target_options = {f"[{t['id']}] {t['name']}": t["id"] for t in targets}

        with st.form("create_finding_form"):
            selected_target = st.selectbox("Target *", options=list(target_options.keys()))
            title = st.text_input("Title *")
            vuln_type = st.selectbox("Vulnerability Type *", options=_VULN_TYPES)
            severity = st.selectbox("Severity *", options=_SEVERITIES, index=2)
            url = st.text_input("URL")
            parameter = st.text_input("Parameter")
            description = st.text_area("Description *")
            steps_to_reproduce = st.text_area(
                "Steps to Reproduce *", help="Use numbered steps"
            )
            impact = st.text_area("Impact *")
            remediation = st.text_area("Remediation")
            request_response = st.text_area(
                "Request/Response", help="Paste raw HTTP request and response"
            )
            cvss_vector = st.text_input(
                "CVSS Vector",
                help="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            )
            references_text = st.text_area("References", help="One URL per line")
            evidence_text = st.text_area(
                "Evidence Paths", help="One file path per line"
            )
            notes = st.text_area(
                "Notes", help="Internal notes, not included in reports"
            )
            submitted = st.form_submit_button("Create Finding")

        if submitted:
            errors = []
            if not title:
                errors.append("Title is required.")
            if not description:
                errors.append("Description is required.")
            if not steps_to_reproduce:
                errors.append("Steps to reproduce is required.")
            if not impact:
                errors.append("Impact is required.")

            if errors:
                for err in errors:
                    st.error(err)
            else:
                references = [r.strip() for r in references_text.splitlines() if r.strip()]
                evidence_paths = [e.strip() for e in evidence_text.splitlines() if e.strip()]
                payload = {
                    "target_id": target_options[selected_target],
                    "title": title,
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "url": url or None,
                    "parameter": parameter or None,
                    "description": description,
                    "steps_to_reproduce": steps_to_reproduce,
                    "impact": impact,
                    "remediation": remediation or None,
                    "request_response": request_response or None,
                    "cvss_vector": cvss_vector or None,
                    "references": references,
                    "evidence_paths": evidence_paths,
                    "notes": notes or None,
                }
                try:
                    result = post("/findings", payload)
                    st.success(f"Finding '{result['title']}' created (ID: {result['id']}).")
                except Exception as exc:
                    st.error(f"Failed to create finding: {exc}")

# ── Section 2: List Findings ─────────────────────────────────────────────────
with tab2:
    st.subheader("List Findings")

    col1, col2 = st.columns(2)
    with col1:
        filter_severity = st.selectbox(
            "Severity",
            options=["all", "critical", "high", "medium", "low", "informational"],
            key="list_severity",
        )
    with col2:
        filter_status = st.selectbox(
            "Status",
            options=["all", "draft", "ready", "submitted", "accepted", "duplicate"],
            key="list_status",
        )

    params: dict = {}
    if filter_severity != "all":
        params["severity"] = filter_severity
    if filter_status != "all":
        params["status"] = filter_status

    try:
        findings = get("/findings", params=params)
    except Exception as exc:
        st.error(f"Failed to load findings: {exc}")
        findings = []

    if not findings:
        st.info("No findings match the current filters.")
    else:
        rows = []
        for f in findings:
            sev = f.get("severity", "")
            badge = _SEVERITY_BADGES.get(sev, sev)
            rows.append(
                {
                    "ID": f.get("id"),
                    "Title": f.get("title"),
                    "Type": f.get("vulnerability_type"),
                    "Severity": badge,
                    "Status": f.get("status"),
                    "URL": f.get("url") or "",
                    "Created": f.get("created_at", "")[:19] if f.get("created_at") else "",
                }
            )
        st.dataframe(rows, use_container_width=True)

# ── Section 3: Finding Detail + Report Generation ────────────────────────────
with tab3:
    st.subheader("Finding Detail & Report Generation")

    finding_id_input = st.number_input(
        "Finding ID", min_value=1, step=1, key="detail_finding_id"
    )
    load_clicked = st.button("Load Finding")

    if load_clicked:
        try:
            finding = get(f"/findings/{int(finding_id_input)}")
            st.session_state["loaded_finding"] = finding
        except Exception as exc:
            st.error(f"Failed to load finding: {exc}")
            st.session_state.pop("loaded_finding", None)

    finding = st.session_state.get("loaded_finding")

    if finding:
        with st.expander("Finding Fields", expanded=True):
            st.write(f"**ID:** {finding.get('id')}")
            st.write(f"**Title:** {finding.get('title')}")
            st.write(f"**Type:** {finding.get('vulnerability_type')}")
            sev = finding.get("severity", "")
            st.write(f"**Severity:** {_SEVERITY_BADGES.get(sev, sev)}")
            st.write(f"**Status:** {finding.get('status')}")
            st.write(f"**URL:** {finding.get('url') or '—'}")
            st.write(f"**Parameter:** {finding.get('parameter') or '—'}")
            st.write(f"**Description:** {finding.get('description')}")
            st.write(f"**Steps to Reproduce:** {finding.get('steps_to_reproduce')}")
            st.write(f"**Impact:** {finding.get('impact')}")
            st.write(f"**Remediation:** {finding.get('remediation') or '—'}")
            st.write(f"**CVSS Score:** {finding.get('cvss_score') or '—'}")
            st.write(f"**CVSS Vector:** {finding.get('cvss_vector') or '—'}")
            refs = finding.get("references") or []
            st.write(f"**References:** {', '.join(refs) if refs else '—'}")
            evidence = finding.get("evidence_paths") or []
            st.write(f"**Evidence Paths:** {', '.join(evidence) if evidence else '—'}")
            st.write(f"**Notes:** {finding.get('notes') or '—'}")
            if finding.get("request_response"):
                st.text_area(
                    "Request/Response", value=finding["request_response"], disabled=True
                )

        st.markdown("---")
        st.subheader("Generate Report")
        col_full, col_platform, col_summary = st.columns(3)

        fid = finding["id"]

        with col_full:
            if st.button("Generate Full Report", key="gen_full"):
                try:
                    resp = post(f"/findings/{fid}/generate-report?template=full", {})
                    st.session_state["report_markdown"] = resp.get("report_markdown", "")
                except Exception as exc:
                    st.error(f"Failed to generate report: {exc}")

        with col_platform:
            if st.button("Generate Platform Report", key="gen_platform"):
                try:
                    resp = post(f"/findings/{fid}/generate-report?template=platform", {})
                    st.session_state["report_markdown"] = resp.get("report_markdown", "")
                except Exception as exc:
                    st.error(f"Failed to generate report: {exc}")

        with col_summary:
            if st.button("Generate Summary", key="gen_summary"):
                try:
                    resp = post(f"/findings/{fid}/generate-report?template=summary", {})
                    st.session_state["report_markdown"] = resp.get("report_markdown", "")
                except Exception as exc:
                    st.error(f"Failed to generate report: {exc}")

        report_md = st.session_state.get("report_markdown")
        if report_md:
            st.text_area("Report (raw Markdown)", value=report_md, height=300)
            st.markdown("---")
            st.markdown("**Rendered Report:**")
            st.markdown(report_md)

        st.markdown("---")
        st.subheader("Export Report")
        col_md, col_txt = st.columns(2)

        def _export_finding(fmt: str, ext: str, mime: str, btn_key: str, dl_key: str) -> None:
            if st.button(f"Export as {fmt.capitalize()}", key=btn_key):
                try:
                    with httpx.Client(timeout=_TIMEOUT) as client:
                        r = client.get(
                            f"{BACKEND_URL}/findings/{fid}/export",
                            params={"format": fmt},
                        )
                        r.raise_for_status()
                        content = r.content
                    st.download_button(
                        label=f"Download {fmt.capitalize()}",
                        data=content,
                        file_name=f"finding_{fid}.{ext}",
                        mime=mime,
                        key=dl_key,
                    )
                except Exception as exc:
                    st.error(f"Failed to export report: {exc}")

        with col_md:
            _export_finding("markdown", "md", "text/markdown", "export_md", "dl_md")

        with col_txt:
            _export_finding("txt", "txt", "text/plain", "export_txt", "dl_txt")

# ── Section 4: Batch Report ───────────────────────────────────────────────────
with tab4:
    st.subheader("Batch Report")

    try:
        all_findings = get("/findings")
    except Exception as exc:
        st.error(f"Failed to load findings: {exc}")
        all_findings = []

    if not all_findings:
        st.info("No findings available.")
    else:
        finding_options = {
            f"[{f['id']}] {f['title']} ({f['severity']})": f["id"]
            for f in all_findings
        }
        selected_labels = st.multiselect(
            "Select Findings", options=list(finding_options.keys())
        )
        batch_template = st.selectbox(
            "Template", options=["summary", "full", "platform"], key="batch_template"
        )

        if st.button("Generate Batch Report"):
            if not selected_labels:
                st.warning("Select at least one finding.")
            else:
                selected_ids = [finding_options[label] for label in selected_labels]
                try:
                    resp = post(
                        "/findings/batch-report",
                        {"finding_ids": selected_ids, "template": batch_template},
                    )
                    batch_md = resp.get("report_markdown", "")
                    st.text_area("Batch Report (raw Markdown)", value=batch_md, height=300)
                    st.markdown("---")
                    st.markdown("**Rendered Batch Report:**")
                    st.markdown(batch_md)
                except Exception as exc:
                    st.error(f"Failed to generate batch report: {exc}")
