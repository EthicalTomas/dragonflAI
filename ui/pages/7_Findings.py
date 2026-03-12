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
                    st.success(f"Finding '{result['title']}' created (ID: {result['id']}) as **draft**.")
                    st.info(
                        "⚠️ This finding is a **draft**. Before submitting to a bug bounty program:\n"
                        "1. Review all details in the *Finding Detail & Reports* tab.\n"
                        "2. Complete the human review (mark as reviewed).\n"
                        "3. Generate and export the report."
                    )
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
            options=["all", "draft", "needs_review", "ready_to_submit", "submitted", "accepted", "duplicate"],
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
            reviewed = f.get("reviewed_by_human", False)
            rows.append(
                {
                    "ID": f.get("id"),
                    "Title": f.get("title"),
                    "Type": f.get("vulnerability_type"),
                    "Severity": badge,
                    "Status": f.get("status"),
                    "Reviewed": "✅ Yes" if reviewed else "❌ No",
                    "URL": f.get("url") or "",
                    "Created": f.get("created_at", "")[:19] if f.get("created_at") else "",
                }
            )
        st.dataframe(rows, use_container_width=True)

        unreviewed_count = sum(1 for f in findings if not f.get("reviewed_by_human", False))
        if unreviewed_count:
            st.warning(
                f"⚠️ **{unreviewed_count} finding(s) have not been human-reviewed.** "
                "Export and submission are blocked until review is complete."
            )

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
        reviewed = finding.get("reviewed_by_human", False)

        if not reviewed:
            st.error(
                "🚫 **Human review required.** This finding has not been reviewed. "
                "Export and submission are **disabled** until you complete the review below."
            )
        else:
            st.success(
                f"✅ **Human-reviewed** by *{finding.get('reviewer') or 'unknown'}* "
                f"on {str(finding.get('reviewed_at', ''))[:19]}."
            )

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

        # ── Human Review Section ──────────────────────────────────────────────
        st.markdown("---")
        st.subheader("Human Review")

        if not reviewed:
            st.warning(
                "⚠️ **Before marking as reviewed, confirm all of the following:**\n"
                "- The finding is within the program's defined scope.\n"
                "- Impact and reproduction steps are accurate and complete.\n"
                "- Rate-limit and responsible-disclosure rules have been followed.\n"
                "- No sensitive data (credentials, PII) is stored in the report."
            )

            with st.form("review_form"):
                reviewer_name = st.text_input(
                    "Reviewer name *",
                    help="Enter your name or handle to record in the audit log.",
                )
                review_notes_input = st.text_area(
                    "Review notes (optional)",
                    help="Any notes about the review, edge cases, or caveats.",
                )
                confirmed = st.checkbox(
                    "✅ I have reviewed this finding and confirmed it complies with program rules."
                )
                review_submitted = st.form_submit_button("Mark as Reviewed")

            if review_submitted:
                if not reviewer_name.strip():
                    st.error("Reviewer name is required.")
                elif not confirmed:
                    st.error("You must confirm the compliance checkbox before marking as reviewed.")
                else:
                    try:
                        fid = finding["id"]
                        updated = post(
                            f"/findings/{fid}/review",
                            {
                                "reviewer": reviewer_name.strip(),
                                "review_notes": review_notes_input or None,
                            },
                        )
                        st.session_state["loaded_finding"] = updated
                        st.success(
                            f"Finding #{fid} marked as reviewed by '{reviewer_name.strip()}'. "
                            "Export is now enabled."
                        )
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to record review: {exc}")
        else:
            st.write(f"**Reviewer:** {finding.get('reviewer') or '—'}")
            st.write(f"**Reviewed at:** {str(finding.get('reviewed_at', ''))[:19] or '—'}")
            st.write(f"**Review notes:** {finding.get('review_notes') or '—'}")

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

        if not reviewed:
            st.error(
                "🚫 Export is disabled. Complete the human review above before exporting."
            )
        else:
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

    st.warning(
        "⚠️ Only **human-reviewed** findings can be included in a batch report. "
        "Unreviewed findings are highlighted below — complete their review first."
    )

    try:
        all_findings = get("/findings")
    except Exception as exc:
        st.error(f"Failed to load findings: {exc}")
        all_findings = []

    if not all_findings:
        st.info("No findings available.")
    else:
        reviewed_findings = [f for f in all_findings if f.get("reviewed_by_human")]
        unreviewed_findings = [f for f in all_findings if not f.get("reviewed_by_human")]

        if unreviewed_findings:
            st.info(
                f"**{len(unreviewed_findings)} finding(s) are not yet reviewed** and cannot be "
                "included in a batch report: "
                + ", ".join(f"#{f['id']}" for f in unreviewed_findings)
            )

        if not reviewed_findings:
            st.warning("No reviewed findings available. Review findings before generating a batch report.")
        else:
            finding_options = {
                f"[{f['id']}] {f['title']} ({f['severity']})": f["id"]
                for f in reviewed_findings
            }
            selected_labels = st.multiselect(
                "Select Reviewed Findings", options=list(finding_options.keys())
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
