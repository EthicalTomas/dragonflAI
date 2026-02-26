import datetime
import json
import logging
import os
import re

from backend.app.llm.base import LLMProvider
from backend.app.llm.null_provider import NullLLMProvider
from backend.app.models.finding import Finding
from backend.app.reports.templates import get_template

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self._llm = llm_provider if llm_provider is not None else NullLLMProvider()

    def generate_report(self, finding: Finding, template_name: str = "full") -> str:
        template = get_template(template_name)

        # Deserialize JSON list fields
        try:
            evidence_paths = json.loads(finding.evidence_paths_json or "[]")
        except (json.JSONDecodeError, TypeError):
            evidence_paths = []

        try:
            references = json.loads(finding.references_json or "[]")
        except (json.JSONDecodeError, TypeError):
            references = []

        if evidence_paths:
            evidence_list = "\n".join(f"- {path}" for path in evidence_paths)
        else:
            evidence_list = "No evidence files attached."

        if references:
            references_list = "\n".join(f"{i}. [{ref}]({ref})" for i, ref in enumerate(references, start=1))
        else:
            references_list = "No references provided."

        created_at = finding.created_at
        if isinstance(created_at, datetime.datetime):
            created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            created_at_str = str(created_at) if created_at is not None else ""

        cvss_score = finding.cvss_score
        cvss_score_str = str(cvss_score) if cvss_score is not None else "Not scored"

        context = {
            "title": finding.title,
            "severity": finding.severity,
            "vulnerability_type": finding.vulnerability_type,
            "status": finding.status,
            "url": finding.url if finding.url is not None else "N/A",
            "parameter": finding.parameter if finding.parameter is not None else "N/A",
            "method": "N/A",
            "description": finding.description,
            "steps_to_reproduce": finding.steps_to_reproduce,
            "impact": finding.impact,
            "remediation": finding.remediation if finding.remediation is not None else "No remediation suggestion provided.",
            "request_response": finding.request_response if finding.request_response is not None else "No request/response captured.",
            "cvss_score": cvss_score_str,
            "cvss_vector": finding.cvss_vector if finding.cvss_vector is not None else "",
            "created_at": created_at_str,
            "evidence_list": evidence_list,
            "references_list": references_list,
        }

        base_report = template.format(**context)

        if isinstance(self._llm, NullLLMProvider):
            return base_report

        prompt = (
            "You are a professional security report writer. Improve the following vulnerability report:\n\n"
            "- Improve clarity and professionalism of the description.\n"
            "- Ensure the impact statement is specific and business-relevant.\n"
            "- Suggest a remediation if none was provided.\n"
            "- Do NOT change the facts, steps to reproduce, or evidence.\n"
            "- Return the improved report in the same Markdown format.\n\n"
            f"{base_report}"
        )

        try:
            enhanced_report = self._llm.generate(prompt)
            return enhanced_report
        except Exception:
            logger.warning("LLM enhancement failed; returning base report.", exc_info=True)
            return base_report

    def generate_batch_report(self, findings: list[Finding], template_name: str = "summary") -> str:
        severity_order = ["critical", "high", "medium", "low", "informational"]
        counts: dict[str, int] = {s: 0 for s in severity_order}
        for finding in findings:
            severity_key = (finding.severity or "").lower()
            if severity_key in counts:
                counts[severity_key] += 1

        generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        individual_reports = []
        for finding in findings:
            try:
                report = self.generate_report(finding, template_name=template_name)
            except Exception:
                logger.warning("Failed to generate report for finding id=%s.", getattr(finding, "id", "?"), exc_info=True)
                report = f"## {finding.title}\n\n*Report generation failed.*"
            individual_reports.append(report)

        header = (
            "# Vulnerability Assessment Report\n"
            f"**Generated:** {generated_at}\n"
            f"**Total Findings:** {len(findings)}\n"
            "\n"
            "## Findings by Severity\n"
            f"- Critical: {counts['critical']}\n"
            f"- High: {counts['high']}\n"
            f"- Medium: {counts['medium']}\n"
            f"- Low: {counts['low']}\n"
            f"- Informational: {counts['informational']}\n"
            "\n"
            "---\n"
            "\n"
        )

        return header + "\n\n---\n\n".join(individual_reports)

    def export_report(self, report_markdown: str, output_path: str, format: str = "markdown") -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        if format == "markdown":
            if not output_path.endswith(".md"):
                output_path = output_path + ".md"
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(report_markdown)
        elif format == "txt":
            if not output_path.endswith(".txt"):
                output_path = output_path + ".txt"
            plain_text = re.sub(r"[#*`]", "", report_markdown)
            plain_text = re.sub(r"\n{3,}", "\n\n", plain_text)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(plain_text)
        else:
            raise ValueError(f"Unsupported export format: {format!r}")

        return output_path
