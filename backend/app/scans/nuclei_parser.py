"""Parse nuclei JSONL output and persist each finding as a ``ScanResult``.

Entry point
-----------
``parse_nuclei_jsonl(db, jsonl_path, scan_id, target_id, run_id=None)``

The function reads the file produced by nuclei's ``-je`` flag line-by-line,
maps each JSON object to a :class:`~backend.app.models.scan.ScanResult`, and
bulk-commits all rows in a single transaction.

Nuclei JSONL fields used
------------------------
- ``template-id``  → ``ScanResult.template_id``
- ``info.name``    → ``ScanResult.title``
- ``info.severity`` → ``ScanResult.severity``
- ``info.tags``    → ``ScanResult.tags_json``
- ``matched-at``   → ``ScanResult.matched_url``
- ``request`` / ``response`` / ``extracted-results`` / ``curl-command``
                   → ``ScanResult.evidence_json``
- raw line        → ``ScanResult.raw_json``
"""

import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app.models.scan import ScanResult

logger = logging.getLogger(__name__)


def parse_nuclei_jsonl(
    db: Session,
    jsonl_path: "str | Path",
    scan_id: int,
    target_id: int,
    run_id: "int | None" = None,
) -> int:
    """Parse *jsonl_path* and persist each finding as a :class:`ScanResult`.

    Parameters
    ----------
    db:
        Active SQLAlchemy session.
    jsonl_path:
        Path to the ``nuclei.jsonl`` output file.
    scan_id:
        Foreign key linking to the parent :class:`~backend.app.models.scan.Scan`.
    target_id:
        Foreign key for the scan target.
    run_id:
        Optional foreign key to the parent run.

    Returns
    -------
    int
        Number of :class:`ScanResult` rows inserted.
    """
    path = Path(jsonl_path)
    if not path.exists():
        logger.warning("parse_nuclei_jsonl: file not found: %s", path)
        return 0

    count = 0
    for line_num, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("parse_nuclei_jsonl: invalid JSON on line %d, skipping", line_num)
            continue

        if not isinstance(entry, dict):
            continue

        info = entry.get("info") or {}
        template_id = entry.get("template-id") or entry.get("template_id")
        title = info.get("name") or template_id or "Unknown"
        severity = (info.get("severity") or "informational").lower()
        matched_url = entry.get("matched-at") or entry.get("host") or ""

        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        evidence: dict = {}
        for field in ("request", "response", "extracted-results", "curl-command"):
            val = entry.get(field)
            if val is not None:
                evidence[field] = val

        db.add(
            ScanResult(
                scan_id=scan_id,
                target_id=target_id,
                run_id=run_id,
                tool="nuclei",
                severity=severity,
                template_id=template_id,
                title=title,
                matched_url=matched_url,
                tags_json=json.dumps(tags),
                evidence_json=json.dumps(evidence),
                raw_json=line,
            )
        )
        count += 1

    if count:
        db.commit()

    logger.info(
        "parse_nuclei_jsonl: inserted %d ScanResult rows (scan_id=%d)",
        count,
        scan_id,
    )
    return count
