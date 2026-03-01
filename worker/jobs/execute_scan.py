import datetime
import logging

from backend.app.db.session import SessionLocal
from backend.app.models.scan import Scan, ScanStatus

logger = logging.getLogger(__name__)


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        scan.status = ScanStatus.RUNNING
        scan.updated_at = datetime.datetime.now(datetime.UTC)
        scan.log_text = (scan.log_text or "") + "[execute_scan] status -> running\n"
        db.commit()

        logger.info("execute_scan: scan_id=%d scanner=%s", scan_id, scan.scanner)

        # Placeholder: nuclei execution not yet implemented
        scan.log_text = (scan.log_text or "") + "[execute_scan] scan execution not implemented\n"
        scan.status = ScanStatus.FAILED
        scan.updated_at = datetime.datetime.now(datetime.UTC)
        db.commit()

        logger.info("execute_scan: scan_id=%d finished with status=%s", scan_id, scan.status)
    except Exception:
        logger.exception("execute_scan: crashed (scan_id=%d)", scan_id)
        raise
    finally:
        db.close()
