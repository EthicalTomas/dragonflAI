import json
import logging
import os
import re
import time
import traceback

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.detection.orchestrator import DetectionOrchestrator
from backend.app.models import Run, RunStatus, Target
from backend.app.parsers.burp_parser import parse_burp_xml
from backend.app.parsers.httpx_parser import parse_httpx_output
from backend.app.parsers.nmap_parser import parse_nmap_output
from backend.app.parsers.subfinder_parser import parse_subfinder_output
from backend.app.parsers.zap_parser import parse_zap_json
from backend.app.scope.validator import ScopeValidator
from backend.app.services.asset_service import AssetService
from backend.app.services.endpoint_service import EndpointService
from backend.app.services.runs_service import append_log, set_progress, set_status
from backend.app.runs.preflight import check_binaries
from backend.app.tools.dnsx import DnsxTool
from backend.app.tools.httpx_probe import HttpxTool
from backend.app.tools.nmap import NmapTool
from backend.app.tools.subfinder import SubfinderTool

logger = logging.getLogger(__name__)

_asset_service = AssetService()
_endpoint_service = EndpointService()

# Pattern used to extract IPs from dnsx output brackets e.g. "[1.2.3.4]"
_DNSX_IP_RE = re.compile(r"\[([^\]]+)\]")
# Record type tokens to skip when extracting IPs from dnsx output
_DNSX_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"})


def _parse_dnsx_output(filepath: str) -> list[dict]:
    """Parse dnsx ``-a -resp -silent`` output into a list of host/IP mappings.

    Each output line has the form::

        hostname [A] [1.2.3.4]

    Returns a list of ``{"hostname": str, "ips": list[str]}`` dicts.
    """
    if not os.path.exists(filepath):
        logger.warning("dnsx output file not found: %s", filepath)
        return []

    results: list[dict] = []
    try:
        with open(filepath, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if not parts:
                    continue
                hostname = parts[0]
                ips: list[str] = []
                for bracket_content in _DNSX_IP_RE.findall(line):
                    for token in bracket_content.split():
                        if token not in _DNSX_RECORD_TYPES:
                            ips.append(token)
                results.append({"hostname": hostname, "ips": ips})
    except OSError as exc:
        logger.warning("Failed to read dnsx output file %s: %s", filepath, exc)
        return []
    return results


_AUTO_VERIFY_SEVERITIES = frozenset({"high", "critical"})


def _queue_auto_verifications(
    db: Session,
    scan_id: int,
    target_id: int,
    run_id: "int | None",
) -> None:
    """Queue verification jobs for high/critical scan results when auto_verify is enabled.

    Creates :class:`~backend.app.models.verification.Verification` records for
    each high or critical ``ScanResult`` from *scan_id* and enqueues them via RQ.
    Failures are logged but do not propagate so the pipeline step succeeds.
    """
    try:
        from backend.app.models.scan import ScanResult  # noqa: PLC0415
        from backend.app.models.verification import Verification, VerificationStatus  # noqa: PLC0415
        from redis import Redis  # noqa: PLC0415
        from rq import Queue  # noqa: PLC0415
        from rq.job import Retry  # noqa: PLC0415

        results = (
            db.query(ScanResult)
            .filter(
                ScanResult.scan_id == scan_id,
                ScanResult.severity.in_(list(_AUTO_VERIFY_SEVERITIES)),
            )
            .all()
        )
        if not results:
            logger.info("_queue_auto_verifications: no high/critical results for scan_id=%d", scan_id)
            return

        redis_conn = Redis.from_url(settings.redis_url)
        q = Queue("verifications", connection=redis_conn)

        queued = 0
        for result in results:
            verification = Verification(
                target_id=target_id,
                run_id=run_id,
                status=VerificationStatus.QUEUED,
                method="http_replay",
                log_text="[auto_verify] queued from pipeline nuclei step\n",
            )
            db.add(verification)
            db.flush()
            q.enqueue(
                "worker.jobs.execute_verification.execute_verification",
                verification.id,
                job_timeout=settings.job_timeout_seconds,
                retry=Retry(max=3, interval=[10, 30, 60]),
            )
            queued += 1

        db.commit()
        logger.info(
            "_queue_auto_verifications: queued %d verification jobs for scan_id=%d",
            queued,
            scan_id,
        )
    except Exception:
        logger.exception(
            "_queue_auto_verifications: failed to queue verifications for scan_id=%d; continuing",
            scan_id,
        )


class ReconPipeline:
    """Orchestrates a multi-step reconnaissance pipeline for a single run."""

    AVAILABLE_STEPS = [
        "subfinder",
        "dnsx",
        "httpx",
        "nmap",
        "import_burp",
        "import_zap",
        "detect",
        "nuclei",
    ]

    def __init__(
        self,
        run_id: int,
        db: Session,
        scope_validator: ScopeValidator,
        artifacts_base_dir: str = "artifacts",
    ) -> None:
        self.run_id = run_id
        self.db = db
        self.scope_validator = scope_validator
        self.artifacts_base_dir = artifacts_base_dir

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _get_step_input(
        self, step: str, config: dict, previous_outputs: dict
    ) -> dict:
        """Return the per-step config dict, wiring previous outputs as inputs.

        For tools that accept an ``input_file`` config key (dnsx, httpx), we
        populate it from subfinder's output when available so that the full
        discovered subdomain list is used instead of just the seed roots.

        Args:
            step: Name of the step being configured.
            config: Top-level pipeline config (may contain per-step sub-dicts).
            previous_outputs: Maps completed step names to their output paths.

        Returns:
            A config dict scoped to *step*, ready to pass to the tool.
        """
        step_config: dict = dict(config.get(step, {}))

        if step == "dnsx":
            if "subfinder" in previous_outputs and "input_file" not in step_config:
                step_config["input_file"] = previous_outputs["subfinder"]

        elif step == "httpx":
            if "subfinder" in previous_outputs and "input_file" not in step_config:
                step_config["input_file"] = previous_outputs["subfinder"]

        return step_config

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def execute(self, modules: list[str], config: dict) -> dict:
        """Run the requested pipeline modules and return a result summary.

        Module execution order is fixed by ``AVAILABLE_STEPS`` regardless of
        the order in *modules*.  Unknown modules are warned about and skipped.
        Individual module failures do **not** abort the pipeline.

        Args:
            modules: Names of modules to run.
            config:  Pipeline-wide configuration dict; may contain per-tool
                     sub-dicts keyed by tool name (e.g. ``config["httpx"]``).

        Returns:
            Result dict with keys: run_id, status, modules_succeeded,
            modules_failed, assets_created, assets_updated, endpoints_created,
            endpoints_updated, signals_detected, duration_seconds.
        """
        start_time = time.time()

        run: Run | None = self.db.get(Run, self.run_id)
        if run is None:
            raise ValueError(f"Run id={self.run_id} not found")

        target: Target | None = self.db.get(Target, run.target_id)
        if target is None:
            raise ValueError(
                f"Target id={run.target_id} not found for run_id={self.run_id}"
            )

        target_roots: list[str] = json.loads(target.roots_json or "[]")

        # Validate and order modules
        unknown = [m for m in modules if m not in self.AVAILABLE_STEPS]
        for m in unknown:
            logger.warning("ReconPipeline: unknown module %r, skipping", m)
        requested: set[str] = set(modules) - set(unknown)
        ordered_modules = [s for s in self.AVAILABLE_STEPS if s in requested]

        # Preflight: verify required binaries are available before starting
        check_binaries(ordered_modules)

        # Create artifacts directory
        artifacts_dir = os.path.join(
            self.artifacts_base_dir, str(target.id), str(self.run_id)
        )
        os.makedirs(artifacts_dir, exist_ok=True)

        # Initialise run state
        set_status(self.db, run, RunStatus.RUNNING)
        append_log(self.db, run, f"Pipeline starting with modules: {ordered_modules}")
        self.db.commit()

        total_steps = len(ordered_modules)
        completed_steps = 0

        succeeded_modules: list[str] = []
        failed_modules: list[str] = []
        previous_outputs: dict[str, str] = {}

        assets_created = 0
        assets_updated = 0
        endpoints_created = 0
        endpoints_updated = 0
        signals_detected = 0

        for step in ordered_modules:
            try:
                step_config = self._get_step_input(step, config, previous_outputs)

                # ---- subfinder -----------------------------------------------
                if step == "subfinder":
                    output_file = SubfinderTool().run(
                        target_roots, artifacts_dir, step_config, self.scope_validator
                    )
                    previous_outputs["subfinder"] = output_file

                    parsed = parse_subfinder_output(output_file)
                    asset_records = [
                        {
                            "target_id": target.id,
                            "run_id": self.run_id,
                            "asset_type": "subdomain",
                            "value": entry["subdomain"],
                        }
                        for entry in parsed
                    ]
                    result = _asset_service.upsert_bulk(self.db, asset_records)
                    assets_created += result["created"]
                    assets_updated += result["updated"]

                # ---- dnsx ----------------------------------------------------
                elif step == "dnsx":
                    output_file = DnsxTool().run(
                        target_roots, artifacts_dir, step_config, self.scope_validator
                    )
                    previous_outputs["dnsx"] = output_file

                    asset_records = [
                        {
                            "target_id": target.id,
                            "run_id": self.run_id,
                            "asset_type": "subdomain",
                            "value": entry["hostname"],
                            "resolved_ips": entry["ips"],
                        }
                        for entry in _parse_dnsx_output(output_file)
                        if entry["ips"]
                    ]
                    _asset_service.upsert_bulk(self.db, asset_records)

                # ---- httpx ---------------------------------------------------
                elif step == "httpx":
                    output_file = HttpxTool().run(
                        target_roots, artifacts_dir, step_config, self.scope_validator
                    )
                    previous_outputs["httpx"] = output_file

                    parsed = parse_httpx_output(output_file)
                    asset_records = []
                    endpoint_records = []
                    for entry in parsed:
                        host = entry.get("host", "")
                        if host:
                            asset_records.append(
                                {
                                    "target_id": target.id,
                                    "run_id": self.run_id,
                                    "asset_type": "subdomain",
                                    "value": host,
                                    "is_alive": True,
                                    "status_code": entry.get("status_code"),
                                    "title": entry.get("title"),
                                    "tech": entry.get("tech", []),
                                }
                            )
                        url = entry.get("url", "")
                        if url:
                            endpoint_records.append(
                                {
                                    "target_id": target.id,
                                    "run_id": self.run_id,
                                    "url": url,
                                    "status_code": entry.get("status_code"),
                                    "source": "httpx",
                                }
                            )

                    a_result = _asset_service.upsert_bulk(self.db, asset_records)
                    assets_created += a_result["created"]
                    assets_updated += a_result["updated"]

                    e_result = _endpoint_service.upsert_bulk(self.db, endpoint_records)
                    endpoints_created += e_result["created"]
                    endpoints_updated += e_result["updated"]

                # ---- nmap ----------------------------------------------------
                elif step == "nmap":
                    # Prefer alive hosts discovered by httpx; fall back to roots.
                    if "httpx" in previous_outputs:
                        httpx_data = parse_httpx_output(previous_outputs["httpx"])
                        nmap_targets = list(
                            {e["host"] for e in httpx_data if e.get("host")}
                        )
                        if not nmap_targets:
                            nmap_targets = target_roots
                    else:
                        nmap_targets = target_roots

                    output_file = NmapTool().run(
                        nmap_targets, artifacts_dir, step_config, self.scope_validator
                    )
                    previous_outputs["nmap"] = output_file

                    asset_records = []
                    for entry in parse_nmap_output(output_file):
                        ip = entry.get("ip", "")
                        hostname = entry.get("hostname", "")
                        ports = entry.get("ports", [])
                        asset_value = hostname or ip
                        if asset_value and ports:
                            asset_type = "subdomain" if hostname else "ip"
                            asset_records.append(
                                {
                                    "target_id": target.id,
                                    "run_id": self.run_id,
                                    "asset_type": asset_type,
                                    "value": asset_value,
                                    "ports": ports,
                                }
                            )
                    _asset_service.upsert_bulk(self.db, asset_records)
                # ---- import_burp ---------------------------------------------
                elif step == "import_burp":
                    burp_file: str = config.get("burp_file", "")
                    if not burp_file:
                        logger.warning(
                            "import_burp: 'burp_file' not in config, skipping"
                        )
                        append_log(
                            self.db,
                            run,
                            "import_burp: no burp_file configured, skipped",
                        )
                    else:
                        parsed = parse_burp_xml(burp_file)
                        endpoint_records = [
                            {
                                "target_id": target.id,
                                "run_id": self.run_id,
                                "url": entry["url"],
                                "method": entry.get("method", "GET"),
                                "status_code": entry.get("status"),
                                "source": "burp",
                            }
                            for entry in parsed
                            if entry.get("url")
                        ]
                        e_result = _endpoint_service.upsert_bulk(
                            self.db, endpoint_records
                        )
                        endpoints_created += e_result["created"]
                        endpoints_updated += e_result["updated"]

                # ---- import_zap ----------------------------------------------
                elif step == "import_zap":
                    zap_file: str = config.get("zap_file", "")
                    if not zap_file:
                        logger.warning(
                            "import_zap: 'zap_file' not in config, skipping"
                        )
                        append_log(
                            self.db,
                            run,
                            "import_zap: no zap_file configured, skipped",
                        )
                    else:
                        parsed = parse_zap_json(zap_file)
                        endpoint_records = [
                            {
                                "target_id": target.id,
                                "run_id": self.run_id,
                                "url": entry["url"],
                                "method": entry.get("method", "GET"),
                                "source": "zap",
                            }
                            for entry in parsed
                            if entry.get("url")
                        ]
                        e_result = _endpoint_service.upsert_bulk(
                            self.db, endpoint_records
                        )
                        endpoints_created += e_result["created"]
                        endpoints_updated += e_result["updated"]

                # ---- detect --------------------------------------------------
                elif step == "detect":
                    detection_result = DetectionOrchestrator(self.db).run_detection(
                        target_id=target.id, run_id=self.run_id
                    )
                    signals_detected = detection_result.get("total_signals", 0)

                # ---- nuclei --------------------------------------------------
                elif step == "nuclei":
                    if not settings.scan_enabled:
                        append_log(
                            self.db,
                            run,
                            "nuclei: scanning is disabled (scan_enabled=false). "
                            "Set SCAN_ENABLED=true to enable.",
                        )
                        logger.warning(
                            "ReconPipeline: nuclei step skipped – scan_enabled=false"
                        )
                    else:
                        from backend.app.models.scan import Scan, ScanStatus  # noqa: PLC0415
                        from backend.app.scans.nuclei_parser import parse_nuclei_jsonl  # noqa: PLC0415
                        from backend.app.scans.nuclei_runner import preflight as nuclei_preflight  # noqa: PLC0415
                        from backend.app.scans.nuclei_runner import run_nuclei  # noqa: PLC0415
                        from backend.app.scans.url_export import export_scan_urls  # noqa: PLC0415

                        nuclei_artifacts_dir = os.path.join(
                            self.artifacts_base_dir,
                            str(target.id),
                            str(self.run_id),
                            "scan",
                        )
                        os.makedirs(nuclei_artifacts_dir, exist_ok=True)

                        # Create a Scan record linked to this run
                        scan_record = Scan(
                            target_id=target.id,
                            run_id=self.run_id,
                            scanner="nuclei",
                            status=ScanStatus.RUNNING,
                            log_text="[pipeline/nuclei] starting\n",
                        )
                        self.db.add(scan_record)
                        self.db.commit()
                        self.db.refresh(scan_record)

                        append_log(
                            self.db, run,
                            f"nuclei: created scan record id={scan_record.id}",
                        )
                        self.db.commit()

                        # Export scope-filtered URLs
                        urls_path = export_scan_urls(
                            self.db,
                            target_id=target.id,
                            scan_id=scan_record.id,
                            artifacts_dir=nuclei_artifacts_dir,
                            scope_validator=self.scope_validator,
                        )
                        append_log(
                            self.db, run,
                            f"nuclei: exported URLs to {urls_path}",
                        )
                        self.db.commit()

                        # Nuclei preflight + run
                        config_meta = nuclei_preflight()
                        scan_record.config_json = json.dumps({
                            "scanner": "nuclei",
                            "template_commit": config_meta.get("template_commit"),
                            "templates_url": config_meta.get("templates_url"),
                            "tags": config_meta.get("tags"),
                            "etags": config_meta.get("etags"),
                            "flags": config_meta.get("flags"),
                            "artifacts_dir": nuclei_artifacts_dir,
                        })
                        self.db.commit()

                        jsonl_path = run_nuclei(artifacts_dir=nuclei_artifacts_dir)

                        # Parse and store results
                        result_count = parse_nuclei_jsonl(
                            self.db,
                            jsonl_path=jsonl_path,
                            scan_id=scan_record.id,
                            target_id=target.id,
                            run_id=self.run_id,
                        )

                        scan_record.status = ScanStatus.SUCCEEDED
                        scan_record.log_text = (
                            (scan_record.log_text or "")
                            + f"[pipeline/nuclei] done: {result_count} results\n"
                        )
                        self.db.commit()

                        append_log(
                            self.db, run,
                            f"nuclei: scan complete (scan_id={scan_record.id}), "
                            f"{result_count} results stored.",
                        )
                        self.db.commit()

                        # Auto-verify high/critical results when configured
                        if settings.auto_verify and result_count > 0:
                            _queue_auto_verifications(
                                self.db, scan_record.id, target.id, self.run_id
                            )

                # ---- post-step bookkeeping -----------------------------------
                completed_steps += 1
                progress = int((completed_steps / total_steps) * 100)
                set_progress(self.db, run, progress)
                append_log(self.db, run, f"Module '{step}' completed successfully.")
                self.db.commit()
                succeeded_modules.append(step)

            except Exception:
                tb = traceback.format_exc()
                logger.error(
                    "ReconPipeline: module '%s' failed:\n%s", step, tb
                )
                append_log(self.db, run, f"Module '{step}' failed:\n{tb}")
                self.db.commit()
                failed_modules.append(step)

        # ------------------------------------------------------------------
        # Finalise run
        # ------------------------------------------------------------------
        total_assets = assets_created + assets_updated
        total_endpoints = endpoints_created + endpoints_updated

        append_log(
            self.db,
            run,
            (
                f"Pipeline complete. "
                f"Assets: {assets_created}/{total_assets}. "
                f"Endpoints: {endpoints_created}/{total_endpoints}. "
                f"Signals: {signals_detected}."
            ),
        )

        if failed_modules and not succeeded_modules:
            # Every module failed
            final_status = RunStatus.FAILED
        else:
            if failed_modules:
                append_log(
                    self.db,
                    run,
                    f"Warning: some modules failed: {failed_modules}",
                )
            final_status = RunStatus.SUCCEEDED

        set_status(self.db, run, final_status)
        set_progress(self.db, run, 100)
        self.db.commit()

        duration = time.time() - start_time

        return {
            "run_id": self.run_id,
            "status": final_status,
            "modules_succeeded": succeeded_modules,
            "modules_failed": failed_modules,
            "assets_created": assets_created,
            "assets_updated": assets_updated,
            "endpoints_created": endpoints_created,
            "endpoints_updated": endpoints_updated,
            "signals_detected": signals_detected,
            "duration_seconds": duration,
        }
