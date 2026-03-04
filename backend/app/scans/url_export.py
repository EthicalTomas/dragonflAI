"""Export a deduplicated list of URLs for a scan target to ``urls.txt``.

Entry point
-----------
``export_scan_urls(db, target_id, scan_id, artifacts_dir)``

The function:
1. Collects all ``Endpoint`` URLs stored for *target_id*.
2. Adds root fallback URLs (``http://host/`` and ``https://host/``) for every
   ``Asset`` belonging to the target.
3. Generates additional URLs from non-standard ports recorded in
   ``asset.ports_json`` when those ports are likely to serve HTTP/HTTPS
   traffic.
4. Normalizes, deduplicates, and sorts the full URL set.
5. Writes the result to ``<artifacts_dir>/urls.txt`` and returns the path.
"""

import json
import logging
import os
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app.models.asset import Asset, AssetType
from backend.app.models.endpoint import Endpoint
from backend.app.scans.url_normalizer import normalize_url

logger = logging.getLogger(__name__)

# Ports that are commonly used for HTTP/HTTPS and therefore worth probing
_HTTP_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 3000, 5000, 9000, 9090, 8888})
_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443})
_ALL_CANDIDATE_PORTS: frozenset[int] = _HTTP_PORTS | _HTTPS_PORTS

# Keywords that indicate an HTTP-like service in nmap service names
_HTTP_SERVICE_KEYWORDS: tuple[str, ...] = ("http", "https", "web", "www")


def _schemes_for_port(port: int, service: str) -> list[str]:
    """Return the URL scheme(s) to try for a given port and service name.

    Logic:
    - If *service* strongly suggests HTTPS (contains "https" or "ssl"), use
      ``https`` only.
    - If *service* suggests HTTP explicitly, prefer ``http``.
    - For port 8443 (or when service hints at SSL/TLS), use ``https``.
    - For all other candidate HTTP ports, use ``http``.
    - Ports in both ``_HTTP_PORTS`` and not clearly HTTPS → ``http``.
    """
    svc_lower = service.lower() if service else ""
    if "https" in svc_lower or "ssl" in svc_lower:
        return ["https"]
    if port in _HTTPS_PORTS:
        return ["https"]
    if port in _HTTP_PORTS:
        return ["http"]
    return []


def _host_from_asset(asset: Asset) -> str | None:
    """Return the hostname/IP string to use in URLs for *asset*.

    For SUBDOMAIN/CIDR assets the stored *value* is used directly.
    IP assets also use *value*.  CIDR ranges are skipped (return ``None``).
    """
    if asset.asset_type == AssetType.CIDR:
        return None
    return asset.value or None


def _generate_port_urls(asset: Asset) -> list[str]:
    """Generate candidate URLs from the port data stored in *asset.ports_json*."""
    host = _host_from_asset(asset)
    if not host:
        return []

    try:
        ports_data: list[dict] = json.loads(asset.ports_json or "[]")
    except (json.JSONDecodeError, TypeError):
        return []

    urls: list[str] = []
    for entry in ports_data:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        service = entry.get("service", "")
        if not isinstance(port, int):
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue

        if port not in _ALL_CANDIDATE_PORTS:
            continue

        # Only generate URLs for ports whose service looks HTTP-like (or is unknown)
        svc_lower = (service or "").lower()
        service_is_http = not svc_lower or any(kw in svc_lower for kw in _HTTP_SERVICE_KEYWORDS)
        if not service_is_http:
            continue

        for scheme in _schemes_for_port(port, service):
            urls.append(f"{scheme}://{host}:{port}/")

    return urls


def export_scan_urls(db: Session, target_id: int, scan_id: int, artifacts_dir: str) -> Path:
    """Build a deduplicated ``urls.txt`` for *target_id* and return its path.

    Parameters
    ----------
    db:
        Active SQLAlchemy session.
    target_id:
        Primary key of the target whose URLs are exported.
    scan_id:
        Scan this export is associated with (used for logging only).
    artifacts_dir:
        Directory in which ``urls.txt`` will be written.  Created if absent.

    Returns
    -------
    Path
        Absolute path to the written ``urls.txt`` file.
    """
    raw_urls: list[str] = []

    # ------------------------------------------------------------------ #
    # 1. Collect stored endpoint URLs
    # ------------------------------------------------------------------ #
    endpoints = db.query(Endpoint).filter(Endpoint.target_id == target_id).all()
    endpoint_urls = [ep.url for ep in endpoints if ep.url]
    raw_urls.extend(endpoint_urls)
    logger.info(
        "scan_id=%d target_id=%d: collected %d endpoint URLs",
        scan_id,
        target_id,
        len(endpoint_urls),
    )

    # ------------------------------------------------------------------ #
    # 2. Collect assets and generate fallback + port-based URLs
    # ------------------------------------------------------------------ #
    assets = db.query(Asset).filter(Asset.target_id == target_id).all()
    logger.info(
        "scan_id=%d target_id=%d: processing %d assets",
        scan_id,
        target_id,
        len(assets),
    )

    fallback_count = 0
    port_url_count = 0

    for asset in assets:
        host = _host_from_asset(asset)
        if not host:
            continue

        # Root fallbacks
        for scheme in ("http", "https"):
            raw_urls.append(f"{scheme}://{host}/")
            fallback_count += 1

        # Non-standard port URLs
        port_urls = _generate_port_urls(asset)
        raw_urls.extend(port_urls)
        port_url_count += len(port_urls)

    logger.info(
        "scan_id=%d target_id=%d: generated %d fallback root URLs, %d port-based URLs",
        scan_id,
        target_id,
        fallback_count,
        port_url_count,
    )

    # ------------------------------------------------------------------ #
    # 3. Normalize, deduplicate, and sort
    # ------------------------------------------------------------------ #
    seen: set[str] = set()
    unique_urls: list[str] = []
    for raw in raw_urls:
        normed = normalize_url(raw)
        if normed and normed not in seen:
            seen.add(normed)
            unique_urls.append(normed)

    unique_urls.sort()
    logger.info(
        "scan_id=%d target_id=%d: final unique URL count = %d",
        scan_id,
        target_id,
        len(unique_urls),
    )

    # ------------------------------------------------------------------ #
    # 4. Write to disk
    # ------------------------------------------------------------------ #
    os.makedirs(artifacts_dir, exist_ok=True)
    output_path = Path(artifacts_dir) / "urls.txt"
    output_path.write_text("\n".join(unique_urls) + ("\n" if unique_urls else ""), encoding="utf-8")
    logger.info("scan_id=%d target_id=%d: wrote %s", scan_id, target_id, output_path)

    return output_path
