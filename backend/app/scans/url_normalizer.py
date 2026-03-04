"""URL normalization helpers for scan URL export."""

import logging
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

logger = logging.getLogger(__name__)

# Default ports that should be removed when explicit (scheme already implies them)
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


def normalize_url(url: str) -> str | None:
    """Normalize a URL for deduplication and consistent storage.

    Transformations applied:
    - Strip surrounding whitespace
    - Remove fragment (#…)
    - Lowercase scheme and hostname
    - Remove default ports (80 for http, 443 for https)
    - Ensure path is at least ``/``
    - Sort query parameters for stable comparison

    Returns ``None`` when *url* is not a valid http/https URL.
    """
    url = url.strip()
    if not url:
        return None

    try:
        parsed = urlparse(url)
    except Exception:
        logger.debug("Failed to parse URL: %r", url)
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    netloc = parsed.netloc.lower() if parsed.netloc else ""
    if not netloc:
        return None

    # Normalize host:port – strip default port
    if ":" in netloc:
        host, port_str = netloc.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = None
        if port is not None and _DEFAULT_PORTS.get(scheme) == port:
            netloc = host
    else:
        host = netloc

    if not host:
        return None

    path = parsed.path or "/"

    # Sort query parameters for stable comparison
    query = ""
    if parsed.query:
        params = parse_qsl(parsed.query, keep_blank_values=True)
        params.sort()
        query = urlencode(params)

    # Drop fragment entirely
    normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))
    return normalized
