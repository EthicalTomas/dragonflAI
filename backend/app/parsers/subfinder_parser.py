import logging
import os

logger = logging.getLogger(__name__)


def parse_subfinder_output(filepath: str) -> list[dict]:
    if not os.path.exists(filepath):
        logger.warning("Subfinder output file not found: %s", filepath)
        return []

    seen: set[str] = set()
    results: list[dict] = []

    try:
        fh_ctx = open(filepath, encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read subfinder output file %s: %s", filepath, exc)
        return []

    with fh_ctx as fh:
        for line in fh:
            subdomain = line.strip().lower()
            if not subdomain or subdomain in seen:
                continue
            seen.add(subdomain)
            results.append({"subdomain": subdomain})

    return results
