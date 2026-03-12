import os
import tempfile

from app.tools.base import BaseTool

_DEFAULT_TIMEOUT = 600


class KatanaTool(BaseTool):
    """Wrapper for the Katana web crawler (https://github.com/projectdiscovery/katana).

    Katana is a fast, configurable web crawler that discovers endpoints via
    both passive (parsing HTML, JS) and active (headless browser) techniques.
    It is particularly effective at finding hidden API endpoints, JavaScript
    source routes, and form action URLs that subfinder/httpx miss.

    Configuration keys (all optional):
        depth         – crawl depth (default: 3)
        js_crawl      – enable JS parsing (default: True)
        headless      – enable headless browser mode (default: False, slower)
        rate_limit    – requests per second (default: 150)
        concurrency   – parallel fetchers (default: 10)
        timeout       – per-request timeout in seconds (default: 10)
        field         – output fields, comma-separated (default: url)
    """

    name = "katana"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        for url in target_roots:
            scope_validator.check_or_raise(url)

        output_file = os.path.join(output_dir, "katana_results.txt")

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        try:
            tmp.write("\n".join(target_roots))
            tmp.flush()
            tmp.close()

            timeout = int(config.get("timeout_tool", _DEFAULT_TIMEOUT))

            cmd = [
                "katana",
                "-list", tmp.name,
                "-o", output_file,
                "-silent",
                "-depth", str(config.get("depth", 3)),
                "-rate-limit", str(config.get("rate_limit", 150)),
                "-concurrency", str(config.get("concurrency", 10)),
                "-timeout", str(config.get("timeout", 10)),
                "-field", str(config.get("field", "url")),
            ]

            if config.get("js_crawl", True):
                cmd.append("-js-crawl")

            if config.get("headless", False):
                cmd.append("-headless")

            try:
                self._execute_command(cmd, timeout=timeout)
            except FileNotFoundError:
                raise RuntimeError(
                    "katana is not installed or not found in PATH. "
                    "Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
                )
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        return output_file
