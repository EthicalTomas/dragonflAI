import os

from backend.app.tools.base import BaseTool

_DEFAULT_TIMEOUT = 600


class GauTool(BaseTool):
    """Wrapper for getallurls / gau (https://github.com/lc/gau).

    gau fetches known URLs from multiple sources:
      - Wayback Machine (web.archive.org)
      - Common Crawl (commoncrawl.org)
      - URLScan (urlscan.io)
      - AlienVault OTX

    This is a **passive** tool — it queries public indexes only and never
    contacts the target directly, making it safe to run broadly.

    Configuration keys (all optional):
        providers     – comma-separated list of sources
                        (default: wayback,commoncrawl,otx,urlscan)
        threads       – number of parallel fetchers (default: 2)
        retries       – number of retries on failure (default: 3)
        blacklist     – comma-separated list of file extensions to skip
                        (default: png,jpg,gif,css,woff,woff2,ico,svg,eot,ttf,map)
        subs          – include subdomains (default: False)
        timeout       – per-request timeout in seconds (default: 45)
    """

    name = "gau"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        for domain in target_roots:
            scope_validator.check_or_raise(domain)

        output_file = os.path.join(output_dir, "gau_results.txt")
        timeout = int(config.get("timeout_tool", _DEFAULT_TIMEOUT))

        _DEFAULT_BLACKLIST = "png,jpg,gif,css,woff,woff2,ico,svg,eot,ttf,map"

        with open(output_file, "w") as out_fh:
            for domain in target_roots:
                cmd = [
                    "gau",
                    domain,
                    "--threads", str(config.get("threads", 2)),
                    "--retries", str(config.get("retries", 3)),
                    "--blacklist", str(config.get("blacklist", _DEFAULT_BLACKLIST)),
                    "--timeout", str(config.get("timeout", 45)),
                ]

                if config.get("providers"):
                    cmd += ["--providers", str(config["providers"])]

                if config.get("subs", False):
                    cmd.append("--subs")

                try:
                    result = self._execute_command(cmd, timeout=timeout)
                    if result.stdout:
                        out_fh.write(result.stdout.decode(errors="replace"))
                        if not result.stdout.endswith(b"\n"):
                            out_fh.write("\n")
                except FileNotFoundError:
                    raise RuntimeError(
                        "gau is not installed or not found in PATH. "
                        "Install with: go install github.com/lc/gau/v2/cmd/gau@latest"
                    )

        return output_file
