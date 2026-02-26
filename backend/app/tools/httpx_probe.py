import os
import tempfile

from app.tools.base import BaseTool

_DEFAULT_TIMEOUT = 600


class HttpxTool(BaseTool):
    name = "httpx"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        output_file = os.path.join(output_dir, "httpx_results.json")

        if "input_file" in config:
            input_file = config["input_file"]
            tmp = None
        else:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            )
            try:
                tmp.write("\n".join(target_roots))
                tmp.flush()
            finally:
                tmp.close()
            input_file = tmp.name

        try:
            with open(input_file) as fh:
                hosts = [line.strip() for line in fh if line.strip()]
            for host in hosts:
                scope_validator.check_or_raise(host)

            cmd = [
                "httpx",
                "-l", input_file,
                "-o", output_file,
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
            ]
            if "threads" in config:
                cmd += ["-threads", str(config["threads"])]
            if "rate_limit" in config:
                cmd += ["-rl", str(config["rate_limit"])]

            try:
                self._execute_command(cmd, timeout=_DEFAULT_TIMEOUT)
            except FileNotFoundError:
                raise RuntimeError(
                    "httpx is not installed or not found in PATH"
                )
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

        return output_file
