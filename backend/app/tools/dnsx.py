import os
import tempfile

from app.tools.base import BaseTool

_DEFAULT_TIMEOUT = 300


class DnsxTool(BaseTool):
    name = "dnsx"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        output_file = os.path.join(output_dir, "dnsx_results.txt")

        tmp = None
        try:
            if "input_file" in config:
                input_file = config["input_file"]
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

            with open(input_file) as fh:
                hosts = [line.strip() for line in fh if line.strip()]
            for host in hosts:
                scope_validator.check_or_raise(host)

            cmd = [
                "dnsx",
                "-l", input_file,
                "-o", output_file,
                "-a",
                "-resp",
                "-silent",
            ]
            if "threads" in config:
                cmd += ["-t", str(config["threads"])]

            try:
                self._execute_command(cmd, timeout=_DEFAULT_TIMEOUT)
            except FileNotFoundError:
                raise RuntimeError(
                    "dnsx is not installed or not found in PATH"
                )
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

        return output_file
