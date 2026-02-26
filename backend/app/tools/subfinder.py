import os
import tempfile

from app.tools.base import BaseTool

_DEFAULT_TIMEOUT = 600


class SubfinderTool(BaseTool):
    name = "subfinder"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        for domain in target_roots:
            scope_validator.check_or_raise(domain)

        output_file = os.path.join(output_dir, "subfinder_results.txt")
        timeout = int(config.get("timeout", _DEFAULT_TIMEOUT))

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        )
        try:
            tmp.write("\n".join(target_roots))
            tmp.flush()
            tmp.close()

            cmd = [
                "subfinder",
                "-dL", tmp.name,
                "-o", output_file,
                "-silent",
            ]
            if "threads" in config:
                cmd += ["-t", str(config["threads"])]
            if "timeout" in config:
                cmd += ["-timeout", str(config["timeout"])]

            try:
                self._execute_command(cmd, timeout=timeout)
            except FileNotFoundError:
                raise RuntimeError(
                    "subfinder is not installed or not found in PATH"
                )
        finally:
            try:
                tmp.close()
            except Exception:
                pass
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        return output_file
