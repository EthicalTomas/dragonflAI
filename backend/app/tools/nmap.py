import os

from app.tools.base import BaseTool

# nmap can be slow, especially for large networks or script scans.
# Note: some scan types (e.g. SYN scan -sS) require root/sudo privileges.
# Do NOT run this service as root automatically; ensure the deployment
# environment grants the necessary capabilities (e.g. CAP_NET_RAW).
_DEFAULT_TIMEOUT = 900


class NmapTool(BaseTool):
    name = "nmap"

    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        for target in target_roots:
            scope_validator.check_or_raise(target)

        output_file = os.path.join(output_dir, "nmap_results.xml")

        cmd = ["nmap", "-sV", "-oX", output_file]

        if "ports" in config:
            cmd += ["-p", str(config["ports"])]
        if "timing" in config:
            timing = int(config["timing"])
            if timing not in range(6):
                raise ValueError(
                    f"Invalid timing value {timing!r}: nmap -T accepts 0-5"
                )
            cmd.append(f"-T{timing}")
        if "scripts" in config:
            cmd += ["--script", str(config["scripts"])]

        cmd.extend(target_roots)

        try:
            self._execute_command(cmd, timeout=_DEFAULT_TIMEOUT)
        except FileNotFoundError:
            raise RuntimeError("nmap is not installed or not found in PATH")

        return output_file
