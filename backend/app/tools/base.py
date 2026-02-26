import abc
import logging
import subprocess

logger = logging.getLogger(__name__)


class BaseTool(abc.ABC):
    name: str

    @abc.abstractmethod
    def run(
        self,
        target_roots: list[str],
        output_dir: str,
        config: dict,
        scope_validator,
    ) -> str:
        """Execute the tool against the given target roots.

        Args:
            target_roots: List of root domains/CIDRs to scan.
            output_dir: Directory to write raw output files.
            config: Tool-specific configuration (rate limits, threads, etc.).
            scope_validator: A ScopeValidator instance; the tool MUST validate
                targets before executing.

        Returns:
            Path to the output file produced by the tool.
        """

    def _execute_command(
        self, cmd: list[str], timeout: int = 300
    ) -> subprocess.CompletedProcess:
        """Run a shell command and return the completed process.

        Args:
            cmd: Command and arguments as a list (never joined into a shell string).
            timeout: Maximum seconds to wait before raising TimeoutExpired.

        Returns:
            subprocess.CompletedProcess with stdout/stderr captured.

        Raises:
            subprocess.TimeoutExpired: If the command exceeds *timeout* seconds.
            subprocess.CalledProcessError: If the command exits with a non-zero code.
        """
        logger.debug("Executing command: %s", cmd[0] if cmd else "<empty>")
        return subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=True,
        )
