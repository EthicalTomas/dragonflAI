"""Preflight checks for the recon pipeline.

Verifies that required external binaries are available in ``$PATH`` before
a pipeline run starts, so that failures produce actionable error messages
rather than cryptic ``subprocess`` errors.
"""

import shutil

# Maps each pipeline step name to its binary name and install instructions.
_BINARY_INFO: dict[str, dict[str, str]] = {
    "subfinder": {
        "binary": "subfinder",
        "install": (
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
            "    Ensure $HOME/go/bin is on your PATH: export PATH=$PATH:$HOME/go/bin\n"
            "    See: https://github.com/projectdiscovery/subfinder"
        ),
    },
    "dnsx": {
        "binary": "dnsx",
        "install": (
            "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest\n"
            "    Ensure $HOME/go/bin is on your PATH: export PATH=$PATH:$HOME/go/bin\n"
            "    See: https://github.com/projectdiscovery/dnsx"
        ),
    },
    "httpx": {
        "binary": "httpx",
        "install": (
            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "    Ensure $HOME/go/bin is on your PATH: export PATH=$PATH:$HOME/go/bin\n"
            "    See: https://github.com/projectdiscovery/httpx"
        ),
    },
    "nmap": {
        "binary": "nmap",
        "install": (
            "sudo apt install nmap   (Debian/Ubuntu)\n"
            "    brew install nmap     (macOS)\n"
            "    See: https://nmap.org/download.html"
        ),
    },
}


def check_binaries(modules: list[str]) -> None:
    """Verify that each module's required binary is present in ``$PATH``.

    Only modules listed in ``_BINARY_INFO`` are checked; steps such as
    ``import_burp``, ``import_zap``, and ``detect`` are silently skipped
    because they do not require external binaries.

    Args:
        modules: List of pipeline step names to run
            (e.g. ``["subfinder", "nmap"]``).

    Raises:
        RuntimeError: If one or more required binaries are missing.  The
            exception message names each missing tool and includes install
            instructions.
    """
    missing: list[str] = []
    for step in modules:
        info = _BINARY_INFO.get(step)
        if info is None:
            continue
        if shutil.which(info["binary"]) is None:
            missing.append(
                f"  - {info['binary']}\n"
                f"    Install: {info['install']}"
            )

    if missing:
        details = "\n".join(missing)
        raise RuntimeError(
            f"Preflight check failed — the following required binaries were not "
            f"found in $PATH:\n\n{details}\n\n"
            f"Please install the missing tools and ensure they are on your PATH.\n"
            f"See docs/setup.md for full setup instructions."
        )
