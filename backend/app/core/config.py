from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    # Maximum wall-clock seconds a recon job may run before RQ kills it.
    # Recon steps (subfinder, nmap, …) can be long; default to 1 hour.
    job_timeout_seconds: int = 3600
    # When True, automatically queue verification jobs for high-confidence
    # detection signals and Nuclei results above medium severity.
    auto_verify: bool = False

    # --- Scanning config ----------------------------------------------------
    # Master kill-switch: scanning is disabled by default.  Set to True (or
    # SCAN_ENABLED=true in .env) to allow nuclei scans to be launched.
    scan_enabled: bool = False
    # Controls when scanning is triggered:
    #   on_demand        – only when the "nuclei" module is explicitly selected
    #   auto_after_recon – also auto-appended to every pipeline run
    scan_mode: str = "on_demand"

    # Hard caps applied at the scan layer.  These may NOT be raised above the
    # program policy (if per-program limits are set they must be <=).
    # Maximum number of target URLs fed to a single nuclei invocation.
    max_scan_targets: int = 500
    # Maximum requests-per-minute passed to nuclei -rl (overrides default 5).
    max_requests_per_minute: int = 5
    # Maximum wall-clock seconds a nuclei scan job may run.
    max_scan_runtime_seconds: int = 3600
    # Maximum HTTP response body bytes captured for evidence storage.
    max_response_size_bytes: int = 1_048_576


settings = Settings()
