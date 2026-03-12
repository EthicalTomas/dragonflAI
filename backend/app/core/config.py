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
    # detection signals and Nuclei results at or above auto_verify_min_severity.
    auto_verify: bool = False
    # Minimum severity level for auto-verification of Nuclei scan results.
    # Results at this severity and above are enqueued automatically when
    # auto_verify=True.  Valid values (lowest → highest):
    #   info | low | medium | high | critical
    # Default is "high" so only high and critical results are auto-verified.
    auto_verify_min_severity: str = "high"

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

    # --- LLM config ---------------------------------------------------------
    # Which LLM provider to use for report enhancement and AI features.
    # Valid values: null | ollama | openai | anthropic
    # Defaults to "null" (LLM disabled).  Switch to "ollama" for a free local
    # option, or "openai" / "anthropic" for cloud-based inference.
    llm_provider: str = "null"

    # Ollama settings (used when llm_provider="ollama")
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_embed_model: str = "nomic-embed-text"

    # OpenAI settings (used when llm_provider="openai")
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_embed_model: str = "text-embedding-3-small"

    # Anthropic settings (used when llm_provider="anthropic")
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-haiku-latest"


settings = Settings()
