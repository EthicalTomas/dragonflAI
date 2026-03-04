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


settings = Settings()
