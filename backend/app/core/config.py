from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000


settings = Settings()
