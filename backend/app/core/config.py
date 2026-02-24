from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://dragonflai:dragonflai_dev@localhost:5433/dragonflai"
    redis_url: str = "redis://localhost:6380/0"

    backend_host: str = "127.0.0.1"
    backend_port: int = 8000

    backend_url: str = "http://127.0.0.1:8000"
    ui_host: str = "127.0.0.1"
    ui_port: int = 8501


settings = Settings()
