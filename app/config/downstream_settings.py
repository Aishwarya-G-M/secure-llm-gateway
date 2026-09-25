from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    simple_rag_base_url: str = "http://127.0.0.1:8001"
    simple_rag_query_path: str = "/rag/query"
    simple_rag_evaluation_path: str = "/rag/evaluate"

    graphrag_base_url: str = "http://127.0.0.1:8680"
    graphrag_query_path: str = "/graphrag-query"

    downstream_timeout_seconds: float = 20.0
    downstream_max_retries: int = 1

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        extra="ignore",
    )


settings = Settings()