"""
BuildOS Auth Service
Application Configuration
"""

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Runtime configuration for the BuildOS Auth Service.
    """

    # Application
    service_name: str = "buildos-auth-service"
    environment: str = "development"
    debug: bool = False

    # Database
    database_url: str

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "buildos-auth-service"
    jwt_audience: str = "buildos-api"

    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    # Password security
    password_hash_time_cost: int = 3
    password_hash_memory_cost: int = 65536
    password_hash_parallelism: int = 4

    # Authentication security
    max_failed_login_attempts: int = 5
    login_lockout_minutes: int = 15
    login_rate_limit_window_minutes: int = 15
    internal_api_key: str = "change-me-in-production"

    # Password reset
    password_reset_expire_minutes: int = 30

    # User Service integration
    user_service_url: str = "http://127.0.0.1:8001"
    user_service_api_key: str
    user_service_id: str = "buildos-auth-service"
    user_service_timeout: float = 5.0

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        """
        Reject insecure configuration in production.
        """

        if self.environment.lower() != "production":
            return self

        placeholder = "change-me-in-production"

        if self.internal_api_key == placeholder:
            raise ValueError(
                "Default internal_api_key used in production!"
            )

        if self.user_service_api_key == placeholder:
            raise ValueError(
                "Default user_service_api_key used in production!"
            )

        if not self.user_service_url.lower().startswith("https://"):
            raise ValueError(
                "user_service_url must use HTTPS in production"
            )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """
    Return the cached application settings.
    """
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
