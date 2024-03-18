from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import PostgresDsn


class Settings(BaseSettings):
    SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8'
    )
    server_host: str = '127.0.0.1'
    server_port: int = 8000
    pg_dsn: PostgresDsn
    postgres_db: str
    postgres_user: str
    postgres_password: str
    jwt_secret: str
    jwt_algorithm: str = 'HS256'
    jwt_expiration: int = 300


dollar_settings = Settings(
    _env_file='.env',
    _env_file_encoding='utf-8'
)
