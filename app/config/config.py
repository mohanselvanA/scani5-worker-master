from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Worker Database
    WORKER_DB_USER: str
    WORKER_DB_PASSWORD: str
    WORKER_DB_HOST: str
    WORKER_DB_PORT: str
    WORKER_DB: str

    # NVDFeeds Database
    NVD_DB_HOST: str
    NVD_DB_PORT: str
    NVD_DB_USER: str
    NVD_DB_PASSWORD: str
    NVD_DB: str

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()