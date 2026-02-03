import os
from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_data_dir: str = Field(default_factory=lambda: os.getenv("APP_DATA_DIR", "/var/lib/apkspider"))
    max_upload_bytes: int = Field(default_factory=lambda: int(os.getenv("MAX_UPLOAD_BYTES", str(250 * 1024 * 1024))))
    max_extracted_bytes: int = Field(default_factory=lambda: int(os.getenv("MAX_EXTRACTED_BYTES", str(1024 * 1024 * 1024))))
    max_extract_files: int = Field(default_factory=lambda: int(os.getenv("MAX_EXTRACT_FILES", "10000")))
    max_extract_file_bytes: int = Field(default_factory=lambda: int(os.getenv("MAX_EXTRACT_FILE_BYTES", str(200 * 1024 * 1024))))
    job_timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("JOB_TIMEOUT_SECONDS", "600")))
    job_cpu_seconds: int = Field(default_factory=lambda: int(os.getenv("JOB_CPU_SECONDS", "600")))
    job_memory_bytes: int = Field(default_factory=lambda: int(os.getenv("JOB_MEMORY_BYTES", str(2 * 1024 * 1024 * 1024))))
    job_fds: int = Field(default_factory=lambda: int(os.getenv("JOB_FD_LIMIT", "256")))
    job_nproc: int = Field(default_factory=lambda: int(os.getenv("JOB_NPROC_LIMIT", "128")))
    disable_job_network: bool = Field(default_factory=lambda: os.getenv("DISABLE_JOB_NETWORK", "true").lower() == "true")
    keep_job_dirs: bool = Field(default_factory=lambda: os.getenv("KEEP_JOB_DIRS", "false").lower() == "true")
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://redis:6379/0"))
    api_origin: str = Field(default_factory=lambda: os.getenv("API_ORIGIN", "http://localhost:3000"))
    allowed_origins: str = Field(default_factory=lambda: os.getenv("ALLOWED_ORIGINS", "http://localhost:3000"))
    enable_basic_auth: bool = Field(default_factory=lambda: os.getenv("BASIC_AUTH_ENABLED", "false").lower() == "true")
    basic_auth_username: str = Field(default_factory=lambda: os.getenv("BASIC_AUTH_USERNAME", "admin"))
    basic_auth_password_hash: str = Field(default_factory=lambda: os.getenv("BASIC_AUTH_PASSWORD_HASH", ""))


settings = Settings()
