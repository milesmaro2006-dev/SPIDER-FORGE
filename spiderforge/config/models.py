"""Application configuration models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    concurrency: int = 20
    timeout: float = 20.0
    max_depth: int = 5
    max_urls: int = 5000
    max_response_size: int = 5_000_000
    max_js_size: int = 2_000_000
    rate_limit: float = 20.0
    delay: float = 0.0
    aggressive: bool = False
    user_agent: str = "SpiderForge/2.0"


class ReconConfig(BaseModel):
    subdomains: bool = True
    ports: bool = False
    technologies: bool = True


class BrowserConfig(BaseModel):
    enabled: bool = False
    screenshots: bool = False
    headless: bool = True


class ReportingConfig(BaseModel):
    enable_json: bool = True
    enable_html: bool = True
    enable_markdown: bool = True
    enable_pdf: bool = False


class StorageConfig(BaseModel):
    database: str = "sqlite"


class LoggingConfig(BaseModel):
    level: str = "INFO"


class NetworkConfig(BaseModel):
    allow_private_ips: bool = False
    allow_public_ips: bool = True
    verify_tls: bool = True
    trust_env_proxies: bool = False


class SpiderForgeConfig(BaseModel):
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
