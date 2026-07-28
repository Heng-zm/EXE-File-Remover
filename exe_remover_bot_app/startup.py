from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    level: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class StartupValidationReport:
    issues: tuple[ValidationIssue, ...]

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.level == "error")

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.level == "warning")

    @property
    def ok(self) -> bool:
        return not self.errors

    def raise_for_errors(self) -> None:
        if self.errors:
            details = "; ".join(f"{issue.code}: {issue.message}" for issue in self.errors)
            raise RuntimeError(f"Startup validation failed: {details}")

    def log(self, logger: Any) -> None:
        for issue in self.issues:
            method = logger.error if issue.level == "error" else logger.warning
            method("startup validation %s: %s", issue.code, issue.message)
        if not self.issues:
            logger.info("Startup validation passed with no warnings.")


def _text(config: Mapping[str, Any], key: str) -> str:
    return str(config.get(key) or "").strip()


def _bool(config: Mapping[str, Any], key: str, default: bool = False) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on"}


def _looks_like_placeholder(value: str) -> bool:
    compact = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")
    markers = (
        "replace",
        "placeholder",
        "change_me",
        "changeme",
        "your_token",
        "your_secret",
        "example",
        "dummy",
        "sample",
    )
    return not compact or any(marker in compact for marker in markers)


def validate_startup_config(
    config: Mapping[str, Any],
    *,
    available_dependencies: Iterable[str] = (),
) -> StartupValidationReport:
    issues: list[ValidationIssue] = []
    dependencies = {str(item).casefold() for item in available_dependencies}

    token = _text(config, "BOT_TOKEN")
    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token) or _looks_like_placeholder(token):
        issues.append(ValidationIssue("error", "bot_token", "BOT_TOKEN is missing, malformed, or a placeholder."))

    mode = _text(config, "BOT_MODE").upper() or "AUTO"
    if mode not in {"AUTO", "WEBHOOK", "POLLING"}:
        issues.append(ValidationIssue("error", "bot_mode", "BOT_MODE must be AUTO, WEBHOOK, or POLLING."))

    base_url = _text(config, "WEBHOOK_BASE_URL").rstrip("/")
    resolved_mode = "WEBHOOK" if mode == "WEBHOOK" or (mode == "AUTO" and bool(base_url)) else "POLLING"
    if resolved_mode == "WEBHOOK":
        if not base_url:
            issues.append(ValidationIssue("error", "webhook_url", "Webhook mode requires WEBHOOK_URL or RENDER_EXTERNAL_URL."))
        else:
            parsed = urlparse(base_url)
            if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
                issues.append(ValidationIssue("error", "webhook_https", "The public Telegram webhook URL must use HTTPS."))
            if not parsed.netloc:
                issues.append(ValidationIssue("error", "webhook_url", "The webhook base URL is not a valid absolute URL."))

        header_secret = _text(config, "WEBHOOK_SECRET_TOKEN")
        path_secret = _text(config, "WEBHOOK_PATH_SECRET")
        if (
            len(header_secret) < 24
            or len(path_secret) < 24
            or _looks_like_placeholder(header_secret)
            or _looks_like_placeholder(path_secret)
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "webhook_secrets",
                    "Webhook header and path secrets must be real random values with at least 24 characters.",
                )
            )
        if header_secret and header_secret == path_secret:
            issues.append(ValidationIssue("error", "webhook_secret_reuse", "Webhook header and path secrets must be different."))

        path = _text(config, "WEBHOOK_URL_PATH")
        if not path or path.startswith("/") or "?" in path or "#" in path or ".." in path:
            issues.append(ValidationIssue("error", "webhook_path", "WEBHOOK_URL_PATH must be a safe relative URL path."))

    redis_enabled = _bool(config, "REDIS_ENABLED")
    redis_url = _text(config, "REDIS_URL")
    if redis_enabled and not redis_url:
        issues.append(ValidationIssue("error", "redis_url", "REDIS_ENABLED=true requires REDIS_URL."))
    if redis_url and not redis_url.startswith(("redis://", "rediss://", "unix://")):
        issues.append(ValidationIssue("warning", "redis_scheme", "REDIS_URL should use redis://, rediss://, or unix://."))

    supabase_enabled = _bool(config, "SUPABASE_ENABLED")
    supabase_url = _text(config, "SUPABASE_URL")
    supabase_key = _text(config, "SUPABASE_SERVICE_ROLE_KEY")
    if supabase_enabled and (not supabase_url or not supabase_key):
        issues.append(ValidationIssue("error", "supabase_config", "SUPABASE_ENABLED=true requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY."))
    if supabase_url and not supabase_url.startswith("https://"):
        issues.append(ValidationIssue("warning", "supabase_https", "SUPABASE_URL should use HTTPS."))

    local_pickle = _bool(config, "LOCAL_PERSISTENCE_ENABLED")
    if local_pickle:
        issues.append(ValidationIssue("warning", "pickle_enabled", "Local pickle persistence is enabled; only load a trusted local state file."))
    if not local_pickle and not redis_enabled and not supabase_enabled:
        issues.append(ValidationIssue("warning", "memory_only", "No durable persistence backend is enabled; state will be lost on restart."))

    mini_app_enabled = _bool(config, "MINI_APP_API_ENABLED")
    if mini_app_enabled and resolved_mode == "WEBHOOK":
        for dependency in ("fastapi", "uvicorn"):
            if dependency not in dependencies:
                issues.append(ValidationIssue("error", f"dependency_{dependency}", f"MINI_APP_API_ENABLED=true requires {dependency}."))

    origins = config.get("MINI_APP_CORS_ORIGINS", ())
    if isinstance(origins, str):
        origins = [item.strip() for item in origins.split(",") if item.strip()]
    if mini_app_enabled and "*" in set(origins or ()):
        issues.append(ValidationIssue("warning", "cors_wildcard", "MINI_APP_CORS_ORIGINS=* is convenient but exact production origins are safer."))

    if _bool(config, "SERVER_LOG_PUBLIC_ACCESS"):
        issues.append(ValidationIssue("error", "public_server_logs", "SERVER_LOG_PUBLIC_ACCESS must remain false; operational logs may contain sensitive metadata."))
    if _bool(config, "SERVER_LOG_AUTH_QUERY_ENABLED"):
        issues.append(ValidationIssue("error", "query_log_key", "Query-string server-log keys are disabled because URLs leak through browser and proxy logs."))

    server_log_key = _text(config, "SERVER_LOG_API_KEY") or _text(config, "SERVER_LOG_TOKEN")
    if server_log_key and (len(server_log_key) < 32 or _looks_like_placeholder(server_log_key)):
        issues.append(ValidationIssue("error", "server_log_api_key", "SERVER_LOG_API_KEY must be a non-placeholder random value of at least 32 characters."))
    if _bool(config, "SERVER_LOG_STORE_CLIENT_IP"):
        issues.append(ValidationIssue("warning", "raw_client_ip_logs", "Raw client IP logging is enabled; privacy-safe fingerprints are recommended."))
    if _bool(config, "MINI_APP_PUBLIC_DOCS_ENABLED"):
        issues.append(ValidationIssue("warning", "public_api_docs", "Public OpenAPI documentation reveals protected administration route names."))
    if _bool(config, "MINI_APP_PUBLIC_ROUTE_CATALOG_ENABLED"):
        issues.append(ValidationIssue("warning", "public_route_catalog", "The public route catalog exposes additional API surface metadata."))
    if _bool(config, "MINI_APP_FRONTEND_DEBUG_ENABLED"):
        issues.append(ValidationIssue("warning", "frontend_debug", "Frontend debug mode should be disabled in production."))

    return StartupValidationReport(tuple(issues))
