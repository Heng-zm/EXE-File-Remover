from exe_remover_bot_app.startup import validate_startup_config


def valid_config():
    return {
        "BOT_TOKEN": "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcd",
        "BOT_MODE": "WEBHOOK",
        "WEBHOOK_BASE_URL": "https://example.com",
        "WEBHOOK_SECRET_TOKEN": "a" * 32,
        "WEBHOOK_PATH_SECRET": "b" * 32,
        "WEBHOOK_URL_PATH": "tg-webhook/" + "b" * 32,
        "REDIS_ENABLED": True,
        "REDIS_URL": "rediss://redis.example.com:6379",
        "SUPABASE_ENABLED": False,
        "LOCAL_PERSISTENCE_ENABLED": False,
        "MINI_APP_API_ENABLED": True,
        "MINI_APP_CORS_ORIGINS": ["https://app.example.com"],
        "SERVER_LOG_PUBLIC_ACCESS": False,
        "SERVER_LOG_AUTH_QUERY_ENABLED": False,
    }


def test_valid_startup_config_has_no_errors():
    report = validate_startup_config(valid_config(), available_dependencies={"fastapi", "uvicorn"})
    assert report.ok, report.errors


def test_reused_webhook_secret_is_rejected():
    config = valid_config()
    config["WEBHOOK_PATH_SECRET"] = config["WEBHOOK_SECRET_TOKEN"]
    report = validate_startup_config(config, available_dependencies={"fastapi", "uvicorn"})
    assert any(issue.code == "webhook_secret_reuse" for issue in report.errors)


def test_missing_durable_backend_warns_not_crashes():
    config = valid_config()
    config["BOT_MODE"] = "POLLING"
    config["REDIS_ENABLED"] = False
    config["REDIS_URL"] = ""
    report = validate_startup_config(config)
    assert report.ok
    assert any(issue.code == "memory_only" for issue in report.warnings)


def test_example_placeholders_are_rejected():
    config = valid_config()
    config["BOT_TOKEN"] = "123456789:replace_with_real_botfather_token"
    config["WEBHOOK_SECRET_TOKEN"] = "replace_with_random_header_secret_32_chars"
    config["WEBHOOK_PATH_SECRET"] = "replace_with_different_random_path_secret"
    report = validate_startup_config(config, available_dependencies={"fastapi", "uvicorn"})
    codes = {issue.code for issue in report.errors}
    assert "bot_token" in codes
    assert "webhook_secrets" in codes
