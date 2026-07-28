from __future__ import annotations

from exe_remover_bot_app.policies import (
    SCANNER_PRESET_IDS,
    apply_scanner_preset,
    detect_scanner_preset,
    normalize_policy_settings,
    scanner_presets_catalog,
)


def test_preset_catalog_is_localized_and_complete():
    english = scanner_presets_catalog("en")
    khmer = scanner_presets_catalog("km")
    assert [item["id"] for item in english] == list(SCANNER_PRESET_IDS)
    assert [item["id"] for item in khmer] == list(SCANNER_PRESET_IDS)
    assert english[0]["name"] != khmer[0]["name"]
    assert all(item["description"] for item in khmer)


def test_apply_and_detect_scanner_presets():
    settings: dict[str, object] = {}
    changed = apply_scanner_preset(settings, "documents")
    assert "allowed_extensions" in changed
    assert settings["scanner_preset"] == "documents"
    assert settings["allowed_only"] is True
    assert ".pdf" in settings["allowed_extensions"]
    assert detect_scanner_preset(settings) == "documents"

    settings["archive_policy"] = "scan"
    assert detect_scanner_preset(settings) == "custom"


def test_policy_normalization_rejects_invalid_values_safely():
    settings = {
        "scanner_preset": "unknown",
        "max_file_size_bytes": -1,
        "archive_policy": "explode",
        "unscannable_policy": "maybe",
        "notification_policy": "everyone",
        "incident_retention_days": 0,
        "policy_notes": "x" * 1000,
    }
    normalize_policy_settings(settings)
    assert settings["scanner_preset"] == "custom"
    assert settings["max_file_size_bytes"] >= 65536
    assert settings["archive_policy"] == "scan"
    assert settings["unscannable_policy"] == "block"
    assert settings["notification_policy"] == "group_and_admins"
    assert settings["incident_retention_days"] == 1
    assert len(settings["policy_notes"]) == 500


def test_runtime_group_policy_enforces_allowlist_size_and_archives():
    from test_runtime_integration import _load_runtime

    bot = _load_runtime()
    bot_data: dict = {}
    settings = bot.get_group_settings(bot_data, -1001)
    settings.update(
        {
            "scanner_preset": "custom",
            "allowed_only": True,
            "allowed_extensions": [".pdf"],
            "max_file_size_bytes": 1_000_000,
            "archive_policy": "block",
            "strictness": "high",
        }
    )

    clean_png = bot.FileScanResult(False, "clean", "clean", (), "photo.png", "image/png", ".png")
    result = bot.apply_group_scan_policy(bot_data, -1001, clean_png, file_size=10_000)
    assert result.blocked is True
    assert result.reason_code == "group_allowlist_only"

    clean_pdf = bot.FileScanResult(False, "clean", "clean", (), "report.pdf", "application/pdf", ".pdf")
    result = bot.apply_group_scan_policy(bot_data, -1001, clean_pdf, file_size=2_000_000)
    assert result.blocked is True
    assert result.reason_code == "group_max_file_size"

    clean_zip = bot.FileScanResult(False, "clean", "clean", (), "archive.zip", "application/zip", ".zip")
    result = bot.apply_group_scan_policy(bot_data, -1001, clean_zip, file_size=100_000)
    assert result.blocked is True
    assert result.reason_code == "group_archive_blocked"
