from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable

TELEGRAM_DOWNLOAD_LIMIT_BYTES = 20_971_520
MIN_GROUP_FILE_SIZE_BYTES = 64 * 1024
MAX_GROUP_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024

SCANNER_PRESET_IDS = ("standard", "strict", "documents", "media", "custom")
ARCHIVE_POLICIES = ("scan", "block", "allow")
UNSCANNABLE_POLICIES = ("block", "allow")
NOTIFICATION_POLICIES = ("group_and_admins", "admins_only", "group_only", "silent")

DOCUMENT_EXTENSIONS = (
    ".pdf", ".txt", ".csv", ".rtf", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".odt", ".ods", ".odp",
)
MEDIA_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff",
    ".mp3", ".m4a", ".aac", ".wav", ".ogg", ".flac",
    ".mp4", ".mov", ".m4v", ".webm", ".mkv", ".avi",
)

POLICY_DEFAULTS: dict[str, Any] = {
    "scanner_preset": "standard",
    "allowed_only": False,
    "max_file_size_bytes": TELEGRAM_DOWNLOAD_LIMIT_BYTES,
    "archive_policy": "scan",
    "unscannable_policy": "block",
    "notification_policy": "group_and_admins",
    "incident_retention_days": 30,
    "policy_notes": "",
    "policy_updated_at_ms": 0,
    "policy_updated_by": 0,
}


@dataclass(frozen=True, slots=True)
class ScannerPreset:
    id: str
    names: dict[str, str]
    descriptions: dict[str, str]
    settings: dict[str, Any]

    def localized(self, lang: str = "en") -> dict[str, Any]:
        selected = "km" if str(lang).casefold().startswith("km") else "en"
        return {
            "id": self.id,
            "name": self.names.get(selected, self.names["en"]),
            "description": self.descriptions.get(selected, self.descriptions["en"]),
            "settings": copy.deepcopy(self.settings),
        }


SCANNER_PRESETS: dict[str, ScannerPreset] = {
    "standard": ScannerPreset(
        id="standard",
        names={"en": "Standard", "km": "ស្តង់ដារ"},
        descriptions={
            "en": "Balanced protection for most groups. Blocks executables and suspicious payloads while allowing normal documents and media.",
            "km": "ការការពារសមតុល្យសម្រាប់ក្រុមភាគច្រើន។ ទប់ស្កាត់ឯកសារដំណើរការ និងឯកសារសង្ស័យ ខណៈអនុញ្ញាតឯកសារ និងមេឌៀធម្មតា។",
        },
        settings={
            "scanner_preset": "standard",
            "strictness": "standard",
            "allowed_only": False,
            "allowed_extensions": [],
            "custom_blocked_extensions": [],
            "archive_policy": "scan",
            "unscannable_policy": "block",
            "max_file_size_bytes": TELEGRAM_DOWNLOAD_LIMIT_BYTES,
            "auto_action_mode": "off",
            "notification_policy": "group_and_admins",
        },
    ),
    "strict": ScannerPreset(
        id="strict",
        names={"en": "Strict Security", "km": "សុវត្ថិភាពតឹងរ៉ឹង"},
        descriptions={
            "en": "Maximum protection for public or high-risk groups, including archive blocking and automatic escalation.",
            "km": "ការការពារខ្ពស់បំផុតសម្រាប់ក្រុមសាធារណៈ ឬក្រុមមានហានិភ័យខ្ពស់ រួមទាំងទប់ស្កាត់ Archive និងចាត់វិធានការស្វ័យប្រវត្តិ។",
        },
        settings={
            "scanner_preset": "strict",
            "strictness": "strict",
            "allowed_only": False,
            "allowed_extensions": [],
            "custom_blocked_extensions": [],
            "archive_policy": "block",
            "unscannable_policy": "block",
            "max_file_size_bytes": TELEGRAM_DOWNLOAD_LIMIT_BYTES,
            "auto_action_mode": "smart",
            "auto_warn_threshold": 1,
            "auto_mute_threshold": 2,
            "auto_ban_threshold": 3,
            "notification_policy": "group_and_admins",
        },
    ),
    "documents": ScannerPreset(
        id="documents",
        names={"en": "Documents Only", "km": "អនុញ្ញាតតែឯកសារ"},
        descriptions={
            "en": "Allows common office and text documents only. Other file types are removed.",
            "km": "អនុញ្ញាតតែឯកសារ Office និងអត្ថបទដែលប្រើជាទូទៅ។ ប្រភេទឯកសារផ្សេងទៀតនឹងត្រូវលុប។",
        },
        settings={
            "scanner_preset": "documents",
            "strictness": "high",
            "allowed_only": True,
            "allowed_extensions": list(DOCUMENT_EXTENSIONS),
            "custom_blocked_extensions": [],
            "archive_policy": "block",
            "unscannable_policy": "block",
            "max_file_size_bytes": TELEGRAM_DOWNLOAD_LIMIT_BYTES,
            "auto_action_mode": "warn",
            "notification_policy": "group_and_admins",
        },
    ),
    "media": ScannerPreset(
        id="media",
        names={"en": "Media Only", "km": "អនុញ្ញាតតែមេឌៀ"},
        descriptions={
            "en": "Allows common image, audio, and video files only. Documents and archives are removed.",
            "km": "អនុញ្ញាតតែរូបភាព សំឡេង និងវីដេអូដែលប្រើជាទូទៅ។ ឯកសារ និង Archive នឹងត្រូវលុប។",
        },
        settings={
            "scanner_preset": "media",
            "strictness": "high",
            "allowed_only": True,
            "allowed_extensions": list(MEDIA_EXTENSIONS),
            "custom_blocked_extensions": [],
            "archive_policy": "block",
            "unscannable_policy": "block",
            "max_file_size_bytes": TELEGRAM_DOWNLOAD_LIMIT_BYTES,
            "auto_action_mode": "warn",
            "notification_policy": "group_and_admins",
        },
    ),
    "custom": ScannerPreset(
        id="custom",
        names={"en": "Custom", "km": "កំណត់ផ្ទាល់ខ្លួន"},
        descriptions={
            "en": "Use your own formats, limits, notification behavior, and escalation rules.",
            "km": "កំណត់ Format ទំហំឯកសារ ការជូនដំណឹង និងច្បាប់ចាត់វិធានការដោយខ្លួនឯង។",
        },
        settings={"scanner_preset": "custom"},
    ),
}


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def normalize_policy_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Normalize v3.5 policy values in-place and return the same dictionary."""
    for key, value in POLICY_DEFAULTS.items():
        if key not in settings:
            settings[key] = copy.deepcopy(value)

    preset = str(settings.get("scanner_preset") or "custom").strip().casefold()
    settings["scanner_preset"] = preset if preset in SCANNER_PRESET_IDS else "custom"
    settings["allowed_only"] = bool(settings.get("allowed_only", False))

    max_size = _safe_int(settings.get("max_file_size_bytes"), TELEGRAM_DOWNLOAD_LIMIT_BYTES)
    settings["max_file_size_bytes"] = max(MIN_GROUP_FILE_SIZE_BYTES, min(MAX_GROUP_FILE_SIZE_BYTES, max_size))

    archive_policy = str(settings.get("archive_policy") or "scan").strip().casefold()
    settings["archive_policy"] = archive_policy if archive_policy in ARCHIVE_POLICIES else "scan"

    unscannable = str(settings.get("unscannable_policy") or "block").strip().casefold()
    settings["unscannable_policy"] = unscannable if unscannable in UNSCANNABLE_POLICIES else "block"

    notifications = str(settings.get("notification_policy") or "group_and_admins").strip().casefold()
    settings["notification_policy"] = notifications if notifications in NOTIFICATION_POLICIES else "group_and_admins"

    settings["incident_retention_days"] = max(1, min(3650, _safe_int(settings.get("incident_retention_days"), 30)))
    settings["policy_notes"] = str(settings.get("policy_notes") or "").strip()[:500]
    settings["policy_updated_at_ms"] = max(0, _safe_int(settings.get("policy_updated_at_ms"), 0))
    settings["policy_updated_by"] = max(0, _safe_int(settings.get("policy_updated_by"), 0))
    return settings


def scanner_presets_catalog(lang: str = "en") -> list[dict[str, Any]]:
    return [SCANNER_PRESETS[preset_id].localized(lang) for preset_id in SCANNER_PRESET_IDS]


def apply_scanner_preset(settings: dict[str, Any], preset_id: str) -> list[str]:
    normalized_id = str(preset_id or "").strip().casefold()
    preset = SCANNER_PRESETS.get(normalized_id)
    if preset is None:
        raise ValueError(f"unknown scanner preset: {preset_id}")

    changed: list[str] = []
    for key, value in preset.settings.items():
        new_value = copy.deepcopy(value)
        if settings.get(key) != new_value:
            settings[key] = new_value
            changed.append(key)
    normalize_policy_settings(settings)
    return changed


def detect_scanner_preset(settings: dict[str, Any]) -> str:
    """Return the matching preset, otherwise custom.

    Metadata fields and admin-specific options are intentionally ignored.
    """
    for preset_id in ("standard", "strict", "documents", "media"):
        preset = SCANNER_PRESETS[preset_id]
        if all(settings.get(key) == value for key, value in preset.settings.items()):
            return preset_id
    return "custom"


def is_archive_name(file_name: str, archive_extensions: Iterable[str]) -> bool:
    lower = str(file_name or "").casefold().strip()
    return any(lower.endswith(str(ext).casefold()) for ext in archive_extensions)
