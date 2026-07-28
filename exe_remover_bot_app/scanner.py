from __future__ import annotations

import io
import logging
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from html import escape as html_escape
from typing import Iterable

from .config import (
    ARCHIVE_EXTENSIONS,
    BLOCKED_EXTENSIONS,
    BLOCKED_MIME_TYPES,
    DANGEROUS_EXTENSIONS,
    MAX_ARCHIVE_MEMBERS_TO_SCAN,
    SUSPICIOUS_ARCHIVE_SCAN_ENABLED,
    SUSPICIOUS_SCANNER_ENABLED,
    _normalize_extension,
)

logger = logging.getLogger("exe_remover_bot.scanner")


@dataclass(frozen=True, slots=True)
class FileScanResult:
    blocked: bool
    reason_code: str
    reason_display: str
    details: tuple[str, ...]
    file_name: str
    mime_type: str
    matched_extension: str = ""
    file_sha256: str = ""


def h(value: object) -> str:
    return html_escape(str(value), quote=False)

def normalize_filename(name: str | None) -> str:
    if not name:
        return "Unknown"
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", "", name).strip()
    return cleaned or "Unknown"


SUSPICIOUS_UNICODE_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
}


def visible_controls_removed(name: str) -> str:
    cleaned_chars: list[str] = []
    for char in name:
        # Remove invisible formatting controls that can reverse or hide extensions.
        if char in SUSPICIOUS_UNICODE_CONTROLS or unicodedata.category(char) == "Cf":
            continue
        cleaned_chars.append(char)
    return "".join(cleaned_chars)


def compact_scan_name(name: str | None) -> str:
    normalized = normalize_filename(name)
    normalized = visible_controls_removed(normalized)
    normalized = normalized.replace("\\", "/").split("/")[-1]
    normalized = re.sub(r"\s+", " ", normalized).strip().rstrip(" .")
    return normalized or "Unknown"


_SUFFIX_TOKEN_RE = re.compile(r"^[a-z0-9_+-]{1,16}$")


def filename_suffixes(file_name: str) -> list[str]:
    """Return safe suffix candidates while preserving compound extensions.

    Examples:
    - archive.tar.gz -> [".tar.gz", ".gz"] instead of [".tar", ".gz"]
    - invoice.pdf.exe.zip -> includes ".exe" and keeps the true final suffix ".zip" last

    The last item is always the true final suffix when one exists. Compound
    candidates come first so custom blocklists such as .tar.gz can match.
    """
    clean_name = compact_scan_name(file_name).casefold()
    if "." not in clean_name:
        return []

    raw_parts = clean_name.split(".")
    ext_parts = raw_parts[1:]
    if not ext_parts or any(part == "" for part in ext_parts):
        candidates = [f".{part}" for part in ext_parts if _SUFFIX_TOKEN_RE.fullmatch(part)]
        return list(dict.fromkeys(_normalize_extension(ext) for ext in candidates))

    ext_parts = [part for part in ext_parts if _SUFFIX_TOKEN_RE.fullmatch(part)]
    if not ext_parts:
        return []

    final_ext = f".{ext_parts[-1]}"
    candidates: list[str] = []

    # Compound endings, excluding the final single suffix which is appended last.
    for start in range(0, max(len(ext_parts) - 1, 0)):
        compound = "." + ".".join(ext_parts[start:])
        if 2 <= len(compound) <= 64:
            candidates.append(compound)

    # Include individual non-final suffixes so invoice.exe.zip and
    # invoice.pdf.exe.zip both catch the hidden .exe before the archive suffix.
    # Harmless compound archives such as .tar.gz remain safe because .tar is not
    # in DANGEROUS_EXTENSIONS by default.
    if len(ext_parts) >= 2:
        for part in ext_parts[:-1]:
            candidates.append(f".{part}")

    candidates.append(final_ext)
    return list(dict.fromkeys(_normalize_extension(ext) for ext in candidates))


def describe_scan_reason(reason_code: str, details: Iterable[str]) -> str:
    detail_text = "; ".join(str(d) for d in details if str(d).strip())
    return h(detail_text or reason_code.replace("_", " "))


def scan_filename_only(file_name: str | None, mime_type: str | None = None) -> FileScanResult:
    original_name = normalize_filename(file_name)
    without_unicode_controls = visible_controls_removed(original_name)
    clean_name = compact_scan_name(without_unicode_controls)
    lower_name = clean_name.casefold()
    mime = (mime_type or "").casefold().strip()
    suffixes = filename_suffixes(clean_name)
    details: list[str] = []

    # Compare before basename/path cleanup so ordinary ZIP folders such as
    # safe/readme.txt are not mistaken for Unicode filename tricks.
    had_unicode_trick = without_unicode_controls != original_name
    if had_unicode_trick:
        details.append("filename contains invisible Unicode control characters")

    # 1) Direct hard block extensions, including setup.exe and setup.exe.
    for ext in BLOCKED_EXTENSIONS:
        if lower_name.endswith(ext):
            return FileScanResult(True, "blocked_extension", f"blocked extension {ext}", tuple(details + [f"matched {ext}"]), clean_name, mime, ext)

    # 2) Suspicious scanner checks: dangerous extensions and misleading names.
    if SUSPICIOUS_SCANNER_ENABLED:
        dangerous_in_name = [ext for ext in suffixes if ext in DANGEROUS_EXTENSIONS]
        last_ext = suffixes[-1] if suffixes else ""

        if dangerous_in_name:
            matched = dangerous_in_name[-1]
            if last_ext == matched:
                return FileScanResult(True, "dangerous_extension", f"dangerous extension {matched}", tuple(details + [f"matched {matched}"]), clean_name, mime, matched)
            if last_ext in ARCHIVE_EXTENSIONS:
                return FileScanResult(True, "dangerous_inside_archive_name", f"dangerous extension {matched} hidden before archive suffix {last_ext}", tuple(details + [f"suffix chain: {' '.join(suffixes)}"]), clean_name, mime, matched)
            return FileScanResult(True, "misleading_double_extension", f"dangerous extension {matched} hidden inside filename", tuple(details + [f"suffix chain: {' '.join(suffixes)}"]), clean_name, mime, matched)

        # Names like "invoice.pdf________________________.exe" are already caught above;
        # this catches misleading long extension chains without a dangerous suffix.
        if len(suffixes) >= 3 and last_ext in ARCHIVE_EXTENSIONS:
            details.append(f"long archive suffix chain: {' '.join(suffixes)}")

        if had_unicode_trick:
            return FileScanResult(True, "unicode_extension_trick", "filename contains invisible Unicode extension-trick characters", tuple(details), clean_name, mime)

    # 3) MIME block list from Telegram metadata.
    if mime and mime in BLOCKED_MIME_TYPES:
        return FileScanResult(True, "blocked_mime", f"blocked MIME type {mime}", tuple(details + [f"mime {mime}"]), clean_name, mime)

    return FileScanResult(False, "clean", "no suspicious filename or MIME match", tuple(details), clean_name, mime)


def scan_file_bytes(file_name: str, mime_type: str, data: bytes) -> FileScanResult | None:
    if not data:
        return None

    details: list[str] = []
    lower_name = compact_scan_name(file_name).casefold()

    try:
        if data.startswith(b"MZ"):
            return FileScanResult(True, "pe_magic_header", "file content starts with Windows executable MZ header", ("matched MZ header",), file_name, mime_type, ".exe")
        if data.startswith(b"\x7fELF"):
            return FileScanResult(True, "elf_magic_header", "file content starts with ELF executable header", ("matched ELF header",), file_name, mime_type)
        if data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
            return FileScanResult(True, "macho_magic_header", "file content starts with Mach-O executable header", ("matched Mach-O header",), file_name, mime_type)
        if data.startswith(b"#!") and any(token in data[:256].lower() for token in (b"/sh", b"bash", b"python", b"node", b"powershell", b"cmd")):
            return FileScanResult(True, "script_shebang", "file content starts with executable script shebang", ("matched script shebang",), file_name, mime_type)
    except Exception:
        logger.exception("Magic-byte scan failed for %r", file_name, exc_info=True)
        return None

    if not SUSPICIOUS_ARCHIVE_SCAN_ENABLED:
        return None

    suffixes = filename_suffixes(lower_name)
    may_be_zip = data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08") or (suffixes and suffixes[-1] == ".zip")
    if may_be_zip:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = zf.namelist()
                if len(names) > MAX_ARCHIVE_MEMBERS_TO_SCAN:
                    return FileScanResult(
                        True,
                        "archive_scan_limit_exceeded",
                        "archive contains too many members to scan safely",
                        (f"members:{len(names)}", f"limit:{MAX_ARCHIVE_MEMBERS_TO_SCAN}"),
                        file_name,
                        mime_type,
                    )
        except (zipfile.BadZipFile, RuntimeError, OSError):
            logger.info("Archive scan skipped for non-readable ZIP file %r", file_name)
            return None

        for member in names:
            try:
                result = scan_filename_only(member, "")
            except Exception:
                logger.exception("Archive member scan failed for %r in %r", member, file_name, exc_info=True)
                continue
            if result.blocked:
                details.append(f"archive contains suspicious member: {member}")
                return FileScanResult(
                    True,
                    "archive_contains_dangerous_file",
                    f"archive contains dangerous file name: {member}",
                    tuple(details),
                    file_name,
                    mime_type,
                    result.matched_extension,
                )

    return None




def scanner_selftest_results() -> list[tuple[str, bool, str]]:
    """Run lightweight scanner checks that do not call Telegram APIs."""
    results: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        results.append((name, bool(ok), detail))

    r = scan_filename_only("invoice.pdf.exe")
    add("block direct .exe", r.blocked and r.reason_code == "blocked_extension", r.reason_code)

    r = scan_filename_only("invoice.exe.zip")
    add("block hidden .exe before archive", r.blocked and r.matched_extension == ".exe", r.reason_code)

    r = scan_filename_only("safe-report.pdf")
    add("allow normal PDF name", not r.blocked, r.reason_code)

    r = scan_file_bytes("renamed.bin", "application/octet-stream", b"MZ" + b"0" * 32)
    add("block PE magic header", bool(r and r.blocked and r.reason_code == "pe_magic_header"), r.reason_code if r else "no-result")

    safe_archive = io.BytesIO()
    with zipfile.ZipFile(safe_archive, "w") as zf:
        zf.writestr("safe/readme.txt", b"ok")
    r = scan_file_bytes("safe-bundle.zip", "application/zip", safe_archive.getvalue())
    add("allow normal ZIP folder paths", r is None, r.reason_code if r else "clean")

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe/readme.txt", b"ok")
        zf.writestr("payload.exe", b"fake")
    r = scan_file_bytes("bundle.zip", "application/zip", archive.getvalue())
    add("block dangerous ZIP member", bool(r and r.blocked and r.reason_code == "archive_contains_dangerous_file"), r.reason_code if r else "no-result")

    oversized_archive = io.BytesIO()
    with zipfile.ZipFile(oversized_archive, "w") as zf:
        for index in range(MAX_ARCHIVE_MEMBERS_TO_SCAN + 1):
            zf.writestr(f"safe/{index}.txt", b"ok")
    r = scan_file_bytes("large-index.zip", "application/zip", oversized_archive.getvalue())
    add("block ZIP beyond scan member limit", bool(r and r.reason_code == "archive_scan_limit_exceeded"), r.reason_code if r else "no-result")

    return results




__all__ = [
    "FileScanResult", "normalize_filename", "visible_controls_removed",
    "compact_scan_name", "filename_suffixes", "describe_scan_reason",
    "scan_filename_only", "scan_file_bytes", "scanner_selftest_results",
]
