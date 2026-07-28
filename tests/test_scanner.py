import io
import zipfile

from exe_remover_bot_app.config import MAX_ARCHIVE_MEMBERS_TO_SCAN
from exe_remover_bot_app.scanner import scan_file_bytes, scan_filename_only, scanner_selftest_results


def test_scanner_selftests_pass():
    results = scanner_selftest_results()
    assert results
    assert all(ok for _, ok, _ in results), results


def test_normal_zip_folder_is_allowed():
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("documents/readme.txt", b"safe")
    assert scan_file_bytes("documents.zip", "application/zip", payload.getvalue()) is None


def test_dangerous_member_is_blocked():
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("documents/readme.txt", b"safe")
        archive.writestr("hidden/payload.exe", b"MZ")
    result = scan_file_bytes("documents.zip", "application/zip", payload.getvalue())
    assert result is not None
    assert result.reason_code == "archive_contains_dangerous_file"


def test_archive_over_member_limit_is_blocked():
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for index in range(MAX_ARCHIVE_MEMBERS_TO_SCAN + 1):
            archive.writestr(f"safe/{index}.txt", b"ok")
    result = scan_file_bytes("many.zip", "application/zip", payload.getvalue())
    assert result is not None
    assert result.reason_code == "archive_scan_limit_exceeded"


def test_unicode_extension_trick_is_blocked():
    result = scan_filename_only("photo.jpg\u202eexe")
    assert result.blocked
    assert result.reason_code == "unicode_extension_trick"
