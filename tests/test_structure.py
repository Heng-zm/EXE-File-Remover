from pathlib import Path


def test_entrypoint_is_thin_and_modules_exist():
    root = Path(__file__).resolve().parents[1]
    entrypoint = (root / "exe_remover_bot.py").read_text(encoding="utf-8")
    assert len(entrypoint.splitlines()) <= 10
    for module in ("config.py", "diagnostics.py", "incidents.py", "policies.py", "retry.py", "scanner.py", "schema.py", "startup.py", "translations.py", "workflow.py", "miniapp_api.py", "bot.py"):
        assert (root / "exe_remover_bot_app" / module).is_file()


def test_runtime_is_smaller_than_previous_monolith():
    root = Path(__file__).resolve().parents[1]
    runtime_lines = len((root / "exe_remover_bot_app" / "bot.py").read_text(encoding="utf-8").splitlines())
    assert runtime_lines < 7300
