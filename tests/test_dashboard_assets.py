from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "exe_remover_bot_app" / "static"


def test_dashboard_assets_are_packaged_without_a_build_step():
    required = ["index.html", "styles.css", "api.js", "i18n.js", "app.js"]
    for name in required:
        path = STATIC / name
        assert path.is_file(), name
        assert path.stat().st_size > 200, name


def test_dashboard_contains_full_administration_sections_and_khmer_copy():
    app_source = (STATIC / "app.js").read_text(encoding="utf-8")
    translations = (STATIC / "i18n.js").read_text(encoding="utf-8")
    for feature in ("renderPolicies", "renderIncidents", "renderFormats", "renderTrusted", "renderWorkflow", "renderAdministration"):
        assert feature in app_source
    assert "គោលការណ៍ជាក់លាក់សម្រាប់ក្រុម" in translations
    assert "ករណីល្មើស" in translations
    assert "មជ្ឈមណ្ឌលលំហូរការងារ" in translations


def test_dashboard_uses_runtime_api_prefix_configuration():
    index = (STATIC / "index.html").read_text(encoding="utf-8")
    api_source = (STATIC / "api.js").read_text(encoding="utf-8")
    assert "/app/config.js" in index
    assert "__EXE_REMOVER_CONFIG__" in api_source
    assert "apiPath(" in api_source
