import json

import pytest

from osintmaster.config import load_config
from osintmaster.core.models import Correlation, Evidence, Finding, FindingStatus, Report
from osintmaster.reports.html_report import render_html, save_html
from osintmaster.reports.json_report import load_report, save_json


def test_config_file_and_validation(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        'timeout = 8\nreports_dir = "./reports"\n[providers]\nsherlock = true\n', encoding="utf-8"
    )
    config = load_config(config_file)
    assert config.timeout == 8
    assert config.sherlock
    assert config.reports_dir == tmp_path / "reports"
    config_file.write_text("max_concurrency = 999\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(config_file)
    config_file.write_text("timeout = [broken\n", encoding="utf-8")
    with pytest.raises(ValueError, match="TOML"):
        load_config(config_file)


def test_json_and_html_reports_escape_public_content(tmp_path):
    finding = Finding("Example", "alex", "https://example.org/alex", FindingStatus.CONFIRMED)
    finding.profile.bio = "<script>alert(1)</script>"
    correlation = Correlation(
        "https://a", "https://b", 10, "weak", [Evidence("exact_username", "alex", 10, "Example")]
    )
    report = Report("alex", [finding], [correlation], ["Example"], ["alex"])
    json_path = save_json(report, tmp_path)
    html_path = save_html(report, tmp_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))["target"] == "alex"
    assert load_report(tmp_path, "alex")["findings"][0]["status"] == "CONFIRMED"
    html = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "<script>" not in html
    assert "<script>" not in render_html(report)


def test_report_path_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        load_report(tmp_path, "../secret")
