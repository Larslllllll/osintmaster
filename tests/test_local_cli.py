import json
from pathlib import Path

from PIL import Image
from typer.testing import CliRunner

from osintmaster import __version__
from osintmaster.cli import app
from osintmaster.core.models import Finding, FindingStatus, Report
from osintmaster.metadata.exif import analyze_metadata
from osintmaster.metadata.image import analyze_image, compare_images


def test_image_hashes_and_metadata(tmp_path):
    first = tmp_path / "a.png"
    second = tmp_path / "b.png"
    Image.new("RGB", (16, 16), "red").save(first)
    Image.new("RGB", (16, 16), "red").save(second)
    a = analyze_image(first)
    assert a["dimensions"] == [16, 16]
    assert len(a["sha256"]) == 64
    comparison = compare_images(first, second)
    assert comparison["exact_sha256_match"] is True
    assert comparison["perceptual_similarity_percent"] == 100
    metadata = analyze_metadata(first, use_exiftool=False)
    assert metadata["format"] == "PNG"
    assert "GPS" in metadata["gps_warning"]


def test_cli_version_dorks_and_image(tmp_path):
    runner = CliRunner()
    assert runner.invoke(app, ["version"]).stdout.strip() == __version__
    dorks = runner.invoke(app, ["dorks", "alex", "--json"])
    assert dorks.exit_code == 0
    assert 'site:github.com "alex"' in json.loads(dorks.stdout)
    image_path = Path(tmp_path) / "image.png"
    Image.new("RGB", (8, 8), "blue").save(image_path)
    result = runner.invoke(app, ["image", str(image_path), "--json"])
    assert result.exit_code == 0, result.output
    assert '"sha256"' in result.stdout
    compare = runner.invoke(app, ["image", "compare", str(image_path), str(image_path), "--json"])
    assert compare.exit_code == 0, compare.output
    assert '"exact_sha256_match": true' in compare.stdout


def test_cli_username_json_and_saved_reports(monkeypatch, tmp_path):
    async def fake_scan(self, target, *, variants=False):
        finding = Finding(
            "Example", target, f"https://example.org/{target}", FindingStatus.CONFIRMED
        )
        return Report(target, [finding], [], ["Example"], [target])

    monkeypatch.setattr("osintmaster.cli.ScanEngine.scan", fake_scan)
    runner = CliRunner()
    result = runner.invoke(app, ["username", "alex", "--json", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["findings"][0]["status"] == "CONFIRMED"
    assert (tmp_path / "alex" / "report.json").is_file()
    assert (tmp_path / "alex" / "report.html").is_file()
    saved = runner.invoke(app, ["report", "alex", "--json", "--output", str(tmp_path)])
    assert saved.exit_code == 0
    assert json.loads(saved.stdout)["target"] == "alex"


def test_cli_username_partial_failure_is_json(monkeypatch, tmp_path):
    async def fake_scan(self, target, *, variants=False):
        finding = Finding(
            "Example",
            target,
            f"https://example.org/{target}",
            FindingStatus.ERROR,
            error="Request timed out",
        )
        return Report(
            target, [finding], [], ["Example"], [target], errors=["Example: Request timed out"]
        )

    monkeypatch.setattr("osintmaster.cli.ScanEngine.scan", fake_scan)
    result = CliRunner().invoke(app, ["username", "alex", "--json", "--output", str(tmp_path)])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["errors"] == ["Example: Request timed out"]


def test_saved_investigation_target_is_literal_terminal_text(monkeypatch, tmp_path):
    def fake_load(self, investigation_id):
        return {
            "target": "[red]forged[/red]\x1b[2J",
            "target_type": "USERNAME",
            "investigation_id": investigation_id,
            "graph": {"nodes": [], "edges": []},
            "limits": {"requests_used": 0},
            "findings": [],
        }

    monkeypatch.setattr("osintmaster.cli.InvestigationStore.load", fake_load)
    result = CliRunner().invoke(app, ["show", "deadbeef", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[red]forged[/red]" in result.stdout
    assert "\x1b" not in result.stdout
