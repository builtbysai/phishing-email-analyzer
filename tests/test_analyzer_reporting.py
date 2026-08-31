import json
import subprocess
import sys
from pathlib import Path

from phishing_email_analyzer.analyzer import analyze_email, analyze_path, risk_level, score_findings
from phishing_email_analyzer.models import Finding
from phishing_email_analyzer.reporting import build_batch_payload, render_html_report, write_json_report

from .helpers import make_message


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "sample_emails"


def test_risk_level_boundaries():
    assert risk_level(0) == "low"
    assert risk_level(20) == "moderate"
    assert risk_level(50) == "high"
    assert risk_level(75) == "critical"


def test_score_is_capped_at_100():
    finding = Finding("rule", "Test", "Title", "Explanation", 60)
    assert score_findings([finding, finding]) == 100


def test_analyze_email_combines_rule_categories():
    message = make_message(
        sender="PayPal Security <alerts@paypa1.top>",
        body="Act now. Verify your account at https://paypa1.com/login",
    )
    message["Authentication-Results"] = "mx.example; spf=fail; dkim=fail; dmarc=fail"
    analysis = analyze_email(message, "synthetic.eml")
    assert analysis.risk_level == "critical"
    assert {finding.category for finding in analysis.findings} == {"Headers", "URLs", "Content"}


def test_batch_payload_has_summary_counts():
    analyses = analyze_path(SAMPLES)
    payload = build_batch_payload(analyses)
    assert payload["summary"]["emails_analyzed"] == 7
    assert sum(payload["summary"]["risk_levels"].values()) == 7


def test_sample_batch_contains_clean_and_phishing_messages():
    analyses = analyze_path(SAMPLES)
    levels = {analysis.risk_level for analysis in analyses}
    assert "low" in levels
    assert "critical" in levels
    assert len(analyses) == 7


def test_json_report_is_valid_and_complete(tmp_path):
    analyses = analyze_path(SAMPLES)
    output = tmp_path / "report.json"
    write_json_report(analyses, output)
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert len(data["emails"]) == 7
    assert all("findings" in item for item in data["emails"])


def test_html_report_escapes_message_values():
    message = make_message(subject="<script>alert('x')</script>")
    html = render_html_report([analyze_email(message)])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_html_report_has_no_external_assets_or_clickable_urls():
    analyses = analyze_path(SAMPLES)
    html = render_html_report(analyses)
    assert "<style>" in html
    assert "<link " not in html
    assert "<script" not in html
    assert '<a href="http' not in html


def test_cli_end_to_end(tmp_path):
    html_path = tmp_path / "batch.html"
    json_path = tmp_path / "batch.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "phishing_email_analyzer",
            str(SAMPLES),
            "--html",
            str(html_path),
            "--json",
            str(json_path),
        ],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Analyzed 7 email(s)" in result.stdout
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert len(json.loads(json_path.read_text(encoding="utf-8"))["emails"]) == 7
