"""Flask web application for the cybersecurity log analyzer dashboard."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS

from log_analyzer import DEFAULT_CONFIG, LogAnalyzer
from log_parser import parse_log_lines


app = Flask(__name__)
CORS(app)

ANALYSES: Dict[str, Dict[str, object]] = {}
SAMPLE_LOG = Path(__file__).parent / "sample_logs" / "sample.log"


def analyze_lines(lines: List[str], filename: str, config: Optional[Dict[str, int]] = None) -> str:
    """Parse raw lines, run analysis, and store the report in memory."""
    entries = parse_log_lines(lines)
    analyzer = LogAnalyzer(entries, config=config)
    report = analyzer.report()
    analysis_id = str(uuid.uuid4())
    ANALYSES[analysis_id] = {
        "id": analysis_id,
        "filename": filename,
        "entries": entries,
        "report": report,
        "warnings": {
            "unparseable_lines": report["statistics"]["unparseable_lines"],
            "empty_lines_skipped": sum(1 for line in lines if not line.strip()),
        },
    }
    return analysis_id


def get_analysis_or_error(analysis_id: str):
    """Fetch stored analysis data or return a JSON 404 response tuple."""
    analysis = ANALYSES.get(analysis_id)
    if analysis is None:
        return None, (jsonify({"error": "Analysis ID not found."}), 404)
    return analysis, None


def threshold_config_from_request() -> Dict[str, int]:
    """Read optional anomaly thresholds from query parameters or form fields."""
    config = dict(DEFAULT_CONFIG)
    for key in config:
        value = request.args.get(key) or request.form.get(key)
        if value is None:
            continue
        try:
            config[key] = int(value)
        except ValueError:
            pass
    return config


@app.get("/")
def index():
    """Serve the single-page dashboard frontend."""
    initial_id = next(iter(ANALYSES.keys()), "")
    return render_template("index.html", initial_analysis_id=initial_id)


@app.post("/upload")
def upload():
    """Accept a log file upload, parse it, and store analysis results in memory."""
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "No log file uploaded."}), 400

    raw_bytes = uploaded.read()
    if not raw_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    analysis_id = analyze_lines(lines, uploaded.filename, threshold_config_from_request())
    analysis = ANALYSES[analysis_id]
    return jsonify(
        {
            "analysis_id": analysis_id,
            "filename": analysis["filename"],
            "warnings": analysis["warnings"],
            "statistics": analysis["report"]["statistics"],
        }
    )


@app.post("/sample")
def sample():
    """Analyze the bundled sample log so the dashboard can be explored immediately."""
    if not SAMPLE_LOG.exists():
        return jsonify({"error": "Sample log file is missing."}), 404
    lines = SAMPLE_LOG.read_text(encoding="utf-8").splitlines()
    if not lines:
        return jsonify({"error": "Sample log file is empty."}), 400
    analysis_id = analyze_lines(lines, SAMPLE_LOG.name, threshold_config_from_request())
    analysis = ANALYSES[analysis_id]
    return jsonify(
        {
            "analysis_id": analysis_id,
            "filename": analysis["filename"],
            "warnings": analysis["warnings"],
            "statistics": analysis["report"]["statistics"],
        }
    )


@app.get("/stats/<analysis_id>")
def stats(analysis_id: str):
    """Return statistics and parsed entries for one analysis."""
    analysis, error = get_analysis_or_error(analysis_id)
    if error:
        return error
    report = analysis["report"]
    return jsonify(
        {
            "statistics": report["statistics"],
            "entries": report["entries"],
            "warnings": analysis["warnings"],
            "filename": analysis["filename"],
        }
    )


@app.get("/anomalies/<analysis_id>")
def anomalies(analysis_id: str):
    """Return detected anomalies for one analysis."""
    analysis, error = get_analysis_or_error(analysis_id)
    if error:
        return error
    return jsonify(analysis["report"]["anomalies"])


@app.get("/export/<analysis_id>")
def export(analysis_id: str):
    """Download a full analysis report as JSON or CSV."""
    analysis, error = get_analysis_or_error(analysis_id)
    if error:
        return error

    export_format = request.args.get("format", "json").lower()
    report = analysis["report"]
    if export_format == "json":
        payload = json.dumps(report, indent=2)
        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=analysis-{analysis_id}.json"},
        )

    if export_format == "csv":
        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["section", "ip", "type", "severity", "count", "timestamp", "message", "raw_line"])
        for anomaly in report["anomalies"]:
            writer.writerow([
                "anomaly",
                anomaly["ip"],
                anomaly["type"],
                anomaly["severity"],
                anomaly["count"],
                anomaly["time_window"]["start"],
                anomaly["description"],
                "",
            ])
        for entry in report["entries"]:
            writer.writerow([
                "entry",
                entry["ip_address"] or "",
                entry["source_format"],
                entry["log_level"],
                entry["status_code"] or "",
                entry["timestamp"] or "",
                entry["message"],
                entry["raw_line"],
            ])
        return Response(
            csv_buffer.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=analysis-{analysis_id}.csv"},
        )

    return jsonify({"error": "Unsupported export format. Use csv or json."}), 400


def load_startup_file(argv: List[str]) -> None:
    """Load and analyze a startup file path when provided as a command-line argument."""
    if len(argv) < 2:
        return
    path = Path(argv[1])
    if path.exists() and path.is_file():
        analyze_lines(path.read_text(encoding="utf-8", errors="replace").splitlines(), path.name)


if __name__ == "__main__":
    load_startup_file(sys.argv)
    app.run(debug=True, port=int(os.environ.get("PORT", "5000")))
