"""Build a standalone synthetic installation-drift report in docs/."""

import json
from pathlib import Path

from skill_dist_check.audit import audit_files
from skill_dist_check.bundle import collect, compare_files, make_manifest
from skill_dist_check.report import render_html

root = Path(__file__).resolve().parents[1]
payload = collect(root / "examples/release-notes")
installed = dict(payload)
installed.pop("references/format.md")
installed["SKILL.md"] += b"\nInstallation-specific edit.\n"
installed["notes.txt"] = b"Synthetic extra file.\n"
report = {
    "schema": "skill-dist-check/report-v1", "operation": "verify", "status": "fail", "demo": True,
    "manifest": make_manifest(payload), "audit": audit_files(payload),
    "installed_audit": audit_files(installed), "diff": compare_files(payload, installed),
}
destination = root / "docs"
destination.mkdir(exist_ok=True)
(destination / "index.html").write_text(render_html(report), encoding="utf-8", newline="\n")
(destination / "demo.json").write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
print("Built synthetic demo: docs/index.html")
