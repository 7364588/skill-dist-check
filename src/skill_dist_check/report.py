"""Render an offline report. Input values are data, never markup or script."""

import json
from importlib.resources import files


def render_html(report: dict) -> str:
    payload = json.dumps(report, ensure_ascii=True, separators=(",", ":"))
    # Prevent terminating the inert JSON script element, including hostile filenames.
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    template = files("skill_dist_check").joinpath("report.html").read_text(encoding="utf-8")
    return template.replace("__REPORT_DATA__", payload)
