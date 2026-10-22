import json
import re
import unittest

from skill_dist_check.report import render_html


class ReportTests(unittest.TestCase):
    def test_hostile_paths_cannot_escape_json_element(self):
        report = {"schema": "skill-dist-check/report-v1", "operation": "check", "status": "pass",
                  "manifest": {"files": [{"path": '</script><img src=x onerror="alert(1)">',
                                          "size": 0, "sha256": "0" * 64}], "payload_sha256": "0" * 64}}
        html = render_html(report)
        embedded = re.search(r'<script type="application/json" id="report-data">(.*?)</script>', html, re.S)
        self.assertIsNotNone(embedded)
        self.assertNotIn("<", embedded[1])
        self.assertEqual(json.loads(embedded[1]), report)
        self.assertIn("connect-src 'none'", html)

    def test_renderer_is_deterministic_and_contains_no_external_assets(self):
        report = {"schema": "skill-dist-check/report-v1", "operation": "check", "status": "pass"}
        html = render_html(report)
        self.assertEqual(html, render_html(report))
        self.assertNotRegex(html, r'<script[^>]+src=')
        self.assertNotIn("innerHTML", html)
        self.assertNotIn("__REPORT_DATA__", html)


if __name__ == "__main__":
    unittest.main()
