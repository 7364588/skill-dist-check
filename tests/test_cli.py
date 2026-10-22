"""Process-level CLI regressions for failure delivery and read-only comparisons."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import skill_dist_check
from skill_dist_check import cli
from skill_dist_check.bundle import pack, read_bundle


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.skill = self.root / "skill"
        self.skill.mkdir()
        (self.skill / "SKILL.md").write_text("# Synthetic changelog skill\n\n[Guide](guide.md)\n", encoding="utf-8")
        (self.skill / "guide.md").write_text("# Formatting guide\n", encoding="utf-8")
        self.archive = self.root / "release.zip"
        pack(self.skill, self.archive)

    def environment(self, unbuffered=False):
        env = dict(os.environ)
        # Also works when CI is exercising a built and installed wheel.
        env["PYTHONPATH"] = str(Path(skill_dist_check.__file__).resolve().parent.parent)
        if unbuffered:
            env["PYTHONUNBUFFERED"] = "1"
        else:
            env.pop("PYTHONUNBUFFERED", None)
        return env

    def command(self, *args):
        return [sys.executable, "-m", "skill_dist_check", *map(str, args)]

    def run_cli(self, *args):
        return subprocess.run(self.command(*args), cwd=self.root, env=self.environment(),
                              capture_output=True, text=True, encoding="utf-8", timeout=30)

    def closed_pipe(self, args, stream, unbuffered):
        reader, writer = os.pipe()
        os.close(reader)
        capture = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        capture[stream] = writer
        try:
            process = subprocess.Popen(self.command(*args), cwd=self.root,
                                       env=self.environment(unbuffered), **capture)
        finally:
            os.close(writer)
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        return process.returncode, (stdout or b"") + (stderr or b"")

    def test_closed_stdout_is_exit_two_without_shutdown_traceback(self):
        cases = [
            ("check", self.skill),
            ("check", self.skill, "--format", "json"),
            ("verify", self.root / "missing.zip", "--format", "json"),
            ("--help",),
            ("--version",),
        ]
        for unbuffered in (False, True):
            for args in cases:
                with self.subTest(unbuffered=unbuffered, args=args):
                    code, visible = self.closed_pipe(args, "stdout", unbuffered)
                    self.assertEqual(code, 2, visible)
                    self.assertNotIn(b"Traceback", visible)
                    self.assertNotIn(b"Exception ignored", visible)

    def test_closed_stderr_is_exit_two_for_usage_and_input_errors(self):
        cases = [(), ("unknown-command",), ("verify", self.root / "missing.zip")]
        for unbuffered in (False, True):
            for args in cases:
                with self.subTest(unbuffered=unbuffered, args=args):
                    code, visible = self.closed_pipe(args, "stderr", unbuffered)
                    self.assertEqual(code, 2, visible)
                    self.assertEqual(visible, b"")

    def test_missing_installed_skill_is_removed_file_not_input_failure(self):
        (self.skill / "SKILL.md").unlink()
        result = self.run_cli("verify", self.archive, "--directory", self.skill, "--format", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["diff"]["removed"], ["SKILL.md"])
        self.assertFalse(report["installed_audit"]["ok"])

    def test_html_cannot_modify_a_checked_or_compared_directory(self):
        before = {path.name: path.read_bytes() for path in self.skill.iterdir()}
        new_archive = self.root / "new-release.zip"
        for args in [
            ("check", self.skill),
            ("pack", self.skill, "--output", new_archive),
            ("verify", self.archive, "--directory", self.skill),
        ]:
            with self.subTest(command=args[0]):
                result = self.run_cli(*args, "--html", self.skill / "report.html", "--format", "json")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertEqual(before, {path.name: path.read_bytes() for path in self.skill.iterdir()})
                self.assertFalse(new_archive.exists())

    def test_output_errors_omit_raw_paths_and_preserve_existing_reports(self):
        sensitive = self.root / "PRIVATE_PATH_SENTINEL" / "report.html"
        result = self.run_cli("check", self.skill, "--html", sensitive, "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PRIVATE_PATH_SENTINEL", result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        existing = self.root / "existing.html"
        existing.write_bytes(b"original report")
        result = self.run_cli("check", self.skill, "--html", existing)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(existing.read_bytes(), b"original report")

    def test_audit_failure_never_creates_archive(self):
        (self.skill / "guide.md").unlink()
        destination = self.root / "broken.zip"
        result = self.run_cli("pack", self.skill, "--output", destination, "--format", "json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "fail")
        self.assertFalse(destination.exists())

    def test_report_publication_failure_reports_created_archive_without_partial_html(self):
        destination = self.root / "new-release.zip"
        html = self.root / "report.html"
        original = cli._write_html

        def refuse_report_link(path, content):
            # Fail only after archive publication, while publishing the report.
            with patch.object(cli.os, "link", side_effect=OSError("PRIVATE_PATH_SENTINEL")):
                original(path, content)

        output, errors = io.StringIO(), io.StringIO()
        with patch.object(cli, "_write_html", side_effect=refuse_report_link):
            with redirect_stdout(output), redirect_stderr(errors):
                code = cli.main(["pack", str(self.skill), "--output", str(destination),
                                 "--html", str(html), "--format", "json"])
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertTrue(report["archive_created"])
        self.assertNotIn("PRIVATE_PATH_SENTINEL", output.getvalue() + errors.getvalue())
        self.assertFalse(html.exists())
        self.assertEqual(list(self.root.glob(".skill-dist-report-*.tmp")), [])
        manifest, payload = read_bundle(destination)
        self.assertEqual(len(manifest["files"]), 2)
        self.assertIn("SKILL.md", payload)


if __name__ == "__main__":
    unittest.main()
