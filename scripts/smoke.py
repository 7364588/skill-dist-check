"""Exercise the installed distribution in a fresh directory, with no source imports."""

import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(*args, expected=0):
    result = subprocess.run([sys.executable, "-m", "skill_dist_check", *map(str, args)],
                            capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="skill-dist-smoke-") as temporary:
    root = Path(temporary)
    skill = root / "source"
    skill.mkdir()
    (skill / "SKILL.md").write_text("# Example\nSee [reference](references/guide.md).\n", encoding="utf-8")
    (skill / "references").mkdir()
    (skill / "references/guide.md").write_text("# Guide\nSynthetic content.\n", encoding="utf-8")
    archive, second = root / "release.zip", root / "again.zip"
    run("--help")
    assert "0.1.0" in run("--version")
    check = json.loads(run("check", skill, "--format", "json", "--html", root / "check.html"))
    assert check["audit"]["ok"] and len(check["manifest"]["files"]) == 2
    run("pack", skill, "--output", archive)
    run("pack", skill, "--output", second)
    assert archive.read_bytes() == second.read_bytes(), "Non-deterministic ZIP"
    run("verify", archive, "--format", "json")
    run("diff", archive, second)
    installed = root / "moved" / "skill"
    # Only this just-created, synthetic archive is extracted for the smoke test.
    with zipfile.ZipFile(archive) as release:
        release.extractall(root / "moved")
    run("verify", archive, "--directory", installed)
    (installed / "references/guide.md").unlink()
    (installed / "extra.txt").write_text("extra", encoding="utf-8")
    drift = json.loads(run("verify", archive, "--directory", installed, "--format", "json",
                           "--html", root / "drift.html", expected=1))
    assert drift["diff"]["removed"] == ["references/guide.md"]
    assert drift["diff"]["added"] == ["extra.txt"]
    run("check", installed, expected=1)
    run("pack", installed, "--output", root / "broken.zip", expected=1)
    assert not (root / "broken.zip").exists()
    run("pack", skill, "--output", archive, expected=2)
    run("check", skill, "--html", root / "check.html", expected=2)
    run("verify", root / "missing.zip", expected=2)
    (skill / "references/guide.md").write_text("# Updated\n", encoding="utf-8")
    run("pack", skill, "--output", root / "changed.zip")
    delta = json.loads(run("diff", archive, root / "changed.zip", "--format", "json", expected=1))
    assert delta["diff"]["changed"] == ["references/guide.md"]
    # SKILL deletion must be reported as drift, not crash or a success.
    (installed / "SKILL.md").unlink()
    run("verify", archive, "--directory", installed, expected=1)
print("Installed CLI smoke passed: check, pack, relocation, verify, drift, diff, HTML and error exits.")
