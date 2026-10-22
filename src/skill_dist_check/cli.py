"""Explicit-input command line interface; no discovery, extraction or execution."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .audit import audit_files
from .bundle import BundleError, collect, compare_files, make_manifest, pack, read_bundle
from .report import render_html


class _OutputFailure(Exception):
    def __init__(self, stream):
        self.stream = stream


def _emit(message: str, stream) -> None:
    try:
        stream.write(message)
        stream.flush()
    except (OSError, ValueError):
        raise _OutputFailure(stream) from None


class _Parser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if message:
            _emit(message, file if file is not None else sys.stderr)


def _write_html(path: Path, content: str) -> None:
    """Publish a complete report without clobbering a destination or leaving partial HTML."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                                         prefix=".skill-dist-report-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def parser() -> argparse.ArgumentParser:
    cli = _Parser(description="Check the files that ship in an agent skill.")
    cli.add_argument("--version", action="version", version=f"skill-dist-check {__version__}")
    commands = cli.add_subparsers(dest="operation", required=True)
    for name, help_text in [
        ("check", "Check local Markdown references in a skill directory"),
        ("pack", "Check and write a reproducible, content-verified ZIP"),
        ("verify", "Verify a ZIP and optionally compare an installed directory"),
        ("diff", "Compare two verified skill ZIP payloads"),
    ]:
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument("source", type=Path, metavar="DIR" if name in ("check", "pack") else "ARCHIVE")
        if name == "diff":
            cmd.add_argument("head", type=Path, metavar="HEAD_ARCHIVE")
        if name == "pack":
            cmd.add_argument("--output", type=Path, required=True, metavar="ZIP")
        if name == "verify":
            cmd.add_argument("--directory", type=Path, metavar="INSTALLED_DIR")
        if name != "diff":
            cmd.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                             help="Exclude a relative POSIX path glob (repeatable, case sensitive)")
        cmd.add_argument("--format", choices=("text", "json"), default="text")
        cmd.add_argument("--html", type=Path, help="Write a standalone HTML report; refuses to overwrite")
    return cli


def summarize(report: dict) -> str:
    lines = [f"{report['operation']}: {report['status'].upper()}"]
    manifest = report.get("manifest")
    if manifest:
        lines.append(f"{len(manifest['files'])} files | payload SHA-256 {manifest['payload_sha256']}")
    for finding in report.get("audit", {}).get("findings", []):
        where = finding["path"] + (f":{finding['line']}" if finding.get("line") else "")
        lines.append(f"{finding['severity'].upper()} {finding['code']} {where}: {finding['message']}")
    difference = report.get("diff")
    if difference:
        lines.append(f"{len(difference['added'])} added, {len(difference['removed'])} removed, "
                     f"{len(difference['changed'])} changed, {difference['unchanged']} unchanged")
        for kind in ("added", "removed", "changed"):
            lines.extend(f"  {kind}: {path}" for path in difference[kind])
    if report.get("audit"):
        lines.append("Scope: local Markdown links and payload bytes; dynamic paths and skill behavior are not tested.")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    archive_created = False
    try:
        if args.html:
            if args.html.exists() or args.html.is_symlink():
                raise BundleError("HTML output already exists; choose a new file.")
            if not args.html.parent.is_dir():
                raise BundleError("HTML output parent must be an existing directory.")
            inspected = args.source if args.operation in ("check", "pack") else getattr(args, "directory", None)
            if inspected and args.html.resolve().is_relative_to(inspected.resolve()):
                raise BundleError("HTML output must be outside the inspected directory.")
        if args.operation == "pack" and args.html and args.html.resolve() == args.output.resolve():
            raise BundleError("Archive and HTML outputs must be different files.")
        report = {"schema": "skill-dist-check/report-v1", "operation": args.operation, "status": "pass"}
        if args.operation in ("check", "pack"):
            payload = collect(args.source, args.exclude)
            audit = audit_files(payload)
            report.update(manifest=make_manifest(payload), audit=audit)
            if not audit["ok"]:
                report["status"] = "fail"
            elif args.operation == "pack":
                report["manifest"] = pack(args.source, args.output, args.exclude,
                                          expected_manifest=report["manifest"])
                archive_created = True
        elif args.operation == "verify":
            manifest, payload = read_bundle(args.source)
            report.update(manifest=manifest, audit=audit_files(payload))
            if args.directory:
                actual = collect(args.directory, args.exclude, require_skill=False)
                report["diff"] = compare_files(payload, actual)
                report["installed_audit"] = audit_files(actual)
                if not report["diff"]["clean"]:
                    report["status"] = "fail"
            if not report["audit"]["ok"]:
                report["status"] = "fail"
        else:
            base, before = read_bundle(args.source)
            head, after = read_bundle(args.head)
            report.update(manifest=head, base_payload_sha256=base["payload_sha256"],
                          diff=compare_files(before, after), audit=audit_files(after))
            if not report["diff"]["clean"] or not report["audit"]["ok"]:
                report["status"] = "fail"
        if args.html:
            _write_html(args.html, render_html(report))
        _emit((json.dumps(report, ensure_ascii=True, indent=2) if args.format == "json" else summarize(report)) + "\n", sys.stdout)
        return 0 if report["status"] == "pass" else 1
    except (BundleError, OSError, UnicodeError, ValueError) as error:
        message = str(error) if isinstance(error, BundleError) else "Cannot read input or write output; check paths, permissions and text encoding."
        if archive_created:
            message += " Archive was created; report delivery failed. Verify the archive before retrying."
        if args.format == "json":
            _emit(json.dumps({"schema": "skill-dist-check/report-v1", "operation": args.operation,
                              "status": "error", "error": message, "archive_created": archive_created}, ensure_ascii=True) + "\n", sys.stdout)
        else:
            _emit(f"skill-dist-check: {message}\n", sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except _OutputFailure as error:
        # Explicit flush above catches buffered pipe errors before interpreter shutdown.
        # Redirect that descriptor so a remaining buffer cannot raise exit 120 later.
        try:
            with open(os.devnull, "w") as sink:
                os.dup2(sink.fileno(), error.stream.fileno())
        except (OSError, ValueError, AttributeError):
            if error.stream is sys.stdout:
                sys.stdout = open(os.devnull, "w")
            if error.stream is sys.stderr:
                sys.stderr = open(os.devnull, "w")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
