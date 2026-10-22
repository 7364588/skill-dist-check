"""Bounded, read-only payload collection and reproducible ZIP distribution.

No operation extracts archives or executes payloads. Trees must remain unchanged
while being collected; filesystem race checks are defense in depth, not a sandbox.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib


FORMAT = "skill-dist-check/v1"
MAX_FILES = 4096
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 40 * 1024 * 1024
MAX_CENTRAL_BYTES = 6 * 1024 * 1024
MAX_COMPONENT_BYTES = 255
MAX_PATH_BYTES = 1024
MAX_DEPTH = 64
DEFAULT_EXCLUDES = frozenset({".git", ".venv", "node_modules", "__pycache__", ".DS_Store"})
_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$", re.IGNORECASE)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class BundleError(ValueError):
    """An input cannot be represented or verified as a bounded bundle."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _path_parts(path: str) -> list[str]:
    if not isinstance(path, str) or not path or "\\" in path:
        raise BundleError("Payload paths must be nonempty relative POSIX paths.")
    try:
        encoded = path.encode("utf-8")
    except UnicodeError as exc:
        raise BundleError("Payload path is not valid Unicode.") from exc
    if len(encoded) > MAX_PATH_BYTES:
        raise BundleError("Payload path exceeds the UTF-8 path limit.")
    parts = path.split("/")
    if len(parts) > MAX_DEPTH:
        raise BundleError("Payload path exceeds the component-depth limit.")
    for part in parts:
        if not part or part in {".", ".."} or part[-1:] in {".", " "}:
            raise BundleError("Payload path has an empty, dot, or trailing-dot/space component.")
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise BundleError("Payload component exceeds the UTF-8 byte limit.")
        if any(c in '<>:"|?*' or unicodedata.category(c) == "Cc" for c in part):
            raise BundleError("Payload path contains a nonportable character.")
        if _RESERVED.fullmatch(part.split(".", 1)[0].rstrip(" ")):
            raise BundleError("Payload path contains a Windows reserved name.")
    return parts


class _Paths:
    def __init__(self) -> None:
        self.names: dict[tuple[str, str], str] = {}
        self.files: set[str] = set()
        self.directories: set[str] = set()

    def add(self, path: str, *, directory: bool = False) -> None:
        parts = _path_parts(path)
        parent = ""
        for i, component in enumerate(parts):
            key = (parent, unicodedata.normalize("NFC", component).casefold())
            previous = self.names.setdefault(key, component)
            if previous != component:
                raise BundleError("Payload has Unicode-normalization or casefold path collisions.")
            current = "/".join(parts[: i + 1])
            is_directory = directory or i < len(parts) - 1
            if is_directory:
                if current in self.files:
                    raise BundleError("Payload path is both a file and a directory.")
                self.directories.add(current)
            else:
                if current in self.directories or current in self.files:
                    raise BundleError("Payload has duplicate or overlapping file paths.")
                self.files.add(current)
            parent = current


def _validate_files(files: dict[str, bytes], *, require_skill: bool = True) -> None:
    if not isinstance(files, dict):
        raise BundleError("Payload must map relative paths to bytes.")
    if len(files) > MAX_FILES:
        raise BundleError("Payload exceeds the file-count limit.")
    if require_skill and "SKILL.md" not in files:
        raise BundleError("Payload must contain a root SKILL.md file.")
    paths = _Paths()
    total = 0
    for name, content in files.items():
        paths.add(name)
        if not isinstance(content, bytes):
            raise BundleError("Payload content must be bytes.")
        total += len(content)
        if len(content) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise BundleError("Payload exceeds a content-size limit.")


def _unsafe_type(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _open_regular(path: Path):
    """Open one regular file without following a final-component symlink."""
    before = path.lstat()
    if _unsafe_type(before) or not stat.S_ISREG(before.st_mode):
        raise BundleError("Only regular files are supported; links and special files are rejected.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        after = os.fstat(fd)
        if _unsafe_type(after) or not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise BundleError("File changed while it was being opened.")
        stream = os.fdopen(fd, "rb")
        fd = -1
        return stream
    finally:
        if fd != -1:
            os.close(fd)


def collect(root: Path, excludes: list[str] | None = None, *, require_skill: bool = True) -> dict[str, bytes]:
    """Collect regular files; excluded directories are pruned before traversal.

    Explicit patterns use fnmatchcase against the entire relative POSIX path.
    Matching is case-sensitive; '*' may cross '/'; '**' has no special meaning.
    Default exclusions match the five exact basenames in DEFAULT_EXCLUDES at any
    depth. ZIP assets are included. Excluded entries are not opened or inspected.
    """
    root = Path(root)
    patterns = [] if excludes is None else list(excludes)
    if any(not isinstance(p, str) or not p for p in patterns):
        raise BundleError("Exclusion patterns must be nonempty strings.")
    files: dict[str, bytes] = {}
    names = _Paths()
    total = 0
    entries_seen = 0
    try:
        initial = root.lstat()
        if _unsafe_type(initial) or not stat.S_ISDIR(initial.st_mode):
            raise BundleError("Source must be a real directory, not a link.")
        resolved = root.resolve(strict=True)

        def walk(directory: Path, prefix: str = "") -> None:
            nonlocal total, entries_seen
            info = directory.lstat()
            if _unsafe_type(info) or not stat.S_ISDIR(info.st_mode):
                raise BundleError("Source directory changed or is a link.")
            if not directory.resolve(strict=True).is_relative_to(resolved):
                raise BundleError("Source directory escapes the selected root.")
            # Bound all enumerated entries, including exclusions and empty dirs.
            children = []
            with os.scandir(directory) as scan:
                for entry in scan:
                    entries_seen += 1
                    if entries_seen > MAX_FILES * 4:
                        raise BundleError("Source exceeds the directory-entry limit.")
                    children.append(entry)
            for entry in sorted(children, key=lambda e: e.name):
                name = f"{prefix}/{entry.name}" if prefix else entry.name
                if entry.name in DEFAULT_EXCLUDES or any(fnmatch.fnmatchcase(name, p) for p in patterns):
                    continue
                path = directory / entry.name
                item = path.lstat()
                if _unsafe_type(item):
                    raise BundleError("Source contains a symbolic link or reparse point.")
                if stat.S_ISDIR(item.st_mode):
                    names.add(name, directory=True)
                    walk(path, name)
                elif stat.S_ISREG(item.st_mode):
                    names.add(name)
                    if len(files) >= MAX_FILES or item.st_size > MAX_FILE_BYTES or total + item.st_size > MAX_TOTAL_BYTES:
                        raise BundleError("Source exceeds a file-count or content-size limit.")
                    if not path.resolve(strict=True).is_relative_to(resolved):
                        raise BundleError("Source file escapes the selected root.")
                    with _open_regular(path) as stream:
                        before = os.fstat(stream.fileno())
                        content = stream.read(min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total) + 1)
                        after = os.fstat(stream.fileno())
                    if len(content) > MAX_FILE_BYTES or total + len(content) > MAX_TOTAL_BYTES:
                        raise BundleError("Source exceeds a content-size limit.")
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(content) != after.st_size:
                        raise BundleError("Source file changed while being read.")
                    files[name] = content
                    total += len(content)
                else:
                    raise BundleError("Source contains a non-regular file.")

        walk(root)
    except OSError as exc:
        raise BundleError("Cannot read the selected source directory.") from exc
    _validate_files(files, require_skill=require_skill)
    return dict(sorted(files.items()))


def make_manifest(files: dict[str, bytes]) -> dict:
    """Hash sorted payload records; payload hash covers canonical records JSON."""
    _validate_files(files)
    records = [{"path": path, "size": len(files[path]), "sha256": hashlib.sha256(files[path]).hexdigest()} for path in sorted(files)]
    manifest = {"format": FORMAT, "files": records, "payload_sha256": hashlib.sha256(_canonical(records)).hexdigest()}
    if len(_canonical(manifest)) > MAX_MANIFEST_BYTES:
        raise BundleError("Manifest exceeds the size limit.")
    return manifest


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def pack(root: Path, destination: Path, excludes: list[str] | None = None, *, expected_manifest: dict | None = None) -> dict:
    """Write a deterministic archive with atomic, no-overwrite publication.

    Publication uses a same-directory hard link; the destination filesystem must
    support hard links. Source validation completes before temporary output exists.
    """
    root, destination = Path(root), Path(destination)
    temporary: Path | None = None
    try:
        if os.path.lexists(destination):
            raise BundleError("Output already exists; existing files are never overwritten.")
        parent = destination.parent.resolve(strict=True)
        if not parent.is_dir():
            raise BundleError("Output parent must be an existing directory.")
        target = parent / destination.name
        patterns = list(excludes or [])
        # Exact destination exclusion is defensive: output is absent at this point.
        resolved_root = root.resolve(strict=True)
        if target.is_relative_to(resolved_root):
            relative = target.relative_to(resolved_root).as_posix()
            patterns.append("".join("[[]" if c == "[" else "[?]" if c == "?" else "[*]" if c == "*" else c for c in relative))
        files = collect(root, patterns)
        manifest = make_manifest(files)
        if expected_manifest is not None and manifest != expected_manifest:
            raise BundleError("Source changed since its audit; no archive was written.")
        with tempfile.NamedTemporaryFile(prefix=".skill-dist-check-", suffix=".tmp", dir=parent, delete=False) as stream:
            temporary = Path(stream.name)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
                archive.writestr(_zip_info("capsule.json"), _canonical(manifest))
                for name, content in files.items():
                    archive.writestr(_zip_info("skill/" + name), content)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            raise BundleError("Archive exceeds the size limit.")
        os.link(temporary, target)
        return manifest
    except (OSError, zipfile.LargeZipFile) as exc:
        raise BundleError("Cannot publish archive; destination must be absent and its filesystem must support hard links.") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("Manifest has duplicate JSON keys.")
        result[key] = value
    return result


def _parse_manifest(content: bytes) -> dict:
    try:
        result = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(BundleError("Manifest contains a nonfinite number.")))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, BundleError):
            raise
        raise BundleError("Manifest is not valid bounded UTF-8 JSON.") from exc
    if not isinstance(result, dict) or set(result) != {"format", "files", "payload_sha256"} or result["format"] != FORMAT:
        raise BundleError("Unsupported manifest format or fields.")
    records = result["files"]
    if not isinstance(records, list) or len(records) > MAX_FILES:
        raise BundleError("Manifest files must be a bounded list.")
    names = _Paths()
    order = []
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise BundleError("Invalid manifest file record.")
        names.add(record["path"])
        if type(record["size"]) is not int or not 0 <= record["size"] <= MAX_FILE_BYTES:
            raise BundleError("Invalid manifest file size.")
        if not isinstance(record["sha256"], str) or not _DIGEST.fullmatch(record["sha256"]):
            raise BundleError("Invalid manifest content digest.")
        total += record["size"]
        if total > MAX_TOTAL_BYTES:
            raise BundleError("Manifest exceeds the total content limit.")
        order.append(record["path"])
    if order != sorted(order) or "SKILL.md" not in names.files:
        raise BundleError("Manifest must have sorted records and a root SKILL.md.")
    digest = result["payload_sha256"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest != hashlib.sha256(_canonical(records)).hexdigest():
        raise BundleError("Manifest payload digest does not match its records.")
    return result


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int, source) -> bytes:
    if info.file_size > limit:
        raise BundleError("Archive member exceeds the size limit.")
    with archive.open(info, "r") as stream:
        content = stream.read(limit + 1)
    if len(content) != info.file_size or len(content) > limit:
        raise BundleError("Archive member has invalid or excessive content size.")
    # ZipExtFile intentionally clips decoded output to the central-directory
    # size. Verify the actual deflate stream too, so a forged short size cannot
    # hide surplus decoded bytes behind a matching checksum for their prefix.
    source.seek(info.header_offset)
    local = source.read(30)
    if len(local) != 30 or local[:4] != b"PK\x03\x04":
        raise BundleError("Archive local member header is malformed.")
    name_size, extra_size = struct.unpack_from("<HH", local, 26)
    if extra_size or info.extra:
        raise BundleError("ZIP extra metadata is unsupported by this bundle format.")
    source.seek(info.header_offset + 30 + name_size)
    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            raise BundleError("Stored ZIP member has inconsistent sizes.")
    else:
        inflater = zlib.decompressobj(-15)
        remaining = info.compress_size
        produced = 0
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise BundleError("Compressed ZIP member is truncated.")
            remaining -= len(chunk)
            produced += len(inflater.decompress(chunk, info.file_size + 1 - produced))
            if produced > info.file_size or inflater.unconsumed_tail or inflater.unused_data:
                raise BundleError("Compressed ZIP member exceeds its declared stream bounds.")
        if not inflater.eof or produced != info.file_size:
            raise BundleError("Compressed ZIP member has an incomplete or inconsistent stream.")
    return content


def _preflight_zip(stream) -> None:
    """Bound central-directory parsing before ZipFile allocates member objects."""
    size = os.fstat(stream.fileno()).st_size
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    index = tail.rfind(b"PK\x05\x06")
    if index < 0 or len(tail) - index < 22:
        raise BundleError("Archive has no valid ZIP end record.")
    _, disk, central_disk, disk_count, count, central_size, offset, comment_size = struct.unpack("<4s4H2LH", tail[index:index + 22])
    end_offset = size - len(tail) + index
    if disk or central_disk or disk_count != count or count > MAX_FILES + 1:
        raise BundleError("Multipart, ZIP64, or excessive-entry archives are unsupported.")
    if index + 22 + comment_size != len(tail) or offset + central_size != end_offset:
        raise BundleError("Archive has inconsistent offsets or trailing data.")
    if central_size > MAX_CENTRAL_BYTES:
        raise BundleError("Archive central directory exceeds the metadata-size limit.")
    stream.seek(offset)
    actual = 0
    while stream.tell() < end_offset:
        header = stream.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise BundleError("Archive central directory is malformed.")
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", header, 28)
        next_offset = stream.tell() + name_len + extra_len + comment_len
        actual += 1
        if next_offset > end_offset or actual > MAX_FILES + 1:
            raise BundleError("Archive central directory exceeds its bounds.")
        stream.seek(next_offset)
    if actual != count:
        raise BundleError("Archive entry count does not match its end record.")
    stream.seek(0)


def read_bundle(archive: Path) -> tuple[dict, dict[str, bytes]]:
    """Verify all members and hashes in memory, without extracting any files."""
    try:
        with _open_regular(Path(archive)) as stream:
            if os.fstat(stream.fileno()).st_size > MAX_ARCHIVE_BYTES:
                raise BundleError("Archive exceeds the byte limit.")
            _preflight_zip(stream)
            with zipfile.ZipFile(stream, "r") as bundle:
                infos = bundle.infolist()
                if len(infos) > MAX_FILES + 1:
                    raise BundleError("Archive exceeds the entry-count limit.")
                members = {}
                total = 0
                for info in infos:
                    if info.filename in members or info.orig_filename != info.filename:
                        raise BundleError("Archive has duplicate or ambiguous member names.")
                    unix_type = stat.S_IFMT(info.external_attr >> 16)
                    if info.is_dir() or info.external_attr & 0x10 or unix_type not in {0, stat.S_IFREG}:
                        raise BundleError("Archive directories, links, and special files are not supported.")
                    if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        raise BundleError("Encrypted or unsupported compressed members are rejected.")
                    if info.filename == "capsule.json":
                        limit = MAX_MANIFEST_BYTES
                    elif info.filename.startswith("skill/"):
                        _path_parts(info.filename[len("skill/"):])
                        limit = MAX_FILE_BYTES
                        total += info.file_size
                    else:
                        raise BundleError("Archive has an unexpected member outside its payload.")
                    if info.file_size > limit or total > MAX_TOTAL_BYTES:
                        raise BundleError("Archive exceeds a content-size limit.")
                    members[info.filename] = info
                if "capsule.json" not in members:
                    raise BundleError("Archive is missing capsule.json.")
                manifest = _parse_manifest(_read_member(bundle, members["capsule.json"], MAX_MANIFEST_BYTES, stream))
                expected = {"capsule.json"} | {"skill/" + record["path"] for record in manifest["files"]}
                if set(members) != expected:
                    raise BundleError("Archive members do not exactly match the manifest.")
                files = {}
                for record in manifest["files"]:
                    info = members["skill/" + record["path"]]
                    if info.file_size != record["size"]:
                        raise BundleError("Archive member size differs from the manifest.")
                    content = _read_member(bundle, info, record["size"], stream)
                    if hashlib.sha256(content).hexdigest() != record["sha256"]:
                        raise BundleError("Archive content digest does not match the manifest.")
                    files[record["path"]] = content
                return manifest, files
    except BundleError:
        raise
    except (OSError, ValueError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, struct.error) as exc:
        raise BundleError("Cannot read or verify the selected archive.") from exc


def compare_files(expected: dict[str, bytes], actual: dict[str, bytes]) -> dict:
    """Return deterministic byte-level installation drift, retaining real zeros."""
    _validate_files(expected, require_skill=False)
    _validate_files(actual, require_skill=False)
    added = sorted(actual.keys() - expected.keys())
    removed = sorted(expected.keys() - actual.keys())
    changed = sorted(path for path in expected.keys() & actual.keys() if expected[path] != actual[path])
    unchanged = len(expected.keys() & actual.keys()) - len(changed)
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged,
            "clean": not (added or removed or changed)}
