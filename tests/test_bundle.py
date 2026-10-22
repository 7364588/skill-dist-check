"""Synthetic collection, reproducibility, tampering, and resource-bound tests."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import zlib

from skill_dist_check import bundle as b


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def unchecked_manifest(files):
    records = [{"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
               for name, content in sorted(files.items())]
    return {"format": b.FORMAT, "files": records, "payload_sha256": hashlib.sha256(canonical(records)).hexdigest()}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.files = {"SKILL.md": b"# Synthetic skill\n", "scripts/hello.py": b"raise RuntimeError('never execute')\n", "data/example.txt": b"hello\n"}
        self.populate(self.root, self.files)

    def populate(self, root, files):
        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

    def archive(self, files=None, *, manifest=None, extras=(), compression=zipfile.ZIP_STORED):
        files = self.files if files is None else files
        manifest = unchecked_manifest(files) if manifest is None else manifest
        target = self.base / "input.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(target, "w", compression=compression) as z:
                z.writestr("capsule.json", manifest if isinstance(manifest, bytes) else canonical(manifest))
                for name, content in files.items():
                    z.writestr("skill/" + name, content)
                for name, content in extras:
                    z.writestr(name, content)
        return target


class CollectionTests(Fixture):
    def test_collect_sorted_exact_content_without_execution(self):
        marker = self.root / "marker"
        source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n".encode()
        (self.root / "scripts/hello.py").write_bytes(source)
        expected = dict(self.files, **{"scripts/hello.py": source})
        actual = b.collect(self.root)
        self.assertEqual(actual, expected)
        self.assertEqual(list(actual), sorted(actual))
        self.assertFalse(marker.exists())

    def test_default_exclusions_apply_at_any_depth_and_zip_assets_remain(self):
        for name in b.DEFAULT_EXCLUDES:
            if name == ".DS_Store":
                self.populate(self.root, {"nested/" + name: b"ignored"})
            else:
                self.populate(self.root, {"nested/" + name + "/file": b"ignored"})
        self.populate(self.root, {"asset.zip": b"zip asset"})
        self.assertEqual(b.collect(self.root), dict(self.files, **{"asset.zip": b"zip asset"}))

    def test_glob_full_path_case_sensitive_and_star_crosses_slash(self):
        self.populate(self.root, {"data/deeper/example.txt": b"skip", "DATA.txt": b"keep"})
        actual = b.collect(self.root, ["data/*.txt", "data.txt", "scripts"])
        self.assertEqual(actual, {"SKILL.md": self.files["SKILL.md"], "DATA.txt": b"keep"})

    def test_missing_skill_rejected_but_installation_comparison_permits_it(self):
        (self.root / "SKILL.md").unlink()
        with self.assertRaises(b.BundleError):
            b.collect(self.root)
        self.assertEqual(set(b.collect(self.root, require_skill=False)), {"scripts/hello.py", "data/example.txt"})

    def test_empty_installation_is_valid_for_drift(self):
        empty = self.base / "empty"
        empty.mkdir()
        self.assertEqual(b.collect(empty, require_skill=False), {})

    def test_source_must_be_directory(self):
        for source in (self.root / "missing", self.root / "SKILL.md"):
            with self.subTest(source=source.name), self.assertRaises(b.BundleError):
                b.collect(source)

    def test_invalid_patterns_rejected(self):
        for patterns in ([""], [1]):
            with self.subTest(patterns=patterns), self.assertRaises(b.BundleError):
                b.collect(self.root, patterns)

    def test_file_count_size_total_and_entry_limits(self):
        for constant, limit in (("MAX_FILES", 2), ("MAX_FILE_BYTES", 2), ("MAX_TOTAL_BYTES", 20), ("MAX_FILES", 0)):
            with self.subTest(constant=constant, limit=limit), patch.object(b, constant, limit), self.assertRaises(b.BundleError):
                b.collect(self.root)

    def test_symlink_rejected_without_reading_target(self):
        outside = self.base / "outside.txt"
        outside.write_bytes(b"outside")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Symlink creation unavailable")
        with self.assertRaises(b.BundleError):
            b.collect(self.root)
        self.assertEqual(b.collect(self.root, ["link.txt"]), self.files)

    def test_reparse_point_detection_does_not_need_windows_privileges(self):
        class Reparse:
            st_mode = stat.S_IFDIR | 0o755
            st_file_attributes = 0x400
        self.assertTrue(b._unsafe_type(Reparse()))

    def test_case_collisions_in_directory_components_are_rejected(self):
        # A synthetic scandir is unnecessary: make_manifest exercises the shared
        # path registry on case-distinct directories on every host filesystem.
        with self.assertRaises(b.BundleError):
            b.make_manifest({"SKILL.md": b"", "Data/a": b"", "data/b": b""})


class ManifestTests(Fixture):
    def test_canonical_records_and_digest(self):
        manifest = b.make_manifest(dict(reversed(list(self.files.items()))))
        self.assertEqual(manifest, unchecked_manifest(self.files))
        self.assertEqual([r["path"] for r in manifest["files"]], sorted(self.files))
        self.assertNotIn(str(self.root), canonical(manifest).decode())

    def test_unicode_filename_hashes_use_utf8_canonical_json(self):
        files = {"SKILL.md": b"", "docs/café.md": b"data"}
        self.assertEqual(b.make_manifest(files), unchecked_manifest(files))

    def test_portability_invalid_names(self):
        names = ["../bad", "/bad", "a//b", "a/./b", "a/../b", "a\\b", "C:bad", "x\x00", "x\x1f", "x\x7f", "x?", "x*", 'x"', "x<", "x>", "x|", "x.", "x ", "CON", "con.txt", "NUL.tar.gz", "COM1.md", "lpt9", "COM¹.dat", "LPT³", "CON .txt", "x" * 256, "/".join(["a"] * 65), "x\ud800"]
        for name in names:
            with self.subTest(name=ascii(name)), self.assertRaises(b.BundleError):
                b.make_manifest({"SKILL.md": b"", name: b""})

    def test_valid_similar_names_and_byte_limit(self):
        for name in ("COM0", "COM10", "LPT0", "console.txt", "a" * 255):
            with self.subTest(name=name):
                b.make_manifest({"SKILL.md": b"", name: b""})
        with self.assertRaises(b.BundleError):
            b.make_manifest({"SKILL.md": b"", "é" * 128: b""})

    def test_normalization_casefold_and_file_directory_collisions(self):
        for pair in (("a", "A"), ("café", "café"), ("Straße", "STRASSE"), ("A/x", "a/y"), ("a", "a/b")):
            with self.subTest(pair=pair), self.assertRaises(b.BundleError):
                b.make_manifest({"SKILL.md": b"", pair[0]: b"", pair[1]: b""})

    def test_rejects_wrong_types_and_missing_skill(self):
        for files in ({}, {"SKILL.md": "text"}, {"SKILL.md": b"", 4: b""}, []):
            with self.subTest(files=files), self.assertRaises(b.BundleError):
                b.make_manifest(files)

    def test_path_and_manifest_limits(self):
        with patch.object(b, "MAX_PATH_BYTES", 10), self.assertRaises(b.BundleError):
            b.make_manifest(self.files)
        with patch.object(b, "MAX_MANIFEST_BYTES", 10), self.assertRaises(b.BundleError):
            b.make_manifest(self.files)


class PackTests(Fixture):
    def test_byte_identical_across_roots_mtimes_and_permissions(self):
        other = self.base / "renamed"
        other.mkdir()
        self.populate(other, dict(reversed(list(self.files.items()))))
        for name in self.files:
            os.utime(other / name, (1700000000, 1700000000))
            os.chmod(other / name, 0o755)
        a, c = self.base / "a.zip", self.base / "c.zip"
        self.assertEqual(b.pack(self.root, a), b.pack(other, c))
        self.assertEqual(a.read_bytes(), c.read_bytes())
        manifest, files = b.read_bundle(a)
        self.assertEqual(manifest, b.make_manifest(self.files))
        self.assertEqual(files, self.files)
        with zipfile.ZipFile(a) as z:
            self.assertEqual(z.namelist(), ["capsule.json"] + ["skill/" + p for p in sorted(self.files)])
            for info in z.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.external_attr >> 16, stat.S_IFREG | 0o644)

    def test_output_inside_root_excluded_without_excluding_other_zip_assets(self):
        self.populate(self.root, {"reference.zip": b"an ordinary asset"})
        dest = self.root / "release[1].zip"
        b.pack(self.root, dest)
        _, files = b.read_bundle(dest)
        self.assertNotIn("release[1].zip", files)
        self.assertEqual(files["reference.zip"], b"an ordinary asset")

    def test_existing_archive_or_source_file_never_overwritten(self):
        for dest in (self.base / "existing.zip", self.root / "SKILL.md"):
            if not dest.exists():
                dest.write_bytes(b"original")
            before = dest.read_bytes()
            with self.assertRaises(b.BundleError):
                b.pack(self.root, dest)
            self.assertEqual(dest.read_bytes(), before)

    def test_expected_manifest_prevents_audit_pack_drift(self):
        expected = b.make_manifest(b.collect(self.root))
        (self.root / "SKILL.md").write_bytes(b"changed")
        dest = self.base / "release.zip"
        with self.assertRaises(b.BundleError):
            b.pack(self.root, dest, expected_manifest=expected)
        self.assertFalse(dest.exists())
        self.assertEqual(list(self.base.glob(".skill-dist-check-*")), [])

    def test_matching_expected_manifest_succeeds(self):
        expected = b.make_manifest(b.collect(self.root))
        self.assertEqual(b.pack(self.root, self.base / "release.zip", expected_manifest=expected), expected)

    def test_failed_atomic_publication_leaves_no_archive_or_temporary_file(self):
        dest = self.base / "release.zip"
        with patch.object(b.os, "link", side_effect=OSError("simulated failure")), self.assertRaises(b.BundleError):
            b.pack(self.root, dest)
        self.assertFalse(dest.exists())
        self.assertEqual(list(self.base.glob(".skill-dist-check-*")), [])

    def test_concurrent_destination_creation_not_overwritten(self):
        real_link = os.link
        dest = self.base / "release.zip"
        def create_before_link(source, target):
            dest.write_bytes(b"concurrent writer")
            return real_link(source, target)
        with patch.object(b.os, "link", side_effect=create_before_link), self.assertRaises(b.BundleError):
            b.pack(self.root, dest)
        self.assertEqual(dest.read_bytes(), b"concurrent writer")

    def test_validation_failure_creates_no_output(self):
        (self.root / "SKILL.md").unlink()
        dest = self.base / "release.zip"
        with self.assertRaises(b.BundleError):
            b.pack(self.root, dest)
        self.assertFalse(dest.exists())


class ReadTests(Fixture):
    def test_stored_and_deflated_read_without_extraction(self):
        before = set(self.base.iterdir())
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            path = self.archive(compression=compression)
            self.assertEqual(b.read_bundle(path)[1], self.files)
        self.assertEqual(set(self.base.iterdir()) - before, {self.base / "input.zip"})

    def test_tampered_content_with_correct_zip_crc_rejected_by_sha256(self):
        manifest = b.make_manifest(self.files)
        files = dict(self.files, **{"data/example.txt": b"jello\n"})
        with self.assertRaises(b.BundleError):
            b.read_bundle(self.archive(files, manifest=manifest))

    def test_missing_extra_and_duplicate_entries_rejected(self):
        manifest = b.make_manifest(self.files)
        cases = [({"SKILL.md": self.files["SKILL.md"]}, manifest, ()),
                 (self.files, manifest, (("skill/extra.txt", b"extra"),)),
                 (self.files, manifest, (("capsule.json", canonical(manifest)),)),
                 (self.files, manifest, (("skill/SKILL.md", self.files["SKILL.md"]),)),
                 (self.files, manifest, (("outside.txt", b"outside"),))]
        for files, data, extras in cases:
            with self.subTest(extras=extras), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive(files, manifest=data, extras=extras))

    def test_unsafe_archive_names_and_manifest_paths(self):
        for name in ("../escape", "/absolute", "a\\b", "C:drive", "CON.txt", "x.", "a//b"):
            with self.subTest(name=name), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive({"SKILL.md": b"", name: b"evil"}))
        self.assertFalse((self.base / "escape").exists())

    def test_nul_entry_name_not_silently_truncated(self):
        path = self.archive({"SKILL.md": b"", "xQ": b""})
        path.write_bytes(path.read_bytes().replace(b"skill/xQ", b"skill/x\0"))
        with self.assertRaises(b.BundleError):
            b.read_bundle(path)

    def test_symlink_directory_and_special_entry_rejected(self):
        for name, mode in (("skill/link", stat.S_IFLNK | 0o777), ("skill/fifo", stat.S_IFIFO | 0o600), ("skill/dir/", stat.S_IFDIR | 0o755)):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            with self.subTest(name=name), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive(extras=((info, b"target"),)))

    def test_manifest_duplicate_keys_nonfinite_deep_or_invalid_utf8_rejected(self):
        bad_json = [b'{"format":"skill-dist-check/v1","format":"skill-dist-check/v1"}', b'{"x":NaN}', b"[" * 2000 + b"]" * 2000, b"\xff", b"null", b"[]"]
        for data in bad_json:
            with self.subTest(data=data[:30]), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive(manifest=data))

    def test_manifest_strict_fields_sizes_hashes_order_and_duplicates(self):
        original = b.make_manifest(self.files)
        mutations = []
        for key, value in (("format", "unknown"), ("files", {}), ("payload_sha256", "0" * 64), ("extra", 1)):
            item = json.loads(json.dumps(original)); item[key] = value; mutations.append(item)
        for key, value in (("size", True), ("size", -1), ("size", 2**60), ("path", 7), ("sha256", "A" * 64), ("extra", 1)):
            item = json.loads(json.dumps(original)); item["files"][0][key] = value; mutations.append(item)
        item = json.loads(json.dumps(original)); item["files"].reverse(); mutations.append(item)
        item = json.loads(json.dumps(original)); item["files"].append(item["files"][0]); mutations.append(item)
        for item in mutations:
            with self.subTest(manifest=item), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive(manifest=item))

    def test_archive_casefold_normalization_and_file_directory_collisions(self):
        for pair in (("a", "A"), ("café", "café"), ("a", "a/b")):
            with self.subTest(pair=pair), self.assertRaises(b.BundleError):
                b.read_bundle(self.archive({"SKILL.md": b"", pair[0]: b"", pair[1]: b""}))

    def test_resource_limits_cover_compressed_data_and_metadata(self):
        path = self.archive(compression=zipfile.ZIP_DEFLATED)
        for name, limit in (("MAX_FILE_BYTES", 4), ("MAX_TOTAL_BYTES", 20), ("MAX_FILES", 1), ("MAX_MANIFEST_BYTES", 10), ("MAX_ARCHIVE_BYTES", 10), ("MAX_CENTRAL_BYTES", 10)):
            with self.subTest(limit=name), patch.object(b, name, limit), self.assertRaises(b.BundleError):
                b.read_bundle(path)

    def test_entry_count_checked_before_zipfile_constructed(self):
        path = self.archive()
        raw = bytearray(path.read_bytes())
        offset = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", raw, offset + 8, 65535, 65535)
        path.write_bytes(raw)
        with patch.object(b.zipfile, "ZipFile", side_effect=AssertionError("must not allocate ZipInfo")), self.assertRaises(b.BundleError):
            b.read_bundle(path)

    def test_forged_low_entry_count_rejected_before_zipfile_constructed(self):
        path = self.archive()
        raw = bytearray(path.read_bytes())
        offset = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", raw, offset + 8, 1, 1)
        path.write_bytes(raw)
        with patch.object(b.zipfile, "ZipFile", side_effect=AssertionError("must not allocate ZipInfo")), self.assertRaises(b.BundleError):
            b.read_bundle(path)

    def test_invalid_zip_and_trailing_data_fail_with_no_absolute_path_in_message(self):
        path = self.archive()
        path.write_bytes(path.read_bytes() + b"trailing")
        for candidate in (path, self.base / "missing.zip"):
            with self.assertRaises(b.BundleError) as caught:
                b.read_bundle(candidate)
            self.assertNotIn(str(self.base), str(caught.exception))

    def test_invalid_compressed_bytes_report_controlled_error(self):
        path = self.archive(compression=zipfile.ZIP_DEFLATED)
        raw = bytearray(path.read_bytes())
        # First member is the manifest; corrupt its compressed body, preserve ZIP metadata.
        name_size, extra_size = struct.unpack_from("<HH", raw, 26)
        offset = 30 + name_size + extra_size
        raw[offset:offset + 4] = b"\xff\xff\xff\xff"
        path.write_bytes(raw)
        with self.assertRaises(b.BundleError):
            b.read_bundle(path)

    def test_forged_short_size_cannot_hide_extra_inflated_content(self):
        manifest = unchecked_manifest({"SKILL.md": b"good"})
        path = self.archive({"SKILL.md": b"goodHIDDEN"}, manifest=manifest, compression=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(path) as z:
            local_offset = z.getinfo("skill/SKILL.md").header_offset
        raw = bytearray(path.read_bytes())
        struct.pack_into("<L", raw, local_offset + 14, zlib.crc32(b"good"))
        struct.pack_into("<L", raw, local_offset + 22, 4)
        offset = raw.find(b"PK\x01\x02")
        while raw[offset + 46:offset + 46 + len(b"skill/SKILL.md")] != b"skill/SKILL.md":
            offset = raw.find(b"PK\x01\x02", offset + 4)
            self.assertGreaterEqual(offset, 0)
        struct.pack_into("<L", raw, offset + 16, zlib.crc32(b"good"))
        struct.pack_into("<L", raw, offset + 24, 4)
        path.write_bytes(raw)
        with self.assertRaises(b.BundleError):
            b.read_bundle(path)

    def test_zip_extra_metadata_cannot_change_extraction_filename(self):
        info = zipfile.ZipInfo("skill/extra")
        info.extra = struct.pack("<HH", 0x7075, 5) + b"\x01xxxx"
        files = dict(self.files, extra=b"test")
        path = self.archive(self.files, manifest=unchecked_manifest(files), extras=((info, b"test"),))
        with self.assertRaises(b.BundleError):
            b.read_bundle(path)


class CompareTests(unittest.TestCase):
    def test_deterministic_added_removed_changed_and_unchanged(self):
        expected = {"SKILL.md": b"same", "removed": b"old", "changed": b"old"}
        actual = {"z-added": b"z", "SKILL.md": b"same", "changed": b"new", "a-added": b"a"}
        self.assertEqual(b.compare_files(expected, actual), {"added": ["a-added", "z-added"], "removed": ["removed"], "changed": ["changed"], "unchanged": 1, "clean": False})

    def test_removed_skill_and_empty_installation_are_reported(self):
        self.assertEqual(b.compare_files({"SKILL.md": b""}, {}), {"added": [], "removed": ["SKILL.md"], "changed": [], "unchanged": 0, "clean": False})
        self.assertEqual(b.compare_files({}, {}), {"added": [], "removed": [], "changed": [], "unchanged": 0, "clean": True})


if __name__ == "__main__":
    unittest.main()
