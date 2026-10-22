"""Synthetic CommonMark and payload-boundary regression checks."""

import json
import unittest

from skill_dist_check.audit import audit_files


def payload(source, **extra):
    return {"SKILL.md": source.encode("utf-8"), **extra}


class AuditTests(unittest.TestCase):
    def test_inline_reference_images_and_escaped_destinations(self):
        files = payload(
            "[Guide](docs/guide.md) ![badge][badge]\n"
            "[Full][guide] [guide][] [guide] [escaped](docs/a\\(b\\).md)\n\n"
            "[guide]: docs/guide.md\n[badge]: assets/badge.svg\n",
            **{"docs/guide.md": b"Guide", "assets/badge.svg": b"<svg/>", "docs/a(b).md": b"Example"},
        )
        report = audit_files(files)
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"], {"files": 4, "markdown_files": 3, "local_links": 6})

    def test_parent_relative_directory_and_query_paths(self):
        files = payload("[docs](docs/) [root](.) [self](?view=compact)\n", **{
            "docs/guide.markdown": b"[root](../SKILL.md) [folder](../assets) [same](./guide.markdown#part)",
            "assets/sample.txt": b"synthetic",
        })
        self.assertTrue(audit_files(files)["ok"])
        self.assertEqual(audit_files(files)["stats"]["local_links"], 6)

    def test_missing_and_directory_slash_are_not_existing_files(self):
        report = audit_files(payload("[a](missing.md) [b](SKILL.md/) [c](empty-folder/)"))
        self.assertFalse(report["ok"])
        self.assertEqual([f["code"] for f in report["findings"]], ["missing-local-target"] * 3)

    def test_commonmark_code_and_unrecognized_references_are_not_guessed(self):
        source = "`[inline](missing.md)`\n\n```md\n[fenced](missing.md)\n```\n\n    [indented](missing.md)\n\n[undefined][unknown]\n\n[unused]: missing.md\nRun scripts/update.py manually.\n"
        report = audit_files(payload(source))
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"]["local_links"], 0)

    def test_external_and_fragment_targets_are_not_checked(self):
        source = "[web](https://example.invalid/a) <http://example.invalid> [mail](mailto:example@example.invalid) ![inline](data:image/png;base64,AAAA) [part](#unknown)"
        report = audit_files(payload(source))
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"]["local_links"], 0)

    def test_unsupported_schemes_are_visible_without_being_local(self):
        report = audit_files(payload("[x](custom:synthetic) [y](javascript:synthetic)"))
        self.assertTrue(report["ok"])
        self.assertEqual([f["severity"] for f in report["findings"]], ["warning", "warning"])
        self.assertEqual(report["stats"]["local_links"], 0)

    def test_absolute_and_encoded_absolute_paths_are_errors(self):
        for destination in ("/example/file", "file:///example/file", "C:/example/file", "C:example", "//example/share", "%2Fexample/file", "%5C%5Cexample%5Cshare"):
            with self.subTest(destination=destination):
                report = audit_files(payload(f"[x]({destination})"))
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["code"], "absolute-local-target")

    def test_traversal_and_encoding_boundaries(self):
        cases = {
            "../outside.md": "escaping-local-target",
            "%2e%2e/outside.md": "escaping-local-target",
            "docs/%2e%2e/%2e%2e/outside.md": "escaping-local-target",
            "%252e%252e/outside.md": "nested-uri-encoding",
            "bad%ZZ.md": "invalid-uri-encoding",
            "%FF.md": "invalid-uri-encoding",
            "a%00.md": "invalid-local-target",
            "docs%5Cguide.md": "invalid-local-target",
        }
        for destination, code in cases.items():
            with self.subTest(destination=destination):
                report = audit_files(payload(f"[x]({destination})"))
                self.assertFalse(report["ok"])
                self.assertEqual(report["findings"][0]["code"], code)

    def test_uri_decoding_preserves_encoded_delimiters_and_unicode(self):
        files = payload("[a](docs/a%23b.md#section) [b](docs/a%20b.md?view=1) [c](docs/%E7%A4%BA%E4%BE%8B.md) [d](docs/a&amp;b.md)", **{
            "docs/a#b.md": b"a", "docs/a b.md": b"b", "docs/示例.md": b"c", "docs/a&b.md": b"d",
        })
        self.assertTrue(audit_files(files)["ok"])

    def test_case_sensitive_resolution(self):
        report = audit_files(payload("[guide](docs/Guide.md)", **{"docs/guide.md": b"Guide"}))
        self.assertFalse(report["ok"])
        self.assertEqual(report["findings"][0]["code"], "target-case-mismatch")
        self.assertEqual(report["findings"][0]["target"], "docs/guide.md")

    def test_missing_root_and_invalid_markdown_utf8(self):
        report = audit_files({"docs/guide.md": b"\xff", "assets/image.bin": b"\xff"})
        self.assertFalse(report["ok"])
        self.assertEqual({f["code"] for f in report["findings"]}, {"missing-skill", "invalid-markdown-utf8"})
        self.assertEqual(report["stats"]["markdown_files"], 1)

    def test_bom_crlf_and_multiline_reference_locations(self):
        report = audit_files({"SKILL.md": b"\xef\xbb\xbf# Changelog\r\n\r\nfirst [x](one.md)\r\nsecond [y][ref]\r\n\r\n[ref]: two.md\r\n"})
        self.assertEqual([f["line"] for f in report["findings"]], [3, 4])

    def test_blockquote_and_list_link_locations(self):
        report = audit_files(payload("> [first](one.md)\n> [second](two.md)\n\n- [third](three.md)\n  [fourth](four.md)\n"))
        self.assertEqual([f["line"] for f in report["findings"]], [1, 2, 4, 5])

    def test_frontmatter_is_skipped_and_following_lines_preserved(self):
        report = audit_files(payload("---\nname: changelog\ndescription: '[metadata](not-markdown.md)'\n---\n[real](missing.md)\n"))
        self.assertEqual([(f["code"], f["line"]) for f in report["findings"]], [("frontmatter-not-checked", 1), ("missing-local-target", 5)])
        self.assertEqual(report["stats"]["local_links"], 1)

    def test_html_references_report_coverage_without_guessing_targets(self):
        report = audit_files(payload('<img src="missing.png">\n\nText <a href="missing.md">link</a>.\n\n<!-- <img src="ignored.png"> -->'))
        self.assertTrue(report["ok"])
        self.assertEqual([f["code"] for f in report["findings"]], ["html-reference-not-checked"] * 2)
        self.assertEqual(report["stats"]["local_links"], 0)

    def test_image_alt_nested_markup_is_text_not_an_extra_resource(self):
        report = audit_files(payload("![![nested](missing.png)](assets/badge.svg)", **{"assets/badge.svg": b"<svg/>"}))
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"]["local_links"], 1)

    def test_reports_do_not_echo_private_like_values(self):
        secret = "SYNTHETIC_PRIVATE_SENTINEL"
        report = audit_files(payload(f"[label]({secret}.md?token={secret}#{secret}) [absolute](/example/{secret}) <img src='{secret}'>"))
        self.assertNotIn(secret, json.dumps(report))
        self.assertTrue(all(f["target"] is None for f in report["findings"]))

    def test_deterministic_and_no_input_mutation(self):
        files = payload("[missing](missing.md)", **{"docs/z.md": b"[x](absent.md)", "docs/a.md": b"Guide"})
        snapshot = dict(files)
        self.assertEqual(audit_files(files), audit_files(dict(reversed(list(files.items())))))
        self.assertEqual(files, snapshot)

    def test_direct_api_rejects_invalid_payload_argument_shapes(self):
        for invalid in ([], {"SKILL.md": "text"}, {1: b"text"}):
            with self.subTest(invalid=invalid), self.assertRaises(TypeError):
                audit_files(invalid)
        for path in ("/outside.md", "../outside.md", "docs/../SKILL.md", "C:/example.md", "docs\\example.md"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit_files({path: b"example"})


if __name__ == "__main__":
    unittest.main()
