"""Audit recognized CommonMark references against an in-memory payload.

No filesystem access, network requests, or evaluation of skill code is performed.
The parser deliberately retains schemes and malformed URI escapes for inspection.
"""

from __future__ import annotations

from bisect import bisect_right
from html.parser import HTMLParser
import re
from urllib.parse import unquote_to_bytes

from markdown_it import MarkdownIt
from markdown_it.rules_inline import autolink, html_inline, image, link


_MARKDOWN_SUFFIXES = (".md", ".markdown")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_DRIVE = re.compile(r"^[A-Za-z]:")
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_OFFSET = "skill_dist_check_offset"

_SCOPE = [
    "Scans UTF-8 .md and .markdown files, including root SKILL.md, with the CommonMark parser.",
    "Checks recognized inline and reference links and images; fenced code, inline code, prose paths, and unused or undefined reference definitions are not path coverage.",
    "Local URI paths are decoded once, resolved case-sensitively from the containing file, and checked only against this payload; nested percent encoding and backslashes are rejected.",
    "Directory targets require payload descendants; an empty URI path refers to the containing file. Query strings and fragment identifiers are not validated.",
    "Explicit HTTP(S), mailto, data, and fragment-only targets are excluded; no remote resource or anchor is checked. Other schemes are reported as unsupported.",
    "A complete leading --- frontmatter block is skipped. HTML reference attributes are reported as uninspected; HTML, metadata semantics, scripts, and generated paths are not evaluated.",
    "Findings omit source excerpts and raw destinations. A target is included only when it identifies an existing payload file or directory.",
    "ok means no reported errors in this scope; it is not a security verdict or complete skill-specification validation.",
]


def _positioned(rule, token_type):
    def wrapped(state, silent):
        offset, before = state.pos, len(state.tokens)
        matched = rule(state, silent)
        if matched and not silent:
            for token in state.tokens[before:]:
                if token.type == token_type:
                    token.meta[_OFFSET] = offset
                    break
        return matched

    return wrapped


def _parser() -> MarkdownIt:
    parser = MarkdownIt("commonmark")
    # The audit must see file:/drive/unknown schemes, rather than having the
    # renderer's link validation silently leave them as ordinary text.
    parser.validateLink = lambda value: True
    parser.normalizeLink = lambda value: value
    for name, rule, token_type in (
        ("link", link, "link_open"),
        ("image", image, "image"),
        ("autolink", autolink, "link_open"),
        ("html_inline", html_inline, "html_inline"),
    ):
        parser.inline.ruler.at(name, _positioned(rule, token_type))
    return parser


class _HTMLReferences(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = False

    def handle_starttag(self, tag, attrs):
        self.found |= any(
            name.lower() in {"href", "src", "srcset", "poster", "action", "data", "xlink:href"}
            for name, _ in attrs
        )

    handle_startendtag = handle_starttag


def _has_html_reference(content: str) -> bool:
    parser = _HTMLReferences()
    parser.feed(content)
    parser.close()
    return parser.found


def _without_frontmatter(source: str) -> tuple[str, bool]:
    lines = source.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\n \t") != "---":
        return source, False
    for index in range(1, len(lines)):
        if lines[index].rstrip("\n \t") in {"---", "..."}:
            # Preserve all physical line numbers without treating metadata as
            # Markdown. This intentionally does not parse or validate YAML.
            prefix = "\n" * sum(line.endswith("\n") for line in lines[: index + 1])
            return prefix + "".join(lines[index + 1 :]), True
    return source, False


def _validate_payload(files: dict[str, bytes]) -> None:
    if not isinstance(files, dict):
        raise TypeError("files must be a dictionary of relative paths to bytes")
    for path, content in files.items():
        if not isinstance(path, str) or not isinstance(content, bytes):
            raise TypeError("files must contain string keys and byte values")
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or ":" in path
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ValueError("payload keys must be canonical relative POSIX paths")


def audit_files(files: dict[str, bytes]) -> dict:
    """Return bounded-scope reference findings without reading outside ``files``.

    Invalid library argument types/keys raise TypeError/ValueError. Markdown
    content errors are ordinary findings. Warnings and information alone do not
    make ``ok`` false; callers should read the returned scope and findings.
    """
    _validate_payload(files)
    findings: list[dict] = []
    markdown_files = 0
    local_links = 0
    parser = _parser()
    directories = {""}
    for path in files:
        parts = path.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    known_paths = set(files) | directories
    folded = {}
    for path in sorted(known_paths):
        folded.setdefault(path.casefold(), path)

    def add(severity, code, path, line, message, target=None):
        findings.append(
            {"severity": severity, "code": code, "path": path, "line": line,
             "message": message, "target": target}
        )

    if "SKILL.md" not in files:
        add("error", "missing-skill", "SKILL.md", None, "The payload requires a root SKILL.md file.")

    def check_target(raw: str, path: str, line: int | None):
        nonlocal local_links
        if raw.startswith("#"):
            return
        scheme_match = _SCHEME.match(raw)
        scheme = scheme_match.group(1).lower() if scheme_match else None
        if scheme in {"http", "https", "mailto", "data"}:
            return
        if scheme and scheme != "file" and not _DRIVE.match(raw):
            add("warning", "unsupported-uri-scheme", path, line,
                "This URI scheme is outside the local-reference audit scope.")
            return

        local_links += 1
        if scheme == "file" or _DRIVE.match(raw) or raw.startswith(("/", "\\")):
            add("error", "absolute-local-target", path, line,
                "A local reference must be relative to the containing Markdown file.")
            return
        # Split actual URI delimiters before decoding. An encoded # remains part
        # of the filename rather than becoming a fragment delimiter.
        uri_path = raw.split("#", 1)[0].split("?", 1)[0]
        if _BAD_ESCAPE.search(uri_path):
            add("error", "invalid-uri-encoding", path, line, "The local URI path has an invalid percent escape.")
            return
        try:
            decoded = unquote_to_bytes(uri_path).decode("utf-8")
        except UnicodeError:
            add("error", "invalid-uri-encoding", path, line, "The local URI path is not valid UTF-8.")
            return
        if _ESCAPE.search(decoded):
            add("error", "nested-uri-encoding", path, line,
                "Nested percent encoding is unsupported; use a single URI encoding.")
            return
        if decoded.startswith(("/", "\\")) or _DRIVE.match(decoded):
            add("error", "absolute-local-target", path, line,
                "The decoded local reference is absolute rather than payload-relative.")
            return
        if "\\" in decoded or ":" in decoded or any(ord(char) < 32 or ord(char) == 127 for char in decoded):
            add("error", "invalid-local-target", path, line,
                "The local URI path contains an unsupported separator or character.")
            return
        if not decoded:
            return  # Empty path (including query-only) refers to this file.
        parts = path.split("/")[:-1]
        for part in decoded.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if not parts:
                    add("error", "escaping-local-target", path, line,
                        "The local reference escapes the payload root.")
                    return
                parts.pop()
            else:
                parts.append(part)
        resolved = "/".join(parts)
        directory_only = decoded.endswith("/") or decoded.split("/")[-1] in {".", ".."}
        exists = resolved in directories if directory_only else resolved in known_paths
        if exists:
            return
        if resolved.casefold() in folded:
            known = folded[resolved.casefold()]
            if known != resolved:
                add("error", "target-case-mismatch", path, line,
                    "The reference does not match the case of its payload target.", known or ".")
                return
        add("error", "missing-local-target", path, line,
            "The local reference has no matching payload file or directory.")

    for path in sorted(files):
        if not path.lower().endswith(_MARKDOWN_SUFFIXES):
            continue
        markdown_files += 1
        try:
            source = files[path].decode("utf-8-sig")
        except UnicodeDecodeError:
            add("error", "invalid-markdown-utf8", path, None, "Markdown payload files must use UTF-8.")
            continue
        source = source.replace("\r\n", "\n").replace("\r", "\n")
        source, frontmatter = _without_frontmatter(source)
        if frontmatter:
            add("info", "frontmatter-not-checked", path, 1,
                "Leading frontmatter was excluded; metadata semantics are not validated.")
        for block in parser.parse(source):
            start_line = block.map[0] + 1 if block.map else None
            if block.type == "html_block" and _has_html_reference(block.content):
                add("info", "html-reference-not-checked", path, start_line,
                    "HTML reference attributes are present but are not resolved by this audit.")
            if block.type != "inline":
                continue
            breaks = [index for index, char in enumerate(block.content) if char == "\n"]
            for token in block.children or []:
                offset = token.meta.get(_OFFSET)
                line = start_line
                if line is not None and isinstance(offset, int):
                    line += bisect_right(breaks, offset)
                if token.type in {"link_open", "image"}:
                    target = token.attrGet("href" if token.type == "link_open" else "src")
                    if target is not None:
                        check_target(target, path, line)
                elif token.type == "html_inline" and _has_html_reference(token.content):
                    add("info", "html-reference-not-checked", path, line,
                        "HTML reference attributes are present but are not resolved by this audit.")
                # Image-alt children become alternative text, not extra resource
                # requests; deliberately do not recurse into their token trees.

    findings.sort(key=lambda item: (item["path"], item["line"] or 0, item["code"], item["target"] or ""))
    return {
        "ok": not any(item["severity"] == "error" for item in findings),
        "findings": findings,
        "stats": {"files": len(files), "markdown_files": markdown_files, "local_links": local_links},
        "scope": list(_SCOPE),
    }
