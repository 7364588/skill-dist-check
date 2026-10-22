# Skill Dist Check

[![Tests](https://github.com/7364588/skill-dist-check/actions/workflows/tests.yml/badge.svg)](https://github.com/7364588/skill-dist-check/actions/workflows/tests.yml)

**Check the files that actually ship in an Agent Skill.** Find missing Markdown
references, build a reproducible ZIP, and compare its contents with a relocated
installation. Python 3.11+, offline operation, no API keys.

[Try the interactive synthetic report](https://7364588.github.io/skill-dist-check/)
· [Releases](https://github.com/7364588/skill-dist-check/releases)

```text
skill directory ── check ── pack ── release.zip
                                      │
                       verify ────────┤
                                      └── compare installed directory
```

## Why

An installer can omit files that were included in a source hash, leaving users
unable to reproduce that hash from their installed copy
([reported example](https://github.com/vercel-labs/skills/issues/806)). A renamed
reference can also leave a syntactically valid `SKILL.md` pointing to a missing
file ([reported example](https://github.com/agentskills/agentskills/discussions/563)).

This tool gives publishers and users a shared, byte-level inventory of the exact
payload. It complements metadata validators and installers: it does not install
skills, infer their capabilities, or evaluate how well an agent follows them.

## Install

Initial alpha; distributed through GitHub, **not published on PyPI**.

```sh
python -m pip install https://github.com/7364588/skill-dist-check/releases/download/v0.1.0/skill_dist_check-0.1.0-py3-none-any.whl
skill-dist-check --help
```

For development, clone this repository and run `python -m pip install -e .`.
The only direct runtime dependency is `markdown-it-py` for CommonMark parsing.

## A complete workflow

From a clone of this repository:

```sh
# Inspect the final file inventory and local references before publishing.
skill-dist-check check examples/release-notes --format json

# Package checked bytes. Existing output files are never overwritten.
skill-dist-check pack examples/release-notes --output release.zip

# Check archive structure, inventory correspondence and every content hash.
skill-dist-check verify release.zip --html verified.html

# After extracting this trusted example ZIP with a standard ZIP tool:
skill-dist-check verify release.zip --directory extracted/skill --html installed.html

# Compare two releases. Differences produce exit code 1 for CI review.
skill-dist-check diff release.zip next-release.zip --format json
```

Every command accepts `--format text|json` and `--html new-report.html`. An HTML
output must be outside the inspected skill directory. Reports are published
atomically without overwriting and require a filesystem supporting hard links.
An archive already created by `pack` remains if subsequent report or stdout
delivery fails; verify it before retrying. Closed output pipes produce exit 2.
An HTML
report is self-contained: searchable file paths, change/severity filters,
packaged hashes and audit findings. It makes no network requests and embeds no
file bodies. It can still contain sensitive filenames and hashes.

`verify --directory` detects added, removed and changed regular files, including
a missing `SKILL.md`. The directory may live anywhere the caller explicitly
chooses. The tool never extracts the ZIP, discovers client installations, runs a
script or modifies an installed skill. Copy an untrusted installation to a
stable, isolated location before inspecting it; live filesystem mutation is
outside the tool's guarantees.

| Exit | Meaning |
| --- | --- |
| `0` | Documented checks passed, or compared payloads are identical |
| `1` | Static reference errors or file differences need review |
| `2` | Usage, I/O, invalid archive, unsupported path, or resource-limit error |

Warnings and information findings do not fail a check. Invalid or tampered
archives exit 2 before a report claims verification. A changed release exits 1
even when the change was intentional.

## What goes into a payload

All regular files below the explicit root are included except these names at
any depth: `.git`, `.venv`, `node_modules`, `__pycache__`, `.DS_Store`.
Empty directories are not recorded. ZIP assets are included like other files.
Use repeated `--exclude` flags for additional exclusions:

```sh
skill-dist-check check ./my-skill --exclude '.env*' --exclude 'private/*' --format json
skill-dist-check pack ./my-skill --exclude '.env*' --exclude 'private/*' --output ./release.zip
skill-dist-check verify ./release.zip --directory ./installed/skill --exclude '.env*' --exclude 'private/*'
```

Patterns use Python `fnmatchcase` against the relative POSIX path; they are case
sensitive and `*` can span `/`. A matching directory is pruned. This is **not**
gitignore syntax: `.env*` matches only a root path beginning with `.env`; add
`*/.env*` for nested paths. Use the same extra exclusions when comparing an
installation, otherwise extra files are correctly reported as drift.

Exclusions are not secret detection. Dotfiles other than the defaults are
included. Review the JSON inventory before distributing an archive. Excluding a
file referenced by a supported Markdown link causes `pack` to fail. Keep release
archives outside the source directory to avoid including older releases.

## Reference-check boundaries

Checks cover CommonMark links and images in `.md` and `.markdown` files,
including resolved reference-style links, using `markdown-it-py`. Relative
targets resolve from the Markdown file containing the link, with case-sensitive
matching; URL query strings and fragments are not part of the filename. Paths
are percent-decoded once; nested encodings and backslashes are rejected.
Directory links require at least one included descendant file.

Missing targets, absolute local targets, paths escaping the payload, missing root
`SKILL.md` and invalid UTF-8 Markdown are errors. Links inside fenced code are not
links. HTTP(S), mailto, data and fragment-only links are not fetched or checked;
other URI schemes produce a warning. Heading
anchors are not validated. Raw HTML, code snippets, frontmatter, unresolved
reference labels, prose commands and script behavior are outside coverage.

**Passing is not certification of universal client compatibility, security, full
Agent Skills metadata compliance, or runnable scripts.** In particular, command
paths can depend on a client's working directory even when every Markdown link
is valid ([reported example](https://github.com/WordPress/agent-skills/issues/86)).

## Artifact format and bounds

A standard ZIP contains `capsule.json` and files under `skill/`. The v1 manifest
has `format`, a sorted `files` array of `{path, size, sha256}`, and
`payload_sha256`. That final digest is SHA-256 over the file-record array encoded
as UTF-8 JSON with sorted keys, no extra whitespace and non-ASCII characters
unescaped. It covers paths, sizes and content digests, not filesystem roots or
timestamps. Exclusion rules and original filesystem permissions are not recorded.

The writer uses stored entries, sorted paths, fixed metadata and normalized file
permissions for identical ZIP bytes across supported systems. Script executable
bits are not preserved; invoke examples through their interpreter. Publishing a
new archive is atomic and requires a filesystem supporting hard links.

Verification accepts this bounded v1 format, not arbitrary ZIP layouts. It checks
exact manifest/payload correspondence, file sizes and SHA-256 hashes; rejects
duplicates, traversal, symlinks, Windows reparse points on collection,
nonportable paths and case/Unicode-normalization collisions. ZIP64, multipart
archives, ZIP extra fields and trailing bytes are unsupported. Stored and deflated entries are
accepted within limits.

| Bound | Limit |
| --- | --- |
| Payload files | 4,096 |
| Enumerated entries, including excluded files and empty directories | 16,384 |
| Per-file / total payload | 8 MiB / 32 MiB |
| Manifest / archive / ZIP directory metadata | 2 MiB / 40 MiB / 6 MiB |
| Path / component, UTF-8 bytes | 1,024 / 255 |
| Path depth | 64 components |

A manifest is not a signature: replacing both content and hashes can create a
different valid bundle. Compare against an independently trusted release or
digest. Hashes establish content identity, not the author's identity.

## Validation and development

```sh
python -m unittest discover -s tests -v
python scripts/smoke.py
python scripts/demo.py
```

CI installs the built wheel and exercises Linux (Python 3.11 and 3.14), Windows
and macOS (Python 3.12). The smoke workflow checks real ZIP creation, repeatable
bytes, relocation, reference failure, installed drift, release diff and exit
codes. `scripts/demo.py` regenerates the synthetic GitHub Pages report.

See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md) and
[CHANGELOG](CHANGELOG.md). MIT licensed.
