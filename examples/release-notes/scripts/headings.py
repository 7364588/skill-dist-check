"""Synthetic example helper; Skill Dist Check never executes this file."""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description="Print headings from one explicitly chosen Markdown file.")
parser.add_argument("document", type=Path)
args = parser.parse_args()
for line in args.document.read_text(encoding="utf-8").splitlines():
    if line.startswith("#"):
        print(line)
