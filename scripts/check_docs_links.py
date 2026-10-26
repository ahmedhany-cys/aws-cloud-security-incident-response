#!/usr/bin/env python3
"""Check that every relative link and image in the repository's Markdown files
points at a file or directory that exists.

Standard library only, so it runs anywhere Python 3 does (CI uses the runner's
python3). External URLs are not fetched: they are checked by hand before a
release because badge and stats services rate-limit automated fetches.

Usage: python3 scripts/check_docs_links.py   (exit 1 if anything is missing)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", ".terraform", "__pycache__", "node_modules"}
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#", "data:")

MD_LINK = re.compile(r'!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)')
HTML_REF = re.compile(r'(?:src|href)\s*=\s*"([^"]+)"')
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
FENCED_CODE = re.compile(r"```.*?```", re.S)


def link_targets(text: str) -> list[str]:
    text = HTML_COMMENT.sub("", text)
    text = FENCED_CODE.sub("", text)
    return [m.group(1) for m in MD_LINK.finditer(text)] + [
        m.group(1) for m in HTML_REF.finditer(text)
    ]


def main() -> int:
    missing: list[tuple[Path, str]] = []
    checked = 0
    for md in sorted(ROOT.rglob("*.md")):
        rel = md.relative_to(ROOT)
        if SKIP_DIRS & set(rel.parts):
            continue
        for raw in link_targets(md.read_text(encoding="utf-8")):
            if raw.startswith(SKIP_PREFIXES):
                continue
            path = raw.split("#", 1)[0]
            if not path:
                continue
            checked += 1
            if not (md.parent / path).exists():
                missing.append((rel, raw))
    for rel, raw in missing:
        print(f"MISSING  {rel}: {raw}")
    print(f"{checked} relative links checked, {len(missing)} missing")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
