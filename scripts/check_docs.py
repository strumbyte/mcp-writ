#!/usr/bin/env python3
"""Check public Markdown encoding, local links, and heading anchors offline."""

from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\s*\)")


def prose(text):
    """Omit fenced examples, which may intentionally contain placeholder links."""
    result = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            result.append(line)
    return "\n".join(result)


def anchors(text):
    ids = set()
    counts = {}
    for line in prose(text).splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        title = re.sub(r"<[^>]*>", "", match.group(1)).lower()
        slug = "".join(
            char for char in title
            if char in "_-" or char.isspace()
            or unicodedata.category(char)[0] in "LNM"
        )
        slug = re.sub(r"\s", "-", slug)
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        ids.add(f"{slug}-{count}" if count else slug)
    ids.update(re.findall(r'<a\s+(?:id|name)=[\"\']([^\"\']+)[\"\']', text))
    return ids


def main():
    files = sorted({
        *ROOT.glob("*.md"),
        *(ROOT / "docs").rglob("*.md"),
        *(ROOT / "tests").rglob("*.md"),
        *(ROOT / ".github").rglob("*.md"),
    })
    documents = {}
    errors = []
    for path in files:
        label = path.relative_to(ROOT).as_posix()
        try:
            data = path.read_bytes()
            documents[path.resolve()] = data.decode("utf-8")
            if data.startswith(b"\xef\xbb\xbf") or b"\r" in data:
                errors.append(f"{label}: use UTF-8 without BOM and LF line endings")
        except UnicodeDecodeError:
            errors.append(f"{label}: invalid UTF-8")
    for path, text in documents.items():
        label = path.relative_to(ROOT).as_posix()
        for match in LINK.finditer(prose(text)):
            value = match.group(1).strip("<>")
            url = urlsplit(value)
            if url.scheme or url.netloc:
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.is_relative_to(ROOT) or not target.exists():
                errors.append(f"{label}: missing local target {value}")
            elif url.fragment and target in documents:
                if unquote(url.fragment) not in anchors(documents[target]):
                    errors.append(f"{label}: missing heading anchor {value}")
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Checked {len(documents)} Markdown files: encoding and local links OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
