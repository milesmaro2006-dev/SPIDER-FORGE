"""URL utilities for the crawler."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit, urlunsplit

from spiderforge.utils.urls import normalize_url

SKIP_EXTENSIONS: set[str] = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    # Media
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".webm", ".mkv", ".flv", ".ogg",
    # Archives
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    # Documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Binary
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg",
    # Data
    ".csv", ".tsv",
    # Static web assets (no vulnerability surface worth scanning)
    ".css", ".scss", ".sass", ".less",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".map", ".webmanifest",
}


SKIP_SCHEMES = (
    "javascript:", "mailto:", "tel:", "data:", "sms:",
    "file:", "ftp:", "ftps:", "ws:", "wss:", "about:",
)


def is_http_url(url: str) -> bool:
    try:
        return urlsplit(url).scheme.lower() in {"http", "https"}
    except Exception:
        return False


def should_skip_by_extension(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except Exception:
        return True

    filename = path.rsplit("/", 1)[-1]
    if "." not in filename:
        return False

    # Handle double extensions like `.min.js`, `.min.css`
    # by checking the last 1 and last 2 tokens
    parts = filename.rsplit(".", 2)
    if len(parts) >= 2:
        ext1 = "." + parts[-1]
        if ext1 in SKIP_EXTENSIONS:
            return True
        if len(parts) >= 3:
            ext2 = "." + parts[-2] + "." + parts[-1]
            if ext2 in SKIP_EXTENSIONS:
                return True

    return False


def normalize_and_validate(
    url: str,
    *,
    base_url: str,
) -> str | None:
    if not url:
        return None

    url = url.strip()
    if not url:
        return None

    if url.startswith("#"):
        return None

    lowered = url.lower()
    if lowered.startswith(SKIP_SCHEMES):
        return None

    from urllib.parse import urljoin
    try:
        absolute = urljoin(base_url, url)
    except Exception:
        return None

    try:
        normalized = normalize_url(absolute, strip_fragment=True, sort_query=True)
    except Exception:
        return None

    if not is_http_url(normalized):
        return None

    if should_skip_by_extension(normalized):
        return None

    return normalized


def extract_query_params(url: str) -> list[str]:
    try:
        parsed = urlsplit(url)
    except Exception:
        return []
    if not parsed.query:
        return []

    names: list[str] = []
    seen: set = set()
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in seen:
            seen.add(key)
            names.append(key)
    return names


def path_without_query(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
