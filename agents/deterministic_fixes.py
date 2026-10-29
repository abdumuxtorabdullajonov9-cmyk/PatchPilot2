import base64
import hashlib
import re
import urllib.request
from urllib.parse import urlparse


def _line_offsets(content: str) -> list:
    offs = [0]
    for m in re.finditer(r"\n", content):
        offs.append(m.end())
    return offs


def _find_tag(content: str, finding: dict, tag_names: list):
    """Semgrep ko'rsatgan qatordan boshlab birinchi mos <tag ...> ning (boshi, oxiri) ni topadi."""
    s = finding.get("start", {}).get("line", 1)
    e = finding.get("end", {}).get("line", s)
    offs = _line_offsets(content)
    base = offs[min(max(s - 1, 0), len(offs) - 1)]
    limit = offs[e] if e < len(offs) else len(content)

    pattern = re.compile(r"<(?:%s)\b" % "|".join(tag_names), re.IGNORECASE)
    m = pattern.search(content, base)
    if not m or m.start() >= limit:
        return None

    quote = None
    j = m.start()
    while j < len(content):
        ch = content[j]
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == ">":
            return m.start(), j + 1
        j += 1
    return None


def fix_csrf_token(content: str, finding: dict):
    span = _find_tag(content, finding, ["form"])
    if not span:
        return None, "could not locate the <form> tag at the reported line"
    start, end = span

    close = re.search(r"</form\s*>", content[end:], re.IGNORECASE)
    body = content[end:end + close.start()] if close else content[end:end + 3000]
    if "csrf_token" in content[start:end] or "csrf_token" in body:
        return None, "csrf_token is already present in this form"

    eol = "\r\n" if "\r\n" in content else "\n"
    line_start = content.rfind("\n", 0, start) + 1
    indent = re.match(r"[ \t]*", content[line_start:]).group(0) + "    "

    insertion = eol + indent + "{% csrf_token %}"
    return content[:end] + insertion + content[end:], ""


def fix_missing_integrity(content: str, finding: dict):
    span = _find_tag(content, finding, ["script", "link"])
    if not span:
        return None, "could not locate the <script>/<link> tag at the reported line"
    start, end = span
    tag = content[start:end]

    if re.search(r"\bintegrity\s*=", tag, re.IGNORECASE):
        return None, "tag already has an integrity attribute"

    m = re.search(r"""\b(?:src|href)\s*=\s*(["'])(.*?)\1""", tag, re.IGNORECASE | re.DOTALL)
    if not m:
        return None, "no src/href attribute found in the tag"

    url = m.group(2).strip()
    if "{{" in url or "{%" in url:
        return None, "URL contains a template expression, hash cannot be computed"
    if url.startswith("//"):
        url = "https:" + url
    if not re.match(r"https?://", url, re.IGNORECASE):
        return None, f"URL is not absolute ({url[:60]}), hash cannot be computed"
    if urlparse(url).path in ("", "/"):
        return None, (
            f"the URL {url} points to a site root, not to a file. If your template really contains this link "
            "it is incomplete and the CDN file cannot load: check this line in your repository"
        )

    data, last_err = None, ""
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PatchPilot/1.0"})
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = resp.read()
            break
        except Exception as e:
            last_err = str(e)
    if data is None:
        return None, (
            f"could not download {url} ({last_err}). Compute the hash yourself: "
            f"curl -s {url} | openssl dgst -sha384 -binary | openssl base64 -A  "
            "and add integrity=\"sha384-<hash>\" crossorigin=\"anonymous\" to the tag"
        )

    digest = base64.b64encode(hashlib.sha384(data).digest()).decode()
    attrs = f' integrity="sha384-{digest}"'
    if not re.search(r"\bcrossorigin\b", tag, re.IGNORECASE):
        attrs += ' crossorigin="anonymous"'

    close_idx = len(tag) - 2 if tag.endswith("/>") else len(tag) - 1
    new_tag = tag[:close_idx] + attrs + tag[close_idx:]
    return content[:start] + new_tag + content[end:], ""

# qoida (check_id) -> tuzatuvchi funksiya. Bular AI'siz, aniq kod bilan tuzatiladi.
DETERMINISTIC_FIXERS = {
    "python.django.security.django-no-csrf-token.django-no-csrf-token": fix_csrf_token,
    "html.security.audit.missing-integrity.missing-integrity": fix_missing_integrity,
}