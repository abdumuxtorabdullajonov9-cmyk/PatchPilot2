import re

GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?$")


def is_valid_github_url(url: str) -> bool:
    """Faqat https://github.com/<owner>/<repo> ko'rinishidagi manzillar qabul qilinadi.
    Bu `git clone` ga begona argument yoki lokal fayl yo'lini yashirib yuborishning oldini oladi."""
    return bool(GITHUB_URL_RE.match(url.strip()))
