import json
import os
import subprocess

RULE_CONFIGS = [
    "--config=auto",
    "--config=p/security-audit",
    "--config=p/secrets",
    "--config=p/owasp-top-ten",
    "--config=p/python",
    "--config=p/javascript",
    "--config=p/typescript",
    "--config=p/django",
    "--config=p/flask",
    "--config=p/docker",
    "--config=p/sql-injection",
    "--config=p/command-injection",
]


def norm_path(path: str) -> str:
    """Semgrep konteyner yo'lini ('/src/...') repo ichidagi nisbiy yo'lga aylantiradi."""
    p = path.replace("\\", "/")
    if p.startswith("/src/"):
        p = p[len("/src/"):]
    return p.lstrip("/")


def scan_repo_full(repo_path: str) -> dict:
    """Semgrep'ni Docker orqali ishga tushiradi. Topilmalar bilan birga qamrov hisobotini ham qaytaradi."""
    abs_path = os.path.abspath(repo_path)
    rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "custom_rules.yml"))
    cache_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".semgrep_cache"))
    os.makedirs(cache_dir, exist_ok=True)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{abs_path}:/src",
        "-v", f"{rules_path}:/rules/custom_rules.yml",
        "-v", f"{cache_dir}:/root/.cache/semgrep",
        "semgrep/semgrep",
        "semgrep",
        *RULE_CONFIGS,
        "--config=/rules/custom_rules.yml",
        "--no-git-ignore",
        "--max-target-bytes=50000000",
        "--json", "/src",
    ]

    empty = {"results": [], "scanned": [], "skipped": [], "errors": [], "ok": False, "error": ""}

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=1500,
        )
    except subprocess.TimeoutExpired:
        empty["error"] = "Semgrep timed out"
        return empty
    except Exception as e:
        empty["error"] = f"Could not run Docker/Semgrep: {e}"
        return empty

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        empty["error"] = "Semgrep output could not be read: " + proc.stderr[:500]
        return empty

    paths = data.get("paths", {}) or {}
    return {
        "results": data.get("results", []),
        "scanned": paths.get("scanned", []) or [],
        "skipped": paths.get("skipped", []) or [],
        "errors": data.get("errors", []) or [],
        "ok": True,
        "error": "",
    }


def scan_repo(repo_path: str) -> list[dict]:
    """Eski kod (main.py, benchmark.py) bilan moslik uchun."""
    full = scan_repo_full(repo_path)
    if not full["ok"]:
        print("Skanerlashda xato:", full["error"])
    return full["results"]