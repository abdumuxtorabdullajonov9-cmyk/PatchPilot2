import os
import shutil
import tempfile
from collections import Counter

from tools.scanner_tool import scan_repo, scan_repo_full, norm_path


def verify_fix(original_repo_path: str, file_relative_path: str, fixed_code: str) -> dict:
    """Eski funksiya (main.py va benchmark.py uchun): butun repoda 0 ta topilma qolishini talab qiladi."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_repo = os.path.join(tmp_dir, "repo")
        shutil.copytree(original_repo_path, tmp_repo)

        target_file = os.path.join(tmp_repo, file_relative_path)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(fixed_code)

        new_findings = scan_repo(tmp_repo)

        return {
            "success": len(new_findings) == 0,
            "remaining_findings": len(new_findings),
            "details": new_findings,
        }


def verify_patches(repo_root: str, patched_files: dict, before_findings: list) -> dict:
    """
    Tuzatilgan fayllarni repo_root ichiga yozadi (bu vaqtinchalik klon bo'lishi kerak!),
    qayta skanerlaydi va har bir (qoida, fayl) uchun 'oldin -> keyin' sonini solishtiradi.
    """
    for rel, content in patched_files.items():
        target = os.path.join(repo_root, *rel.split("/"))
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write(content)

    after = scan_repo_full(repo_root)
    if not after["ok"]:
        return {"ok": False, "error": after.get("error", "re-scan failed")}

    before_c = Counter((f.get("check_id"), norm_path(f.get("path", ""))) for f in before_findings)
    after_c = Counter((f.get("check_id"), norm_path(f.get("path", ""))) for f in after["results"])
    new_issues = [(k, n - before_c.get(k, 0)) for k, n in after_c.items() if n > before_c.get(k, 0)]

    return {
        "ok": True,
        "before": before_c,
        "after": after_c,
        "new_issues": new_issues,
        "total_before": len(before_findings),
        "total_after": len(after["results"]),
    }