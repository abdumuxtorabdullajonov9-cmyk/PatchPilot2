import time
from tools.scanner_tool import scan_repo
from agents.triage_agent import triage_finding
from agents.fixer_agent import fix_finding
from tools.sandbox_tool import verify_fix
import shutil
import os

def reset_from_templates():
    template_root = "examples/_templates"
    for folder in os.listdir(template_root):
        src = os.path.join(template_root, folder, "bad_code.py")
        dst = os.path.join("examples", folder, "bad_code.py")
        if os.path.exists(src):
            shutil.copy(src, dst)
    print("Barcha namunalar asl holatga qaytarildi.\n")

TEST_REPOS = [
    ("examples/vulnerable_repo", "bad_code.py"),
    ("examples/vuln_hardcoded_secret", "bad_code.py"),
    ("examples/vuln_sql_injection", "bad_code.py"),
    ("examples/vuln_insecure_deserialization", "bad_code.py"),
    ("examples/vuln_weak_crypto", "bad_code.py"),
]


def run_benchmark():
    reset_from_templates()
    report = []

    for repo_path, file_name in TEST_REPOS:
        file_path = f"{repo_path}/{file_name}"
        print(f"\n=== {repo_path} ===")

        start = time.time()
        findings = scan_repo(repo_path)
        found_count = len(findings)

        with open(file_path, "r", encoding="utf-8") as f:
            current_code = f.read()

        fixed_count = 0
        for f in findings:
            result = triage_finding(f)
            if result["is_real_vulnerability"]:
                current_code = fix_finding(f, current_code, file_path=file_path)
                fixed_count += 1

        verified = False
        if fixed_count > 0:
            verification = verify_fix(repo_path, file_name, current_code)
            verified = verification["success"]
            if verified:
                with open(file_path, "w", encoding="utf-8") as out:
                    out.write(current_code)

        elapsed = time.time() - start

        report.append({
            "repo": repo_path,
            "found": found_count,
            "fixed_attempted": fixed_count,
            "verified_success": verified,
            "time_sec": round(elapsed, 1),
        })

        status = "✅" if verified else ("⚠️ qisman" if fixed_count > 0 else "❌")
        print(f"{status} Topildi: {found_count}, Tuzatilgan: {fixed_count}, Tasdiqlandi: {verified}, Vaqt: {elapsed:.1f}s")

    print("\n\n========== YAKUNIY HISOBOT ==========")
    print(f"{'Repo':<40} {'Topildi':<10} {'Tuzatildi':<12} {'Tasdiqlandi':<12} {'Vaqt(s)':<8}")
    for r in report:
        print(f"{r['repo']:<40} {r['found']:<10} {r['fixed_attempted']:<12} {str(r['verified_success']):<12} {r['time_sec']:<8}")

    total_found = sum(r["found"] for r in report)
    total_verified = sum(1 for r in report if r["verified_success"])
    times = [r["time_sec"] for r in report]
    avg_time = sum(times) / len(times)

    print(f"\nJami: {total_found} ta zaiflik topildi, {total_verified}/{len(report)} repo to'liq tuzatildi.")
    print(f"O'rtacha vaqt: {avg_time:.1f}s (eng tez: {min(times)}s, eng sekin: {max(times)}s)")
    print("Eslatma: vaqt asosan Nemotron API serverining joriy yuklamasiga bog'liq.")


if __name__ == "__main__":
    run_benchmark()