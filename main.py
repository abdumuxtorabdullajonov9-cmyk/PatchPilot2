from tools.scanner_tool import scan_repo
from agents.triage_agent import triage_finding
from agents.fixer_agent import fix_finding
from tools.sandbox_tool import verify_fix
from agents.pr_agent import open_pull_request


def main():
    repo_path = "examples/vulnerable_repo"
    file_name = "bad_code.py"
    file_path = f"{repo_path}/{file_name}"

    print(f"'{repo_path}' skanerlanmoqda...\n")
    findings = scan_repo(repo_path)
    print(f"Skaner topdi: {len(findings)} ta natija\n")

    with open(file_path, "r", encoding="utf-8") as f:
        current_code = f.read()

    real_vulns_fixed = 0

    for f in findings:
        print(f"Tahlil qilinmoqda: {f.get('check_id')} ...")
        result = triage_finding(f)
        print(f"  Haqiqiy zaiflikmi: {result['is_real_vulnerability']}")
        print(f"  Jiddiylik: {result['severity']}")
        print(f"  Izoh: {result['explanation']}\n")

        if result["is_real_vulnerability"]:
            print("Tuzatish yozilmoqda...\n")
            current_code = fix_finding(f, current_code, file_path=file_path)
            real_vulns_fixed += 1

    if real_vulns_fixed == 0:
        print("Haqiqiy zaiflik topilmadi, hech narsa o'zgartirilmadi.")
        return

    print(f"Jami {real_vulns_fixed} ta tuzatish qo'llanildi. Yakuniy tekshiruv...\n")
    verification = verify_fix(repo_path, file_name, current_code)

    if verification["success"]:
        print("✅ Barcha zaifliklar tuzatildi!\n")
        with open(file_path, "w", encoding="utf-8") as out:
            out.write(current_code)
        print(f"Fayl yangilandi: {file_path}\n")

        print("GitHub'da Pull Request ochilmoqda...\n")
        pr_url = open_pull_request(
            repo_full_name="abdumuxtorabdullajonov9-cmyk/patchpilot",
            file_relative_path=f"PatchPilot/{repo_path}/{file_name}",
            fixed_code=current_code,
        )
        print(f"✅ Pull Request ochildi: {pr_url}")
    else:
        print(f"❌ Hali ham {verification['remaining_findings']} ta muammo qoldi:")
        for d in verification["details"]:
            print(" -", d.get("check_id"))
        print("\nShunga qaramay, qisman tuzatilgan kodni ko'rib chiqing:\n")
        print(current_code)


if __name__ == "__main__":
    main()