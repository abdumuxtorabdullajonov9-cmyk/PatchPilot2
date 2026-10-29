from agents.llm_client import client, MODEL_ULTRA


def fix_finding(finding: dict, file_content: str, file_path: str = "") -> str:
    """Nemotron Ultra yordamida bitta zaiflikni tuzatadi va to'liq yangilangan fayl matnini qaytaradi."""

    check_id = finding.get("check_id", "noma'lum")
    message = finding.get("extra", {}).get("message", "")
    line = finding.get("start", {}).get("line", "?")

    file_extension = file_path.split(".")[-1] if "." in file_path else ""

    prompt = (
        "Siz tajribali, ko'p tilli xavfsizlik muhandisisiz. "
        f"Quyidagi faylda ({file_extension} tilida yozilgan) xavfsizlik zaifligi bor.\n\n"
        f"Qoida: {check_id}\n"
        f"Qator: {line}\n"
        f"Muammo: {message}\n\n"
        "To'liq fayl matni:\n"
        "-----\n"
        f"{file_content}\n"
        "-----\n\n"
        "Vazifa: faylni tuzating, faqat aynan shu zaiflikni bartaraf eting, "
        "boshqa kodni o'zgartirmang, funksiya va o'zgaruvchi nomlarini saqlang, "
        "kodning dasturlash tilini o'zgartirmang.\n"
        "FAQAT tuzatilgan to'liq kodni qaytaring, hech qanday izoh, "
        "tushuntirish yoki kod bloki belgilarisiz."
    )

    resp = client.chat.completions.create(
        model=MODEL_ULTRA,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=4096,
    )

    fixed_code = resp.choices[0].message.content.strip()

    if fixed_code.startswith("```"):
        lines = fixed_code.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        fixed_code = "\n".join(lines)

    return fixed_code


def fix_multiple_findings(findings: list[dict], file_content: str, file_path: str = "") -> str:
    """Bitta fayldagi bir nechta zaiflikni BIR so'rovda birga tuzatadi."""

    file_extension = file_path.split(".")[-1] if "." in file_path else ""

    issues_text = "\n".join(
        f"- Qoida: {f.get('check_id')}, Qator: {f.get('start', {}).get('line', '?')}, "
        f"Muammo: {f.get('extra', {}).get('message', '')}"
        for f in findings
    )

    prompt = (
        "Siz tajribali, ko'p tilli xavfsizlik muhandisisiz. "
        f"Quyidagi faylda ({file_extension} tilida yozilgan) BIR NECHTA xavfsizlik zaifligi bor.\n\n"
        f"Aniqlangan muammolar:\n{issues_text}\n\n"
        "To'liq fayl matni:\n"
        "-----\n"
        f"{file_content}\n"
        "-----\n\n"
        "Vazifa: faylni tuzating, YUQORIDA SANAB O'TILGAN BARCHA muammolarni bartaraf eting, "
        "boshqa kodni o'zgartirmang, strukturani saqlang.\n"
        "FAQAT tuzatilgan to'liq fayl matnini qaytaring, hech qanday izoh yoki kod bloki belgilarisiz."
    )

    resp = client.chat.completions.create(
        model=MODEL_ULTRA,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=4096,
    )

    fixed_code = resp.choices[0].message.content.strip()

    if fixed_code.startswith("```"):
        lines = fixed_code.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        fixed_code = "\n".join(lines)

    return fixed_code