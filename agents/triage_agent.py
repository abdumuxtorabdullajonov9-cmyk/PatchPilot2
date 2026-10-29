from agents.llm_client import client, MODEL_ULTRA

def triage_finding(finding: dict) -> dict:
    """Semgrep topilmasini Nemotron Ultra yordamida tahlil qiladi."""

    check_id = finding.get("check_id", "noma'lum")
    path = finding.get("path", "noma'lum")
    line = finding.get("start", {}).get("line", "?")
    message = finding.get("extra", {}).get("message", "")
    code_snippet = finding.get("extra", {}).get("lines", "")

    prompt = f"""Siz kiberxavfsizlik bo'yicha tajribali muhandissiz. Quyidagi statik tahlil (Semgrep) natijasini baholang.

Qoida: {check_id}
Fayl: {path}, qator: {line}
Xabar: {message}
Kod qatori: {code_snippet}

Quyidagi savollarga JAVOB BERING, FAQAT JSON formatida, boshqa hech narsa yozmang:
{{
  "is_real_vulnerability": true yoki false,
  "severity": "low" yoki "medium" yoki "high" yoki "critical",
  "explanation": "1-2 jumlada, nima uchun bu muammo ekanligi"
}}"""

    resp = client.chat.completions.create(
        model=MODEL_ULTRA,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
    )

    raw = resp.choices[0].message.content.strip()

    # Model ba'zan ```json``` bilan o'rab yuborishi mumkin, tozalaymiz
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:]

    import json
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {
            "is_real_vulnerability": None,
            "severity": "unknown",
            "explanation": f"Modelning javobi JSON emas: {raw[:200]}"
        }

    result["check_id"] = check_id
    result["path"] = path
    result["line"] = line
    return result