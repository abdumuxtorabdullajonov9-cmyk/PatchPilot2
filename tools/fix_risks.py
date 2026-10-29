"""AI tuzatishlari uchun qo'shimcha xavfsizlik tekshiruvlari (tarmoq va API kaliti SHART EMAS).

1) unsafe_fix_reason: tuzatish ZARARLI yoki ISHLAMAYDIGAN kod qo'shsa, uni rad etadi.
2) risk_notes: tuzatish boshqa fayllarni ham o'zgartirishni talab qilsa, ogohlantiradi.
Faqat tuzatish QO'SHGAN qatorlar tekshiriladi, eski kod emas.
"""
import re

# Django parol validatorlari klass nusxasi bo'lib, maydon validatori sifatida CHAQIRIB BO'LMAYDI (TypeError).
_PWD_VALIDATOR_IN_FIELD = re.compile(
    r"validators\s*=\s*\[[^\]]*\b(?:MinimumLength|CommonPassword|NumericPassword|UserAttributeSimilarity)Validator\b",
    re.S,
)

_DANGEROUS = (
    (re.compile(r"verify\s*=\s*False"), "it turns off TLS certificate verification"),
    (re.compile(r"\beval\s*\("), "it adds eval()"),
    (re.compile(r"\bexec\s*\("), "it adds exec()"),
    (re.compile(r"shell\s*=\s*True"), "it adds shell=True"),
    (re.compile(r"\bos\.system\s*\("), "it adds os.system()"),
    (re.compile(r"\bcsrf_exempt\b"), "it disables CSRF protection (csrf_exempt)"),
    (re.compile(r"\bDEBUG\s*=\s*True\b"), "it enables DEBUG mode"),
)


def added_lines(old: str, new: str) -> str:
    """Tuzatish QO'SHGAN (eski faylda yo'q) qatorlar matni."""
    old_set = {ln.strip() for ln in old.splitlines()}
    return "\n".join(ln for ln in new.splitlines() if ln.strip() and ln.strip() not in old_set)


def unsafe_fix_reason(added: str):
    """Tuzatishni rad etish sababi (matn) yoki None."""
    if _PWD_VALIDATOR_IN_FIELD.search(added):
        return (
            "Django password validators cannot be used in a field's validators=[...] list (they are not callable "
            "and would crash the form). Use validate_password(value) inside clean_password() instead."
        )
    for pattern, why in _DANGEROUS:
        if pattern.search(added):
            return f"{why}, which makes the code less safe than before."
    return None


def risk_notes(added: str) -> list:
    """Odam e'tibor berishi kerak bo'lgan ogohlantirishlar ro'yxati."""
    notes = []
    if re.search(r"\brequire_POST\b|\brequire_http_methods\b", added):
        notes.append(
            "This makes a view accept POST only. Every template link (<a href>) or JS call that opens this URL with "
            "GET will return 405 Method Not Allowed. Change them to <form method=\"post\"> with {% csrf_token %} "
            "before merging."
        )
    return notes
