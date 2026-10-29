import unittest

import conftest  # noqa: F401  (openai stub + sys.path)
from agents import patcher
from tools import fix_risks

OLD = "from django import forms\n\nclass F(forms.Form):\n    password = forms.CharField()\n"
BAD = OLD.replace(
    "forms.CharField()",
    "forms.CharField(validators=[MinimumLengthValidator(), CommonPasswordValidator()])",
)


class FixRisksTest(unittest.TestCase):
    def test_password_validators_in_field_are_rejected(self):
        added = fix_risks.added_lines(OLD, BAD)
        self.assertIn("not callable", fix_risks.unsafe_fix_reason(added))

    def test_dangerous_additions_are_rejected(self):
        for code in ("requests.get(u, verify=False)", "eval(x)", "subprocess.run(c, shell=True)", "@csrf_exempt"):
            self.assertIsNotNone(fix_risks.unsafe_fix_reason(code), code)

    def test_safe_code_is_not_rejected(self):
        self.assertIsNone(fix_risks.unsafe_fix_reason("ast.literal_eval(x)\ncursor.execute(sql, params)"))

    def test_existing_dangerous_code_is_not_blamed_on_the_fix(self):
        old = "x = eval(a)\ny = 1\n"
        self.assertEqual(fix_risks.added_lines(old, old.replace("y = 1", "y = 2")), "y = 2")

    def test_require_post_gets_a_warning(self):
        notes = fix_risks.risk_notes("@require_POST\ndef cart_add(request):")
        self.assertEqual(len(notes), 1)
        self.assertIn("405", notes[0])
        self.assertEqual(fix_risks.risk_notes("def ok(): pass"), [])

    def test_patcher_finalize_rejects_unsafe_fix(self):
        result = {"note": "", "status": ""}
        out, imports, res = patcher._finalize(OLD, BAD, [], result, "apps/accounts/forms.py")
        self.assertEqual(res["status"], "rejected")
        self.assertEqual(out, OLD)

    def test_patcher_finalize_keeps_risk_notes_for_require_post(self):
        old = "def cart_add(request):\n    return 1\n"
        new = "@require_POST\ndef cart_add(request):\n    return 1\n"
        _, _, res = patcher._finalize(old, new, [], {"note": "", "status": ""}, "apps/cart/views.py")
        self.assertEqual(res["status"], "fixed")
        self.assertTrue(res["risk_notes"])


if __name__ == "__main__":
    unittest.main()
