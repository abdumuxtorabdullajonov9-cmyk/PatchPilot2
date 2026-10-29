"""PatchPilot yadrosi uchun testlar. Tarmoq, Docker va API kaliti SHART EMAS.

Ishga tushirish:  python -m unittest discover -s tests -v
"""
import os
import sqlite3
import tempfile
import unittest

import conftest  # noqa: F401  (openai stub + sys.path; unittest conftest.py ni o'zi yuklamaydi)
from agents import ai_auditor, patcher
from agents.deterministic_fixes import fix_csrf_token, fix_missing_integrity
from tools import history
from tools.scanner_tool import norm_path
from tools.validators import is_valid_github_url


class ValidatorTests(unittest.TestCase):
    def test_accepts_normal_github_urls(self):
        for url in (
            "https://github.com/user/repo",
            "https://github.com/user/repo.git",
            "https://github.com/user/my-repo_2.0/",
        ):
            self.assertTrue(is_valid_github_url(url), url)

    def test_rejects_dangerous_inputs(self):
        for url in (
            "--upload-pack=touch /tmp/pwned",
            "file:///etc/passwd",
            "http://github.com/user/repo",
            "https://evil.com/user/repo",
            "https://github.com/user",
            "https://github.com/user/repo; rm -rf /",
            "",
        ):
            self.assertFalse(is_valid_github_url(url), url)


class ScannerHelpersTests(unittest.TestCase):
    def test_norm_path(self):
        self.assertEqual(norm_path("/src/app/views.py"), "app/views.py")
        self.assertEqual(norm_path("app\\views.py"), "app/views.py")


class DeterministicFixTests(unittest.TestCase):
    FORM = '<div>\n  <form method="post" action="/x">\n    <input name="a">\n  </form>\n</div>\n'

    def _finding(self, line):
        return {"start": {"line": line}, "end": {"line": line}}

    def test_csrf_token_inserted(self):
        new, note = fix_csrf_token(self.FORM, self._finding(2))
        self.assertEqual(note, "")
        self.assertIn("{% csrf_token %}", new)
        # token <form ...> tagidan keyin, <input> dan oldin turishi kerak
        self.assertLess(new.index("{% csrf_token %}"), new.index("<input"))

    def test_csrf_token_already_present(self):
        html = self.FORM.replace("<input", "{% csrf_token %}<input")
        new, note = fix_csrf_token(html, self._finding(2))
        self.assertIsNone(new)
        self.assertTrue(note.startswith("csrf_token is already present"))

    def test_integrity_skips_template_urls(self):
        html = '<script src="{{ cdn_url }}"></script>\n'
        new, note = fix_missing_integrity(html, self._finding(1))
        self.assertIsNone(new)
        self.assertIn("template expression", note)

    def test_integrity_skips_existing_attribute(self):
        html = '<script src="https://cdn.example.com/a.js" integrity="sha384-x"></script>\n'
        new, note = fix_missing_integrity(html, self._finding(1))
        self.assertIsNone(new)
        self.assertIn("already has", note)


class PatcherHelpersTests(unittest.TestCase):
    def test_splice_replaces_only_target_lines(self):
        src = "a\nb\nc\nd\n"
        out = patcher._splice(src, 2, 3, "B\nC")
        self.assertEqual(out, "a\nB\nC\nd\n")

    def test_splice_keeps_crlf(self):
        src = "a\r\nb\r\nc\r\n"
        out = patcher._splice(src, 2, 2, "B")
        self.assertEqual(out, "a\r\nB\r\nc\r\n")

    def test_splice_no_trailing_newline(self):
        out = patcher._splice("a\nb", 2, 2, "B")
        self.assertEqual(out, "a\nB")

    def test_count_changed(self):
        self.assertEqual(patcher._count_changed("a\nb\n", "a\nB\n"), 2)
        self.assertEqual(patcher._count_changed("a\n", "a\n"), 0)

    def test_syntax_guard(self):
        self.assertTrue(patcher._syntax_ok("x = 1\n", "a.py"))
        self.assertFalse(patcher._syntax_ok("x = (\n", "a.py"))
        self.assertFalse(patcher._syntax_ok("{bad", "a.json"))
        self.assertTrue(patcher._syntax_ok("anything <<<", "a.txt"))

    def test_clean_code_removes_model_separators(self):
        cleaned = patcher._clean_code("-----\nx = 1\n```\n", "x = 0")
        self.assertEqual(cleaned.strip(), "x = 1")

    def test_parse_answer(self):
        text = "<<<EXPLANATION>>>\nbad\n<<<IMPORTS>>>\nimport os\n<<<CODE>>>\nx = 1\n"
        explanation, imports, code = patcher._parse_answer(text)
        self.assertEqual(explanation, "bad")
        self.assertEqual(imports, ["import os"])
        self.assertEqual(code.strip(), "x = 1")
        self.assertIsNone(patcher._parse_answer("no markers here"))

    def test_add_python_imports(self):
        new, added = patcher._add_python_imports("import os\n\nx = 1\n", ["import secrets", "import os"])
        self.assertEqual(added, ["import secrets"])
        self.assertIn("import secrets", new)
        self.assertTrue(patcher._syntax_ok(new, "a.py"))

    def test_vendored_and_env_files_are_report_only(self):
        """Bu holatlarda model chaqirilmaydi va kod o'zgarmaydi."""
        finding = {
            "check_id": "x.y.z",
            "start": {"line": 1}, "end": {"line": 1},
            "extra": {"message": "m", "severity": "ERROR"},
        }
        for rel in ("staticfiles/admin/js/lib.js", ".env"):
            fr = patcher.patch_file(rel, "SECRET=1\n", [finding])
            self.assertEqual(fr["final"], fr["original"], rel)
            self.assertEqual(fr["results"][0]["method"], "report-only", rel)


class AuditorTests(unittest.TestCase):
    def test_parse_items_filters(self):
        text = (
            '[{"line": 5, "end_line": 6, "category": "SQL Injection", "severity": "high", '
            '"kind": "security", "title": "t", "explanation": "e", "confidence": 0.9},'
            ' {"line": 7, "severity": "low", "kind": "security", "confidence": 0.3},'
            ' {"line": 999, "severity": "high", "kind": "security", "confidence": 0.99},'
            ' {"line": 8, "severity": "low", "kind": "bug", "confidence": 0.99}]'
        )
        items = ai_auditor._parse_items(text, 1, 100, include_bugs=False)
        self.assertEqual([i["line"] for i in items], [5])
        with_bugs = ai_auditor._parse_items(text, 1, 100, include_bugs=True)
        self.assertEqual(sorted(i["line"] for i in with_bugs), [5, 8])

    def test_parse_items_garbage(self):
        self.assertEqual(ai_auditor._parse_items("not json", 1, 10, False), [])
        self.assertEqual(ai_auditor._parse_items("[1, 2]", 1, 10, False), [])

    def test_prompt_marks_code_as_untrusted(self):
        prompt = ai_auditor._build_prompt("a.py", ["x = 1"], 0, 1, False)
        self.assertIn("UNTRUSTED", prompt)

    def test_collect_source_files_skips_third_party(self):
        with tempfile.TemporaryDirectory() as root:
            for rel, body in (
                ("app/views.py", "x = 1\n"),
                ("node_modules/lib/a.js", "x"),
                ("static/app.min.js", "x"),
                ("logo.png", "x"),
            ):
                full = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w") as f:
                    f.write(body)
            found, skipped, _ = ai_auditor.collect_source_files(root)
            self.assertEqual(found, ["app/views.py"])
            self.assertIn("node_modules", skipped)


class HistoryTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = history.DB_PATH
            history.DB_PATH = os.path.join(tmp, "h.db")
            try:
                rep = {
                    "repo_url": "https://github.com/u/r",
                    "scan": {"scanned": ["a.py"]},
                    "total_findings": 1, "semgrep_findings": 1, "ai_findings": 0,
                    "duration": 1.5,
                    "files": [{
                        "rel_path": "a.py",
                        "results": [{
                            "line": 3, "check_id": "r.sql", "severity": "high", "status": "fixed",
                            "method": "ai", "note": "", "explanation": "e", "snippet": "s", "diff": "d",
                        }],
                    }],
                }
                sid = history.save_scan(rep)
                self.assertEqual(history.list_scans()[0]["fixed"], 1)
                self.assertEqual(history.get_scan(sid)["details"][0]["rule"], "r.sql")
                self.assertEqual(history.get_scan(9999), {})
            finally:
                history.DB_PATH = old


if __name__ == "__main__":
    unittest.main()
