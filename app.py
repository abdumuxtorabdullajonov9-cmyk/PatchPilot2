import os
import shutil
import subprocess
import tempfile
import time
from collections import Counter

import pandas as pd
import streamlit as st

from tools.scanner_tool import scan_repo_full, norm_path
from tools.sandbox_tool import verify_patches
from tools.history import save_scan, list_scans, get_scan
from tools.validators import is_valid_github_url
from agents.patcher import patch_file
from agents.ai_auditor import run_audit, recheck_region
from agents.pr_agent import open_pull_request_multi

st.set_page_config(page_title="PatchPilot", page_icon="🛡️", layout="wide")

st.title("🛡️ PatchPilot")
st.caption(
    "AI agent that finds security vulnerabilities in any language, shows exactly where they are, "
    "and proposes minimal, verified fixes. Powered by NVIDIA Nemotron on Nebius Token Factory."
)

LANGS = {
    "py": "python", "js": "javascript", "ts": "typescript", "html": "html", "htm": "html",
    "json": "json", "yml": "yaml", "yaml": "yaml", "css": "css", "sh": "bash",
    "java": "java", "go": "go", "rb": "ruby", "php": "php",
}
THIRD_PARTY = ("staticfiles/", "node_modules/", "vendor/", "site-packages/", "/dist/", ".min.")


def lang_of(path: str):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return LANGS.get(ext)


def is_ai(check_id: str) -> bool:
    return check_id.startswith("ai.audit.")


def source_of(check_id: str) -> str:
    return "AI audit" if is_ai(check_id) else "Semgrep rules"


def status_of(r: dict) -> str:
    if r["status"] == "fixed":
        return "fixed"
    if r["status"] == "false_positive":
        return "false positive"
    return "not fixed"


def clone_repo(repo_url: str, dest: str, status):
    if not is_valid_github_url(repo_url):
        return False, "Invalid URL: only https://github.com/<owner>/<repo> is accepted."
    last_err = ""
    for attempt in range(1, 4):
        r = subprocess.run(
            ["git", "clone", "-c", "core.autocrlf=false", "--depth", "1", "--", repo_url, dest],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return True, ""
        last_err = r.stderr[-500:]
        status.write(f"⚠️ Clone attempt {attempt} failed, retrying...")
        shutil.rmtree(dest, ignore_errors=True)
        time.sleep(2)
    return False, last_err


def analyze_repo(repo_url: str, status, ai_max_files: int, include_bugs: bool) -> dict:
    started = time.time()
    td = tempfile.TemporaryDirectory(prefix="patchpilot_")
    try:
        local_path = os.path.join(td.name, "repo")

        status.write("📥 Cloning repository...")
        ok, err = clone_repo(repo_url, local_path, status)
        if not ok:
            raise RuntimeError(err if err.startswith("Invalid URL") else f"Clone failed after 3 attempts: {err}")

        # .git bu repozitoriya metama'lumoti, loyiha kodi emas. Qolgan HAMMA narsa skanerlanadi.
        with open(os.path.join(local_path, ".semgrepignore"), "w", encoding="utf-8") as f:
            f.write(".git/\n")

        status.write("🔎 Rule-based scan of every file (first run downloads rule packs, this can take a few minutes)...")
        scan = scan_repo_full(local_path)
        if not scan["ok"]:
            raise RuntimeError(f"Scan failed: {scan['error']}")
        semgrep_findings = scan["results"]
        status.write(f"Rules found **{len(semgrep_findings)}** issue(s) in **{len(scan['scanned'])}** scanned file(s).")

        ai_info = {
            "enabled": False, "findings": [], "audited": [], "not_audited": [], "unreadable": [],
            "truncated": [], "skipped_dirs": [], "too_large": [], "calls": 0, "errors": [],
        }
        if ai_max_files > 0:
            status.write("🤖 AI audit: Nemotron is reading source files for problems the rules cannot see...")
            flagged = {norm_path(f.get("path", "")) for f in semgrep_findings}

            def progress(done, total):
                if done % 5 == 0 or done == total:
                    status.write(f"🤖 AI audit: {done}/{total} code sections reviewed")

            try:
                ai_info = run_audit(local_path, flagged, semgrep_findings, ai_max_files, include_bugs, progress)
            except Exception as ex:
                ai_info["errors"] = [f"AI audit failed: {ex}"]
            status.write(f"🤖 AI audit found **{len(ai_info['findings'])}** additional issue(s).")

        all_findings = semgrep_findings + ai_info["findings"]

        by_file = {}
        for f in all_findings:
            by_file.setdefault(norm_path(f.get("path", "")), []).append(f)

        file_reports, patched = [], {}
        for rel, fs in by_file.items():
            abs_file = os.path.join(local_path, *rel.split("/"))
            try:
                with open(abs_file, "r", encoding="utf-8", newline="") as fh:
                    content = fh.read()
            except Exception as e:
                file_reports.append({"rel_path": rel, "unreadable": str(e), "results": [], "findings": fs})
                continue

            status.write(f"🛠️ {rel}: preparing fixes for {len(fs)} issue(s)...")
            fr = patch_file(rel, content, fs)

            for r in fr["results"]:
                if r["status"] == "fixed" and is_ai(r["check_id"]):
                    try:
                        r["recheck"] = recheck_region(rel, fr["final"], r["line"], include_bugs)
                    except Exception:
                        r["recheck"] = "unknown"

            file_reports.append(fr)
            if fr["final"] != content:
                patched[rel] = fr["final"]

        verification = None
        if patched:
            status.write("✅ Re-scanning the patched code to verify the fixes...")
            verification = verify_patches(local_path, patched, semgrep_findings)

        return {
            "repo_url": repo_url,
            "repo_full_name": repo_url.rstrip("/").removesuffix(".git").replace("https://github.com/", ""),
            "scan": scan,
            "ai": ai_info,
            "semgrep_findings": len(semgrep_findings),
            "ai_findings": len(ai_info["findings"]),
            "total_findings": len(all_findings),
            "files": file_reports,
            "patched": patched,
            "verification": verification,
            "duration": round(time.time() - started, 1),
        }
    finally:
        td.cleanup()


def verified_label(rep: dict, r: dict) -> str:
    if is_ai(r["check_id"]):
        if r["status"] != "fixed":
            return ""
        rc = r.get("recheck")
        if rc == "resolved":
            return "🤖 AI re-check: looks resolved (unverified opinion: review the diff yourself)"
        if rc == "still":
            return "⚠️ AI re-check: still suspicious"
        return "🤖 AI re-check: unavailable"

    ver = rep.get("verification")
    if not ver or not ver.get("ok"):
        return ""
    key = (r["check_id"], r["rel_path"])
    b, a = ver["before"].get(key, 0), ver["after"].get(key, 0)
    if a == 0:
        return "✅ re-scan: rule no longer matches"
    if a < b:
        return f"🟡 re-scan: {b} → {a}"
    return "⚠️ re-scan: still reported"


def safe_files(rep: dict) -> list:
    ver = rep.get("verification")
    if not ver or not ver.get("ok"):
        return []
    bad = {p for (_, p), _ in ver["new_issues"]}
    for fr in rep["files"]:
        for r in fr.get("results", []):
            if r["status"] != "fixed":
                continue
            if is_ai(r["check_id"]):
                bad.add(fr["rel_path"])  # AI topgan tuzatishlar hech qachon oldindan belgilanmaydi
            else:
                key = (r["check_id"], r["rel_path"])
                if ver["after"].get(key, 0) >= ver["before"].get(key, 0):
                    bad.add(fr["rel_path"])
    return [p for p in rep["patched"] if p not in bad]


def build_pr_body(rep: dict, files: list) -> str:
    lines = [
        "Automated security fixes generated by **PatchPilot** (NVIDIA Nemotron on Nebius Token Factory).",
        "",
        "Only the vulnerable lines were changed. Rule-based findings were re-scanned with Semgrep; "
        "AI-audit findings are proposals and must be reviewed by a human.",
        "",
    ]
    manual = []
    for fr in rep["files"]:
        for r in fr.get("results", []):
            if r["status"] == "fixed" and fr["rel_path"] in files:
                lines.append(f"- `{fr['rel_path']}` line {r['line']}: `{r['check_id']}` ({source_of(r['check_id'])}). {r['explanation']}")
            elif r["status"] == "not_fixed" or r["status"] in ("no_fix", "rejected"):
                manual.append(f"- `{fr['rel_path']}` line {r['line']}: `{r['check_id']}` ({r['note']})")
    if manual:
        lines += ["", "### Still needs manual attention", *manual]
    return "\n".join(lines)


def render_stats(results_all: list):
    if not results_all:
        return
    st.subheader("Statistics")
    sev = Counter(r["severity"] for r in results_all)
    src = Counter(source_of(r["check_id"]) for r in results_all)
    stat = Counter(status_of(r) for r in results_all)
    rules = Counter(r["check_id"].split(".")[-1] for r in results_all).most_common(8)
    files = Counter(r["rel_path"] for r in results_all).most_common(8)
    types = Counter(
        (r["rel_path"].rsplit(".", 1)[-1].lower() if "." in r["rel_path"] else "other") for r in results_all
    )

    c1, c2 = st.columns(2)
    with c1:
        st.caption("By severity")
        st.bar_chart(pd.Series({k: sev.get(k, 0) for k in ("high", "medium", "low")}))
        st.caption("By source")
        st.bar_chart(pd.Series(dict(src)))
        st.caption("Most common problems")
        st.bar_chart(pd.Series(dict(rules)))
    with c2:
        st.caption("Fixed / false positive / not fixed")
        st.bar_chart(pd.Series(dict(stat)))
        st.caption("By file type")
        st.bar_chart(pd.Series(dict(types)))
        st.caption("Most affected files")
        st.bar_chart(pd.Series(dict(files)))


def render_report(rep: dict):
    results_all = [r for fr in rep["files"] for r in fr.get("results", [])]
    fixed_n = sum(1 for r in results_all if r["status"] == "fixed")
    fp_n = sum(1 for r in results_all if r["status"] == "false_positive")
    manual_n = rep["total_findings"] - fixed_n - fp_n
    scan, ai = rep["scan"], rep["ai"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Files scanned (rules)", len(scan["scanned"]))
    c2.metric("Issues found", rep["total_findings"],
              help=f"{rep['semgrep_findings']} from rules + {rep['ai_findings']} from AI audit")
    c3.metric("Fixes proposed", fixed_n)
    c4.metric("Need your decision", manual_n)
    st.caption(f"Rules: {rep['semgrep_findings']} · AI audit: {rep['ai_findings']} · False positives: {fp_n}")

    ver = rep.get("verification")
    if ver and ver.get("ok"):
        st.info(
            f"Rule re-scan after fixes: {ver['total_before']} → {ver['total_after']} issue(s). "
            f"New rule-based issues introduced: {len(ver['new_issues'])}."
        )
    elif ver:
        st.warning(f"Re-scan could not run: {ver.get('error')}")

    with st.expander("Coverage report (what was and was not checked)"):
        st.write(f"**Rule scan:** {len(scan['scanned'])} file(s) scanned, {len(scan['skipped'])} skipped by the scanner. "
                 "Only the `.git/` metadata folder is excluded.")
        for sk in scan["skipped"][:50]:
            if isinstance(sk, dict):
                st.write(f"- `{sk.get('path')}`: {sk.get('reason')}")
            else:
                st.write(f"- `{sk}`")
        if scan["errors"]:
            st.write(
                f"Scanner reported **{len(scan['errors'])}** file-level error(s). For these files some rules "
                "did not run completely (parse errors or timeouts):"
            )
            for er in scan["errors"][:30]:
                st.write(f"- `{er.get('path')}`: {er.get('message') or er.get('long_msg') or er.get('type')}")

        if ai["enabled"]:
            st.write(f"**AI audit:** {len(ai['audited'])} file(s) read in {ai['calls']} section(s).")
            if ai["not_audited"]:
                st.write(f"Not read by the AI audit (file limit reached, raise the slider): {len(ai['not_audited'])}")
                for p in ai["not_audited"][:40]:
                    st.write(f"- `{p}`")
            if ai["truncated"]:
                st.write("Only the first part was read (file too long): " + ", ".join(f"`{p}`" for p in ai["truncated"]))
            if ai["too_large"]:
                st.write("Skipped by the AI audit (file larger than 400 KB): " + ", ".join(f"`{p}`" for p in ai["too_large"]))
            if ai["unreadable"]:
                st.write("Skipped by the AI audit (not UTF-8 text): " + ", ".join(f"`{p}`" for p in ai["unreadable"]))
            if ai["skipped_dirs"]:
                st.write("Third-party folders skipped by the AI audit (still covered by the rule scan): "
                         + ", ".join(f"`{p}`" for p in ai["skipped_dirs"]))
            for e in ai["errors"]:
                st.write(f"⚠️ {e}")
        else:
            st.write("**AI audit:** off.")
        st.caption("Images, fonts and other non-code files contain no source code to analyze.")

    if not rep["files"]:
        st.success("No issues found in any checked file.")
        return

    render_stats(results_all)

    st.subheader("Findings")
    f1, f2, f3, f4 = st.columns(4)
    sev_sel = f1.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])
    src_sel = f2.multiselect("Source", ["Semgrep rules", "AI audit"], default=["Semgrep rules", "AI audit"])
    stat_sel = f3.multiselect("Status", ["fixed", "false positive", "not fixed"],
                              default=["fixed", "false positive", "not fixed"])
    text_q = f4.text_input("Search file or rule")
    show_vendor = st.checkbox("Show third-party / vendored files (hidden by default)", value=False)
    hidden_vendor = 0

    def passes(r: dict, rel: str) -> bool:
        if r["severity"] not in sev_sel or source_of(r["check_id"]) not in src_sel or status_of(r) not in stat_sel:
            return False
        if text_q and text_q.lower() not in f"{rel} {r['check_id']}".lower():
            return False
        return True

    shown = 0
    for fr in rep["files"]:
        rel = fr["rel_path"]
        if not show_vendor and any(t in rel for t in THIRD_PARTY):
            hidden_vendor += 1
            continue
        visible = [r for r in fr.get("results", []) if passes(r, rel)]
        if not fr.get("unreadable") and not visible:
            continue
        shown += 1
        tag = " (third-party / vendored file)" if any(t in rel for t in THIRD_PARTY) else ""
        with st.expander(f"📄 {rel}{tag}", expanded=True):
            if fr.get("unreadable"):
                st.warning(f"This file could not be read as UTF-8 text, so no fix was attempted: {fr['unreadable']}")
                for f in fr.get("findings", []):
                    st.write(f"- line {f.get('start', {}).get('line')}: `{f.get('check_id')}`")
                continue

            for r in visible:
                with st.container(border=True):
                    st.markdown(
                        f"**`{r['check_id']}`** · {source_of(r['check_id'])} · line {r['line']} · "
                        f"severity **{r['severity']}** {verified_label(rep, r)}"
                    )
                    st.markdown("❌ **Problem: the code as it is now**")
                    st.code(r["snippet"], language=lang_of(rel))
                    st.markdown(f"**Why it is a problem:** {r['explanation']}")
                    if is_ai(r["check_id"]):
                        st.caption(
                            "Found by the AI audit, not by a rule. PatchPilot cannot see your templates, URLs or "
                            "deployment settings, so a fix can change how your app behaves. Treat it as a proposal."
                        )
                    if r["status"] == "fixed":
                        how = "computed by code" if r["method"] == "deterministic" else "written by Nemotron"
                        st.markdown(f"✅ **Proposed fixed version** ({how}, {r['changed_lines']} line(s) changed)")
                        st.code(r["diff"], language="diff")
                        for note in r.get("risk_notes") or []:
                            st.warning("⚠️ Review before merging: " + note)
                    elif r["status"] == "false_positive":
                        st.info(r["note"])
                    else:
                        st.warning(f"No automatic fix applied: {r['note']}")

            if fr["imports_added"]:
                st.caption("Imports added at the top of the file: " + ", ".join(fr["imports_added"]))
            if fr["import_note"]:
                st.warning(fr["import_note"])
            if fr["file_diff"]:
                untouched = fr["total_lines"] - fr["changed_lines"]
                st.caption(f"Whole-file change: {fr['changed_lines']} line(s) changed, the remaining {untouched} line(s) are untouched ✅")
                st.code(fr["file_diff"], language="diff")
    if hidden_vendor:
        st.caption(f"{hidden_vendor} third-party / vendored file(s) hidden. Tick the box above to show them.")
    if shown == 0:
        st.info("No findings match the current filters.")

    if rep["patched"]:
        st.subheader("Pull Request")
        st.caption(
            "Nothing is written to your repository until you press the button. A passing re-scan only means the "
            "rule no longer matches; it does not prove the fix is correct. Read every diff before creating the PR."
        )
        safe = safe_files(rep)
        choices = st.multiselect(
            "Files to include (only files whose rule re-scan passed are pre-selected)",
            options=list(rep["patched"].keys()), default=safe,
        )
        if st.button("🚀 Create Pull Request with the selected fixes"):
            if not choices:
                st.warning("Select at least one file.")
            else:
                try:
                    url = open_pull_request_multi(
                        rep["repo_full_name"],
                        {p: rep["patched"][p] for p in choices},
                        title="PatchPilot: reviewed security fixes",
                        body=build_pr_body(rep, choices),
                    )
                    st.session_state["pr_url"] = url
                except Exception as e:
                    st.error(f"Pull Request could not be created: {e}")
        if st.session_state.get("pr_url"):
            st.success("Pull Request created")
            st.markdown(f"[{st.session_state['pr_url']}]({st.session_state['pr_url']})")

    st.caption(f"Analysis took {rep['duration']} s.")


def render_history():
    scans = list_scans()
    if not scans:
        st.info("No scans saved yet. Run a scan and it will appear here.")
        return

    st.subheader("Scan history")
    st.dataframe(pd.DataFrame(scans), hide_index=True)

    repos = sorted({s["repo_url"] for s in scans})
    repo = st.selectbox("Trend for repository", repos)
    trend = [s for s in reversed(scans) if s["repo_url"] == repo]
    if len(trend) > 1:
        st.line_chart(pd.DataFrame(
            {"issues found": [s["total_findings"] for s in trend],
             "fixes proposed": [s["fixed"] for s in trend]},
            index=[s["ts"] for s in trend],
        ))
    else:
        st.caption("Scan this repository again to see a trend.")

    labels = {s["id"]: f"#{s['id']} · {s['ts']} · {s['repo_url']}" for s in scans}
    sid = st.selectbox("Open a past scan", list(labels.keys()), format_func=lambda i: labels[i])
    scan = get_scan(sid)
    if not scan:
        return

    st.write(
        f"**{scan['repo_url']}** · {scan['ts']} · {scan['files_scanned']} file(s) · "
        f"{scan['total_findings']} issue(s) ({scan['semgrep_findings']} rules + {scan['ai_findings']} AI) · "
        f"{scan['fixed']} fix(es) proposed · {scan['duration']} s"
    )
    details = scan["details"]
    if details:
        st.dataframe(
            pd.DataFrame(details)[["file", "line", "rule", "severity", "source", "status", "method"]],
            hide_index=True,
        )
        for d in details:
            if d["status"] == "fixed":
                with st.expander(f"{d['file']}:{d['line']} · {d['rule']}"):
                    st.markdown("❌ **Problem**")
                    st.code(d["snippet"], language=lang_of(d["file"]))
                    st.markdown(f"**Why:** {d['explanation']}")
                    st.markdown("✅ **Proposed fix**")
                    st.code(d["diff"], language="diff")
    st.caption("History is stored locally in history/patchpilot.db")


tab_scan, tab_history = st.tabs(["🔍 Scan", "🕘 History"])

with tab_scan:
    repo_url = st.text_input("GitHub repo URL", placeholder="https://github.com/username/reponame")
    o1, o2 = st.columns(2)
    ai_max_files = o1.slider("AI audit: max files to read (0 = off)", 0, 80, 50)
    include_bugs = o2.checkbox("AI audit also reports non-security bugs (report only, never edited)", value=False)
    scan_clicked = st.button("🔍 Scan repository", type="primary")

    if scan_clicked and repo_url.strip():
        st.session_state.pop("pr_url", None)
        status = st.status("Starting...", expanded=True)
        try:
            rep = analyze_repo(repo_url.strip(), status, ai_max_files, include_bugs)
            try:
                rep["scan_id"] = save_scan(rep)
            except Exception as e:
                status.write(f"⚠️ History could not be saved: {e}")
            st.session_state["report"] = rep
            status.update(label="Analysis complete", state="complete", expanded=False)
        except Exception as ex:
            st.session_state["report"] = None
            status.update(label="❌ Analysis stopped", state="error")
            st.error(str(ex))

    report = st.session_state.get("report")
    if report:
        render_report(report)

with tab_history:
    render_history()