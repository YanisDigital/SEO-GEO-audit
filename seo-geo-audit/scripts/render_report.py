#!/usr/bin/env python3
"""Render report.json into report.html, a developer-ready tz.md and tasks.csv.

Usage:
    python -I render_report.py audits/<dir>/report.json --out-dir audits/<dir>

Security: every value is HTML-escaped; links are emitted only for http(s) URLs
and carry rel="noopener noreferrer nofollow"; the page ships a strict CSP with
no scripts, no external resources and no forms. In CSV, cells that a
spreadsheet could read as a formula are prefixed with an apostrophe. In Markdown, raw HTML, links,
images and stray backticks outside code are escaped, line breaks inside values
are flattened, and code fences are sized so content cannot break out. All
parsing of untrusted text is linear-time (no backtracking regexes).
Area scores, "Site readiness" and "Real visibility" are computed here from the
weaknesses and live checks (references/report-spec.md section 2), so every
number in the report can be traced back to its inputs.
See references/report-spec.md for the report.json schema.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report-template.html")

DEFAULT_LABELS = {
    "report_title": "SEO & GEO/AEO audit",
    "eyebrow": "Website audit",
    "audit_date": "Audit date",
    "pages_analyzed": "Pages analysed",
    "platform": "Platform",
    "summary": "Executive summary",
    "scores": "Scores by area",
    "overall": "Overall",
    "readiness": "Site readiness",
    "readiness_hint": "How well the site itself is built for search and AI engines (weighted average of the area scores).",
    "visibility": "Real visibility",
    "visibility_hint": "How often AI and search answers name or cite the business for non-brand queries.",
    "visibility_basis": "{hits} of {total} non-brand checks mention or cite the business",
    "not_measured": "not measured",
    "deductions": "Deductions",
    "no_deductions": "No issues found in this area",
    "wave": "Wave",
    "priority": "Priority",
    "task_title": "Task",
    "strengths": "Strengths",
    "weaknesses": "Weaknesses",
    "tasks": "Action plan (technical brief)",
    "wave_now": "Do now (quick wins, 1-7 days)",
    "wave_30d": "Next 30 days",
    "wave_strategic": "Strategic (1-3 months)",
    "geo": "Visibility in AI answers (live checks)",
    "engine": "Engine",
    "query": "Query",
    "mentioned": "Brand mentioned",
    "cited": "Site cited",
    "competitors_named": "Named instead",
    "note": "Note",
    "competitors": "Competitor comparison",
    "better_at": "They do better",
    "worse_at": "Client does better",
    "limitations": "Limitations and assumptions",
    "data_sources": "Data sources",
    "why": "Why",
    "steps": "What to do",
    "code": "Example",
    "acceptance": "Done when",
    "effort": "Effort",
    "owner": "Owner",
    "area": "Area",
    "pages": "Pages",
    "evidence": "Evidence",
    "yes": "yes",
    "no": "no",
    "partial": "partly",
    "severity_critical": "critical",
    "severity_high": "high",
    "severity_medium": "medium",
    "severity_low": "low",
    "generated_by": "Generated with the open-source seo-geo-audit skill. Passive, read-only checks; "
                    "AI answers are a point-in-time snapshot and vary by user, location and time.",
}

WAVES = [("now", "wave_now"), ("30d", "wave_30d"), ("strategic", "wave_strategic")]
SEVERITIES = ("critical", "high", "medium", "low")
DEDUCTION = {"critical": 25, "high": 12, "medium": 6, "low": 2}
AREA_WEIGHT = {"technical": 1.5, "geo": 1.5}
VISIBILITY_KEYS = ("visibility", "ai_visibility")  # measured by live checks, not by deductions
NON_BRAND = ("non_brand", "nonbrand", "generic")
MIN_VISIBILITY_CHECKS = 3
CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\uff1d", "\uff0b", "\uff0d", "\uff20")
URL_RX = re.compile(r"^https?://[^\s<>\"'`\\]+$", re.I)
LANG_RX = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$")
CTRL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def s(value) -> str:
    """Coerce to a clean string (no control characters)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return CTRL_RX.sub("", str(value))


def e(value) -> str:
    return html.escape(s(value), quote=True)


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def link(url, text=None) -> str:
    u = s(url).strip()
    if URL_RX.match(u):
        return f'<a href="{e(u)}" rel="noopener noreferrer nofollow" target="_blank">{e(text or u)}</a>'
    return e(text or u)


def score_class(n: int) -> str:
    return "s-good" if n >= 80 else ("s-ok" if n >= 50 else "s-bad")


def clamp_score(v) -> int | None:
    try:
        return max(0, min(100, int(round(float(v)))))
    except (TypeError, ValueError):
        return None


def norm_sev(v) -> str:
    v = s(v).lower()
    return v if v in SEVERITIES else "medium"


def half_up(x: float) -> int:
    return int(x + 0.5)


def norm_key(v) -> str:
    return s(v).strip().lower().replace("-", "_").replace(" ", "_")


def mention(v) -> str | None:
    key = s(v).strip().lower()
    if v is True or key in ("true", "yes"):
        return "yes"
    if v is False or key in ("false", "no"):
        return "no"
    if key in ("partial", "partly"):
        return "partial"
    return None  # not checked / engine unavailable


def weakness_matches(w: dict, sc: dict) -> bool:
    key = norm_key(sc.get("key"))
    if key and norm_key(w.get("area_key")) == key:
        return True
    area = s(sc.get("area")).strip()
    return bool(area) and s(w.get("area")).strip() == area


def compute_scores(d: dict) -> tuple[list[dict], int | None, list[str]]:
    """Area scores from weakness deductions, plus the weighted site-readiness score."""
    weaknesses = [w for w in as_list(d.get("weaknesses")) if isinstance(w, dict)]
    out, warnings = [], []
    for sc in as_list(d.get("scores")):
        if not isinstance(sc, dict):
            continue
        key = norm_key(sc.get("key"))
        deds = [{"severity": norm_sev(w.get("severity")), "points": DEDUCTION[norm_sev(w.get("severity"))],
                 "title": w.get("title")} for w in weaknesses if weakness_matches(w, sc)]
        deds.sort(key=lambda x: -x["points"])
        score = max(0, 100 - sum(x["points"] for x in deds))
        stated = clamp_score(sc.get("score"))
        if stated is not None and stated != score and key not in VISIBILITY_KEYS:
            warnings.append(f'area "{s(sc.get("area"))}": stated score {stated} replaced by computed {score} '
                            f'(100 minus {len(deds)} deduction(s))')
        out.append(dict(sc, key=key, score=score, deductions=deds))
    rated = [x for x in out if x["key"] not in VISIBILITY_KEYS]
    readiness = None
    if rated:
        total_w = sum(AREA_WEIGHT.get(x["key"], 1.0) for x in rated)
        readiness = half_up(sum(x["score"] * AREA_WEIGHT.get(x["key"], 1.0) for x in rated) / total_w)
    unmatched = [s(w.get("title")) for w in weaknesses
                 if norm_key(w.get("area_key")) not in VISIBILITY_KEYS
                 and not any(weakness_matches(w, x) for x in out)]
    if out and unmatched:
        warnings.append(f"{len(unmatched)} weakness(es) match no scored area and deduct nothing: "
                        + "; ".join(unmatched[:5]))
    return out, readiness, warnings


def compute_visibility(d: dict) -> dict:
    """Real visibility from non-brand live checks: cited 1, named 0.6, partly 0.3, absent 0."""
    checks = [c for c in as_list((d.get("geo_visibility") or {}).get("checks")) if isinstance(c, dict)]
    points = []
    for c in checks:
        if norm_key(c.get("query_type")) not in NON_BRAND:
            continue
        m = mention(c.get("mentioned"))
        cited = bool(URL_RX.match(s(c.get("cited_url")).strip()))
        if cited:
            points.append(1.0)
        elif m is not None:
            points.append({"yes": 0.6, "partial": 0.3, "no": 0.0}[m])
    hits = sum(1 for p in points if p > 0)
    score = half_up(100 * sum(points) / len(points)) if len(points) >= MIN_VISIBILITY_CHECKS else None
    return {"score": score, "hits": hits, "total": len(points)}


def norm_prio(v) -> str:
    v = s(v).upper()
    return v if v in ("P1", "P2", "P3") else "P2"


def yes_no(v, L) -> str:
    key = s(v).lower()
    if v is True or key in ("true", "yes"):
        return f'<span class="tag yes">{e(L["yes"])}</span>'
    if v is False or key in ("false", "no"):
        return f'<span class="tag no">{e(L["no"])}</span>'
    if key in ("partial", "partly"):
        return f'<span class="tag partial">{e(L["partial"])}</span>'
    return e(v)


# ----------------------------------------------------------------------------- HTML

def render_html(d: dict, L: dict) -> str:
    out = []
    site = d.get("site") or {}
    title = f'{L["report_title"]}: {s(site.get("name") or site.get("url"))}'
    out.append('<header class="top">')
    out.append(f'<div class="eyebrow">{e(L["eyebrow"])}</div>')
    out.append(f'<h1>{e(title)}</h1><div class="meta">')
    if site.get("url"):
        out.append(f'<span>{link(site["url"])}</span>')
    for key, lab in (("audit_date", "audit_date"), ("pages_analyzed", "pages_analyzed"), ("cms", "platform")):
        if site.get(key) not in (None, ""):
            out.append(f'<span>{e(L[lab])}: {e(site[key])}</span>')
    out.append("</div></header>")

    scores, readiness, _ = compute_scores(d)
    vis = compute_visibility(d)
    head = d.get("headline") if isinstance(d.get("headline"), dict) else {}
    tiles = []
    if readiness is not None:
        tiles.append(("readiness", readiness, ""))
    if readiness is not None or vis["total"]:
        basis = (L["visibility_basis"].replace("{hits}", str(vis["hits"])).replace("{total}", str(vis["total"]))
                 if vis["total"] else L["not_measured"])
        tiles.append(("visibility", vis["score"], basis))
    if tiles:
        out.append('<div class="headline">')
        for name, n, basis in tiles:
            cls = score_class(n) if n is not None else "s-na"
            num = str(n) if n is not None else "&mdash;"
            out.append(f'<div class="card score big {cls}"><div class="row"><h3>{e(L[name])}</h3>'
                       f'<span class="num">{num}</span></div>'
                       f'<div class="bar"><span style="width:{n or 0}%"></span></div>'
                       f'<p>{e(L[name + "_hint"])}</p>')
            if basis:
                out.append(f'<p class="basis">{e(basis)}</p>')
            if head.get(name):
                out.append(f'<p class="comment">{e(head[name])}</p>')
            out.append("</div>")
        out.append("</div>")

    if d.get("summary"):
        out.append(f'<h2>{e(L["summary"])}</h2><div class="card summary">')
        for para in s(d["summary"]).split("\n\n"):
            out.append(f"<p>{e(para)}</p>")
        out.append("</div>")

    if scores:
        out.append(f'<h2>{e(L["scores"])}</h2><div class="scores">')
        for sc in scores:
            if sc["key"] in VISIBILITY_KEYS:
                continue  # shown as the "Real visibility" headline
            n = sc["score"]
            out.append(f'<div class="card score {score_class(n)}"><div class="row"><h3>{e(sc.get("area"))}</h3>'
                       f'<span class="num">{n}</span></div>'
                       f'<div class="bar"><span style="width:{n}%"></span></div>'
                       f'<p>{e(sc.get("comment"))}</p>')
            if sc["deductions"]:
                out.append(f'<details class="ded"><summary>{e(L["deductions"])}: '
                           f'&minus;{sum(x["points"] for x in sc["deductions"])}</summary><ul>')
                for x in sc["deductions"]:
                    out.append(f'<li><span class="pts">&minus;{x["points"]}</span>'
                               f'<span class="tag {x["severity"]}">{e(L["severity_" + x["severity"]])}</span>'
                               f'{e(x["title"])}</li>')
                out.append("</ul></details>")
            else:
                out.append(f'<p class="basis">{e(L["no_deductions"])}</p>')
            out.append("</div>")
        out.append("</div>")

    strengths = [x for x in as_list(d.get("strengths")) if isinstance(x, dict)]
    if strengths:
        out.append(f'<h2>{e(L["strengths"])}</h2><div class="list">')
        for it in strengths:
            out.append(f'<div class="card item good"><h3>{e(it.get("title"))}</h3><p>{e(it.get("detail"))}</p>')
            if it.get("evidence"):
                out.append(f'<div class="evidence">{e(L["evidence"])}: {e(it["evidence"])}</div>')
            out.append("</div>")
        out.append("</div>")

    weaknesses = [x for x in as_list(d.get("weaknesses")) if isinstance(x, dict)]
    if weaknesses:
        order = {k: i for i, k in enumerate(SEVERITIES)}
        weaknesses.sort(key=lambda w: order[norm_sev(w.get("severity"))])
        out.append(f'<h2>{e(L["weaknesses"])}</h2><div class="list">')
        for it in weaknesses:
            sev = norm_sev(it.get("severity"))
            out.append(f'<div class="card item sev-{sev}"><h3><span class="tag {sev}">{e(L["severity_" + sev])}</span>'
                       f'{e(it.get("title"))}</h3>')
            if it.get("area"):
                out.append(f'<p class="muted">{e(L["area"])}: {e(it["area"])}</p>')
            out.append(f'<p>{e(it.get("detail"))}</p>')
            if it.get("evidence"):
                out.append(f'<div class="evidence">{e(L["evidence"])}: {e(it["evidence"])}</div>')
            out.append("</div>")
        out.append("</div>")

    tasks = [x for x in as_list(d.get("tasks")) if isinstance(x, dict)]
    if tasks:
        out.append(f'<h2>{e(L["tasks"])}</h2>')
        for wave, lab in WAVES:
            wt = [t for t in tasks if s(t.get("wave")).lower() == wave]
            if not wt:
                continue
            out.append(f'<section class="wave"><h3>{e(L[lab])}</h3>')
            for t in wt:
                prio = norm_prio(t.get("priority"))
                opened = " open" if wave == "now" else ""
                out.append(f'<details class="task"{opened}><summary><span class="tid">{e(t.get("id"))}</span>'
                           f'<span class="tag {prio.lower()}">{e(prio)}</span>'
                           f'<span class="ttl">{e(t.get("title"))}</span>'
                           f'<span class="tag">{e(L["effort"])}: {e(t.get("effort"))}</span>'
                           f'<span class="tag">{e(t.get("owner"))}</span></summary><div class="body">')
                if t.get("area"):
                    out.append(f'<h4>{e(L["area"])}</h4><p>{e(t["area"])}</p>')
                if t.get("why"):
                    out.append(f'<h4>{e(L["why"])}</h4><p>{e(t["why"])}</p>')
                steps = as_list(t.get("steps"))
                if steps:
                    out.append(f'<h4>{e(L["steps"])}</h4><ol>' + "".join(f"<li>{e(x)}</li>" for x in steps) + "</ol>")
                if t.get("code"):
                    out.append(f'<h4>{e(L["code"])}</h4><pre><code>{e(t["code"])}</code></pre>')
                acc = as_list(t.get("acceptance"))
                if acc:
                    out.append(f'<h4>{e(L["acceptance"])}</h4><ul>' + "".join(f"<li>{e(x)}</li>" for x in acc) + "</ul>")
                pages = as_list(t.get("pages"))
                if pages:
                    out.append(f'<h4>{e(L["pages"])}</h4><ul>' + "".join(f"<li>{link(p)}</li>" for p in pages[:20]) + "</ul>")
                out.append("</div></details>")
            out.append("</section>")

    geo = d.get("geo_visibility") or {}
    checks = [x for x in as_list(geo.get("checks")) if isinstance(x, dict)]
    if geo.get("summary") or checks:
        out.append(f'<h2>{e(L["geo"])}</h2>')
        if geo.get("summary"):
            out.append(f'<div class="card"><p>{e(geo["summary"])}</p></div>')
        if checks:
            out.append('<div class="table-wrap" style="margin-top:12px"><table><thead><tr>'
                       f'<th>{e(L["engine"])}</th><th>{e(L["query"])}</th><th>{e(L["mentioned"])}</th>'
                       f'<th>{e(L["cited"])}</th><th>{e(L["competitors_named"])}</th><th>{e(L["note"])}</th>'
                       '</tr></thead><tbody>')
            for c in checks:
                cited = c.get("cited_url")
                cited_html = link(cited) if cited and URL_RX.match(s(cited)) else yes_no(cited, L)
                out.append(f'<tr><td>{e(c.get("engine"))}</td><td>{e(c.get("query"))}</td>'
                           f'<td>{yes_no(c.get("mentioned"), L)}</td><td>{cited_html}</td>'
                           f'<td>{e(", ".join(s(x) for x in as_list(c.get("competitors_named"))))}</td>'
                           f'<td>{e(c.get("note"))}</td></tr>')
            out.append("</tbody></table></div>")

    comps = [x for x in as_list(d.get("competitors")) if isinstance(x, dict)]
    if comps:
        out.append(f'<h2>{e(L["competitors"])}</h2><div class="list">')
        for c in comps:
            out.append(f'<div class="card"><h3>{e(c.get("name"))} <span class="muted">{link(c.get("url"))}</span></h3>')
            if c.get("notes"):
                out.append(f'<p>{e(c["notes"])}</p>')
            for key in ("better_at", "worse_at"):
                vals = as_list(c.get(key))
                if vals:
                    out.append(f'<p><strong>{e(L[key])}:</strong></p><ul>' + "".join(f"<li>{e(v)}</li>" for v in vals) + "</ul>")
            out.append("</div>")
        out.append("</div>")

    for key in ("limitations", "data_sources"):
        vals = as_list(d.get(key))
        if vals:
            out.append(f'<h2>{e(L[key])}</h2><div class="card"><ul>' + "".join(f"<li>{e(v)}</li>" for v in vals) + "</ul></div>")

    out.append(f'<footer>{e(L["generated_by"])}</footer>')
    return "\n".join(out), title


# ----------------------------------------------------------------------------- Markdown

TICK_RUN = re.compile(r"`+")
MD_ESCAPES = {"\\": "\\\\", "`": "\\`", "[": "\\[", "]": "\\]", "<": "&lt;", ">": "&gt;"}


def code_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of inline code spans, CommonMark style, in linear time.

    A run of N backticks opens a span that closes at the next run of exactly N
    backticks; a run with no partner is literal text.
    """
    runs = [(m.start(), m.end()) for m in TICK_RUN.finditer(text)]
    partner: list[int | None] = [None] * len(runs)
    next_of_len: dict[int, int] = {}
    for i in range(len(runs) - 1, -1, -1):
        n = runs[i][1] - runs[i][0]
        partner[i] = next_of_len.get(n)
        next_of_len[n] = i
    spans, i = [], 0
    while i < len(runs):
        j = partner[i]
        if j is None:
            i += 1
            continue
        spans.append((runs[i][0], runs[j][1]))
        i = j + 1
    return spans


def _md_escape(chunk: str) -> str:
    return "".join(MD_ESCAPES.get(ch, ch) for ch in chunk)


def md_text(value) -> str:
    """Make untrusted text safe for one line of Markdown.

    Line breaks are flattened (no block-level constructs such as HTML blocks).
    Outside code spans, raw HTML, link/image brackets, backslashes and stray
    backticks are escaped, so the result's code spans are self-contained and
    stay safe when several values are joined on one line. Code spans are kept
    verbatim: renderers show their content as literal text.
    """
    text = " ".join(s(value).splitlines())
    parts, last = [], 0
    for start, end in code_spans(text):
        parts.append(_md_escape(text[last:start]))
        parts.append(text[start:end])
        last = end
    parts.append(_md_escape(text[last:]))
    return "".join(parts)


def md_url(u) -> str:
    u = s(u).strip()
    return f"<{u}>" if URL_RX.match(u) else md_text(u)


def fence(code: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", code)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}\n{code}\n{ticks}"


def render_md(d: dict, L: dict) -> str:
    site = d.get("site") or {}
    lines = [f'# {md_text(L["tasks"])}: {md_text(site.get("name") or site.get("url"))}', ""]
    if site.get("url"):
        lines.append(f"- URL: {md_url(site['url'])}")
    if site.get("audit_date"):
        lines.append(f'- {md_text(L["audit_date"])}: {md_text(site["audit_date"])}')
    if site.get("cms"):
        lines.append(f'- {md_text(L["platform"])}: {md_text(site["cms"])}')
    _, readiness, _ = compute_scores(d)
    vis = compute_visibility(d)
    if readiness is not None:
        lines.append(f'- {md_text(L["readiness"])}: {readiness}/100')
    if readiness is not None or vis["total"]:
        lines.append(f'- {md_text(L["visibility"])}: '
                     + (f'{vis["score"]}/100' if vis["score"] is not None else md_text(L["not_measured"])))
    lines.append("")
    tasks = [x for x in as_list(d.get("tasks")) if isinstance(x, dict)]
    for wave, lab in WAVES:
        wt = [t for t in tasks if s(t.get("wave")).lower() == wave]
        if not wt:
            continue
        lines += [f"## {md_text(L[lab])}", ""]
        for t in wt:
            lines.append(f'### {md_text(t.get("id"))} [{norm_prio(t.get("priority"))}] {md_text(t.get("title"))}')
            meta = []
            for key in ("area", "effort", "owner"):
                if t.get(key):
                    meta.append(f"**{md_text(L[key])}:** {md_text(t[key])}")
            if meta:
                lines.append(" · ".join(meta))
            lines.append("")
            if t.get("why"):
                lines += [f'**{md_text(L["why"])}:** {md_text(t["why"])}', ""]
            steps = as_list(t.get("steps"))
            if steps:
                lines.append(f'**{md_text(L["steps"])}:**')
                lines += [f"{i}. {md_text(x)}" for i, x in enumerate(steps, 1)]
                lines.append("")
            if t.get("code"):
                lines += [f'**{md_text(L["code"])}:**', "", fence(s(t["code"])), ""]
            acc = as_list(t.get("acceptance"))
            if acc:
                lines.append(f'**{md_text(L["acceptance"])}:**')
                lines += [f"- [ ] {md_text(x)}" for x in acc]
                lines.append("")
            pages = as_list(t.get("pages"))
            if pages:
                lines.append(f'**{md_text(L["pages"])}:** ' + ", ".join(md_url(p) for p in pages[:20]))
                lines.append("")
    lims = as_list(d.get("limitations"))
    if lims:
        lines += [f'## {md_text(L["limitations"])}', ""] + [f"- {md_text(x)}" for x in lims] + [""]
    return "\n".join(lines).rstrip() + "\n"


# ----------------------------------------------------------------------------- CSV

def csv_cell(value) -> str:
    """Plain text that a spreadsheet will not evaluate as a formula (OWASP CSV injection)."""
    text = s(value)
    if text.lstrip(" ").startswith(CSV_FORMULA_START):
        return "'" + text
    return text


def render_csv(d: dict, L: dict) -> str:
    """tasks.csv for Jira/Trello/Asana/Sheets imports: one row per task."""
    waves = {w: L[lab] for w, lab in WAVES}
    order = {w: i for i, (w, _) in enumerate(WAVES)}
    cols = ["ID", L["wave"], L["priority"], L["area"], L["task_title"], L["why"], L["steps"],
            L["acceptance"], L["effort"], L["owner"], L["pages"]]
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    w.writerow([csv_cell(c) for c in cols])
    tasks = [x for x in as_list(d.get("tasks")) if isinstance(x, dict)]
    tasks.sort(key=lambda t: (order.get(s(t.get("wave")).lower(), len(WAVES)), norm_prio(t.get("priority"))))
    for t in tasks:
        wave = s(t.get("wave")).lower()
        row = [t.get("id"), waves.get(wave, wave), norm_prio(t.get("priority")), t.get("area"), t.get("title"),
               t.get("why"),
               "\n".join(f"{i}. {s(x)}" for i, x in enumerate(as_list(t.get("steps")), 1)),
               "\n".join(f"\u2022 {s(x)}" for x in as_list(t.get("acceptance"))),
               t.get("effort"), t.get("owner"),
               "\n".join(s(p) for p in as_list(t.get("pages"))[:20])]
        w.writerow([csv_cell(c) for c in row])
    return buf.getvalue()


# ----------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="Render report.json to HTML + Markdown")
    ap.add_argument("data", help="Path to report.json")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    with open(args.data, encoding="utf-8") as fh:
        d = json.load(fh)
    if not isinstance(d, dict):
        print("ERROR: report.json must contain a JSON object", file=sys.stderr)
        return 2
    L = dict(DEFAULT_LABELS)
    for k, v in (d.get("labels") or {}).items():
        if k in L and isinstance(v, str) and v.strip():
            L[k] = v
    lang = s(d.get("language") or "en")
    lang = lang if LANG_RX.match(lang) else "en"

    body, title = render_html(d, L)
    with open(TEMPLATE, encoding="utf-8") as fh:
        tpl = fh.read()
    values = {"LANG": e(lang), "TITLE": e(title), "CONTENT": body}
    page = re.sub(r"\{\{(LANG|TITLE|CONTENT)\}\}", lambda m: values[m.group(1)], tpl)

    os.makedirs(args.out_dir, exist_ok=True)
    html_path = os.path.join(args.out_dir, "report.html")
    md_path = os.path.join(args.out_dir, "tz.md")
    csv_path = os.path.join(args.out_dir, "tasks.csv")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_md(d, L))
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:  # BOM so Excel reads UTF-8
        fh.write(render_csv(d, L))
    for warning in compute_scores(d)[2]:
        print(f"WARNING: {warning}", file=sys.stderr)
    if compute_visibility(d)["score"] is None:
        print(f"NOTE: real visibility not scored: fewer than {MIN_VISIBILITY_CHECKS} non-brand checks "
              "with a result (set query_type on geo_visibility.checks)", file=sys.stderr)
    print(f"Wrote {html_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
