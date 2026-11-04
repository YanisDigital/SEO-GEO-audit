#!/usr/bin/env python3
"""Render report.json into a self-contained report.html and a developer-ready tz.md.

Usage:
    python -I render_report.py audits/<dir>/report.json --out-dir audits/<dir>

Security: every value is HTML-escaped; links are emitted only for http(s) URLs
and carry rel="noopener noreferrer nofollow"; the page ships a strict CSP with
no scripts, no external resources and no forms. In Markdown, angle brackets
outside code are escaped and code fences are sized so content cannot break out.
See references/report-spec.md for the report.json schema.
"""

from __future__ import annotations

import argparse
import html
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

    if d.get("summary"):
        out.append(f'<h2>{e(L["summary"])}</h2><div class="card summary">')
        for para in s(d["summary"]).split("\n\n"):
            out.append(f"<p>{e(para)}</p>")
        out.append("</div>")

    scores = [x for x in as_list(d.get("scores")) if isinstance(x, dict)]
    if scores:
        out.append(f'<h2>{e(L["scores"])}</h2><div class="scores">')
        overall = clamp_score(d.get("overall_score"))
        if overall is not None:
            scores = [{"area": L["overall"], "score": overall, "comment": d.get("overall_comment", "")}] + scores
        for sc in scores:
            n = clamp_score(sc.get("score"))
            if n is None:
                continue
            out.append(f'<div class="card score {score_class(n)}"><div class="row"><h3>{e(sc.get("area"))}</h3>'
                       f'<span class="num">{n}</span></div>'
                       f'<div class="bar"><span style="width:{n}%"></span></div>'
                       f'<p>{e(sc.get("comment"))}</p></div>')
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

CODE_SPAN = re.compile(r"(`+)(.+?)\1", re.S)


def md_text(value) -> str:
    """Escape raw HTML outside inline code spans; keep code spans verbatim."""
    text = s(value)
    parts, last = [], 0
    for m in CODE_SPAN.finditer(text):
        parts.append(text[last:m.start()].replace("<", "&lt;").replace(">", "&gt;"))
        parts.append(m.group(0))
        last = m.end()
    parts.append(text[last:].replace("<", "&lt;").replace(">", "&gt;"))
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
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_md(d, L))
    print(f"Wrote {html_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
