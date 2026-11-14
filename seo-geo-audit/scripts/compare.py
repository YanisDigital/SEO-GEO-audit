#!/usr/bin/env python3
"""Compare a re-audit with the previous audit of the same site -> changes.json.

Usage:
    python -I compare.py <PREV>/report.json <OUT>/report.json --out <OUT>/changes.json

If crawl.json sits next to each report.json (or is given with --prev-crawl /
--crawl), site metrics are compared too.
No network access: this only reads local files. The renderer picks up
changes.json from the folder of the current report.json. changes.json also holds the
status of each previous task (fixed / partial / unchanged), see task_changes().
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render_report import (SEVERITIES, STATUS_KEYS, VISIBILITY_KEYS, as_list, compute_scores,  # noqa: E402
                           compute_visibility, mention, norm_key, norm_sev, s)

MAX_INPUT_BYTES = 64 * 1024 * 1024
WORD = re.compile(r"\w+", re.UNICODE)


def load(path: str) -> dict:
    if os.path.getsize(path) > MAX_INPUT_BYTES:
        raise ValueError(f"{path}: file too large")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def load_crawl(report_path: str, explicit: str | None = None) -> dict | None:
    path = explicit or os.path.join(os.path.dirname(os.path.abspath(report_path)), "crawl.json")
    try:
        return load(path) if os.path.isfile(path) else None
    except (OSError, ValueError):
        return None


def tokens(text) -> set[str]:
    return {w[:6] for w in WORD.findall(s(text).lower()) if len(w) > 2}


def same_issue(a: dict, b: dict) -> bool:
    ka, kb = norm_key(a.get("key")), norm_key(b.get("key"))
    if ka and kb:
        return ka == kb
    ta, tb = tokens(a.get("title")), tokens(b.get("title"))
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= 0.5


def weakness_changes(prev: dict, cur: dict) -> dict:
    pw = [w for w in as_list(prev.get("weaknesses")) if isinstance(w, dict)]
    cw = [w for w in as_list(cur.get("weaknesses")) if isinstance(w, dict)]
    brief = lambda w: {"title": s(w.get("title")), "severity": s(w.get("severity")) or "medium",  # noqa: E731
                       "key": s(w.get("key")) or None}
    fixed = [brief(w) for w in pw if not any(same_issue(w, c) for c in cw)]
    new = [brief(w) for w in cw if not any(same_issue(w, p) for p in pw)]
    still = []
    for c in cw:
        match = next((p for p in pw if same_issue(p, c)), None)
        if match:
            item = brief(c)
            if s(match.get("severity")) != s(c.get("severity")):
                item["severity_before"] = s(match.get("severity"))
            still.append(item)
    return {"fixed": fixed, "new": new, "still_open": still}


def sev_rank(w: dict) -> int:
    return SEVERITIES.index(norm_sev(w.get("severity")))


def task_changes(prev: dict, cur: dict) -> list[dict]:
    """Status of every task of the previous audit: fixed, partial, unchanged or unknown.

    A task points at the weaknesses it fixes with `fixes: [weakness keys]`. It is fixed when none of
    them is left in the current report, partial when some are gone or one is still open at a lower
    severity, unchanged otherwise. Without `fixes` the task is matched to the previous weakness whose
    title is most similar (basis "title"). `task_status_overrides` in the current report.json sets the
    status by hand, keyed by the previous task id, for what the keys cannot express (for example
    "12 of 19 descriptions rewritten").
    """
    pw = [w for w in as_list(prev.get("weaknesses")) if isinstance(w, dict)]
    cw = [w for w in as_list(cur.get("weaknesses")) if isinstance(w, dict)]
    overrides = cur.get("task_status_overrides") if isinstance(cur.get("task_status_overrides"), dict) else {}
    out = []
    for task in as_list(prev.get("tasks")):
        if not isinstance(task, dict):
            continue
        tid, item = s(task.get("id")), {"id": s(task.get("id")), "title": s(task.get("title"))}
        ov = overrides.get(tid)
        if isinstance(ov, dict) and norm_key(ov.get("status")) in STATUS_KEYS:
            out.append({**item, "status": norm_key(ov["status"]), "basis": "override", "note": s(ov.get("note"))})
            continue
        closed, still, lowered, basis = [], [], False, "keys"
        keys = [norm_key(k) for k in as_list(task.get("fixes")) if s(k)]
        if keys:
            for k in keys:
                before = next((w for w in pw if norm_key(w.get("key")) == k), None)
                now = next((w for w in cw if norm_key(w.get("key")) == k), None)
                if now is None:
                    closed.append(k)
                else:
                    still.append(k)
                    lowered = lowered or (before is not None and sev_rank(now) > sev_rank(before))
        else:
            basis = "title"
            best, best_score = None, 0.0
            tt = tokens(task.get("title"))
            for w in pw:
                wt = tokens(w.get("title"))
                score = len(tt & wt) / len(tt | wt) if tt and wt else 0.0
                if score > best_score:
                    best, best_score = w, score
            if best is not None and best_score >= 0.3:
                label = s(best.get("title"))
                match = next((c for c in cw if same_issue(best, c)), None)
                if match is None:
                    closed.append(label)
                else:
                    still.append(label)
                    lowered = sev_rank(match) > sev_rank(best)
        if not closed and not still:
            status = "unknown"
        elif not still:
            status = "fixed"
        elif closed or lowered:
            status = "partial"
        else:
            status = "unchanged"
        out.append({**item, "status": status, "basis": basis, "closed": closed, "still_open": still, "note": ""})
    return out


def area_changes(prev: dict, cur: dict) -> list[dict]:
    before = {}
    for x in compute_scores(prev)[0]:
        before[s(x.get("area")).strip()] = x
        if x["key"]:
            before[x["key"]] = x
    out = []
    for x in compute_scores(cur)[0]:
        if x["key"] in VISIBILITY_KEYS:
            continue
        b = (before.get(x["key"]) if x["key"] else None) or before.get(s(x.get("area")).strip())
        out.append({"key": x["key"], "area": s(x.get("area")),
                    "before": b["score"] if b else None, "after": x["score"]})
    return out


def check_changes(prev: dict, cur: dict) -> list[dict]:
    def index(d):
        return {(s(c.get("engine")).lower().strip(), s(c.get("query")).lower().strip()): c
                for c in as_list((d.get("geo_visibility") or {}).get("checks")) if isinstance(c, dict)}

    def state(c):
        if c is None:
            return None
        if re.match(r"^https?://", s(c.get("cited_url")).strip()):
            return "cited"
        return mention(c.get("mentioned")) or "n/a"

    p, c = index(prev), index(cur)
    out = []
    for key, chk in c.items():
        out.append({"engine": s(chk.get("engine")), "query": s(chk.get("query")),
                    "query_type": s(chk.get("query_type")) or None,
                    "before": state(p.get(key)), "after": state(chk)})
    return out


def crawl_metrics(crawl: dict) -> dict:
    pages = [p for p in crawl.get("pages", []) if isinstance(p, dict) and "title" in p]
    summ = crawl.get("site_summary") or {}
    analytics, forms = summ.get("analytics"), summ.get("forms")
    hreflang, external, links = crawl.get("hreflang_check"), crawl.get("external_link_check"), crawl.get("link_check")
    images = ((crawl.get("asset_check") or {}).get("images") or {})
    bad = lambda r: bool(r.get("error")) or (r.get("status") or 0) >= 400  # noqa: E731
    llms = (crawl.get("llms_txt") or {}).get("/llms.txt") or {}
    dup = lambda k: sum(x.get("count", 0) for x in summ.get(k) or [])  # noqa: E731
    return {
        "pages_analyzed": len(pages),
        "pages_without_canonical": sum(1 for p in pages if not p.get("canonical")),
        "pages_missing_description": sum(1 for p in pages if not p.get("meta_description")),
        "pages_with_duplicate_description": dup("duplicate_descriptions"),
        "pages_with_duplicate_title": dup("duplicate_titles"),
        "pages_without_h1": sum(1 for p in pages if p.get("h1_count") == 0),
        "structured_data_types": len(summ.get("structured_data_types") or []),
        "images_missing_alt": summ.get("images_missing_alt_total"),
        "avg_ttfb_ms": summ.get("avg_ttfb_ms"),
        "llms_txt": llms.get("status") == 200 and not llms.get("looks_like_html"),
        "sitemap_urls": summ.get("sitemap_urls"),
        "sanity_flags": len(crawl.get("sanity_flags") or []),
        # newer collectors only: None when the earlier crawl did not measure it
        "analytics_tools": len(analytics.get("tools") or []) if analytics else None,
        "pages_without_tracking": analytics.get("pages_without_tracking_count") if analytics else None,
        "forms_without_spam_protection": forms.get("forms_without_visible_spam_protection") if forms else None,
        "images_over_200kb": images.get("over_200kb"),
        "hreflang_issues": sum((hreflang.get("issue_counts") or {}).values()) if hreflang else None,
        "internal_links_broken": sum(1 for r in links if bad(r)) if links else None,
        "external_links_broken": (sum(1 for r in external if r.get("class") in ("broken", "unreachable"))
                                  if external else None),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare a re-audit with the previous audit")
    ap.add_argument("previous", help="previous report.json")
    ap.add_argument("current", help="current report.json")
    ap.add_argument("--prev-crawl", help="previous crawl.json (default: next to the previous report.json)")
    ap.add_argument("--crawl", help="current crawl.json (default: next to the current report.json)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    try:
        prev, cur = load(args.previous), load(args.current)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    ps, cs = (prev.get("site") or {}), (cur.get("site") or {})
    out = {
        "previous": {"audit_date": s(ps.get("audit_date")) or None, "readiness": compute_scores(prev)[1],
                     "visibility": compute_visibility(prev)["score"]},
        "current": {"audit_date": s(cs.get("audit_date")) or None, "readiness": compute_scores(cur)[1],
                    "visibility": compute_visibility(cur)["score"]},
        "areas": area_changes(prev, cur),
        "weaknesses": weakness_changes(prev, cur),
        "checks": check_changes(prev, cur),
        "tasks": task_changes(prev, cur),
    }
    out["task_counts"] = dict(Counter(x["status"] for x in out["tasks"]))
    pc, cc = load_crawl(args.previous, args.prev_crawl), load_crawl(args.current, args.crawl)
    if pc and cc:
        before, after = crawl_metrics(pc), crawl_metrics(cc)
        out["site_metrics"] = [{"metric": k, "before": before[k], "after": after[k]} for k in after]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    w = out["weaknesses"]
    print(f"readiness {out['previous']['readiness']} -> {out['current']['readiness']}, "
          f"visibility {out['previous']['visibility']} -> {out['current']['visibility']}; "
          f"fixed {len(w['fixed'])}, new {len(w['new'])}, still open {len(w['still_open'])}")
    if out["tasks"]:
        print(f"tasks: {out['task_counts']}")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
