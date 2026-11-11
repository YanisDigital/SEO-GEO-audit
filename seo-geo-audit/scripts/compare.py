#!/usr/bin/env python3
"""Compare a re-audit with the previous audit of the same site -> changes.json.

Usage:
    python -I compare.py <PREV>/report.json <OUT>/report.json --out <OUT>/changes.json

If crawl.json sits next to each report.json, site metrics are compared too.
No network access: this only reads local files. The renderer picks up
changes.json from the folder of the current report.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render_report import (VISIBILITY_KEYS, as_list, compute_scores, compute_visibility,  # noqa: E402
                           mention, norm_key, s)

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


def load_crawl(report_path: str) -> dict | None:
    path = os.path.join(os.path.dirname(os.path.abspath(report_path)), "crawl.json")
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
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare a re-audit with the previous audit")
    ap.add_argument("previous", help="previous report.json")
    ap.add_argument("current", help="current report.json")
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
    }
    pc, cc = load_crawl(args.previous), load_crawl(args.current)
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
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
