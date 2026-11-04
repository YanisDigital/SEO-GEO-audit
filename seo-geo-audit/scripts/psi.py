#!/usr/bin/env python3
"""Google PageSpeed Insights (Lighthouse + CrUX field data) summary, stdlib only.

Usage:
    python -I psi.py https://example.com --strategy both --out audits/<dir>/psi.json

API key (optional): set the environment variable PSI_API_KEY. Without a key the
public quota is small and requests may fail with HTTP 429.
The key is read only from the environment, is sent only to www.googleapis.com
over HTTPS in the X-goog-api-key header (never in the URL), redirects are not
followed, and it is never printed, logged or written to the output file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netsafe import UnsafeURLError, normalize_input_url, validate_url  # noqa: E402

ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
CATEGORIES = ["performance", "accessibility", "best-practices", "seo"]
LAB_METRICS = ["first-contentful-paint", "largest-contentful-paint", "total-blocking-time",
               "cumulative-layout-shift", "speed-index", "interactive"]


def redact(text: str, secret: str | None) -> str:
    return text.replace(secret, "[REDACTED]") if secret else text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would forward the API key header to the new host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def build_request(url: str, strategy: str, key: str | None) -> urllib.request.Request:
    """The key goes in a header, not the query string, so it never appears in URLs or logs."""
    params = [("url", url), ("strategy", strategy)] + [("category", c) for c in CATEGORIES]
    headers = {"User-Agent": "seo-geo-audit/1.0"}
    if key:
        headers["X-goog-api-key"] = key
    return urllib.request.Request(ENDPOINT + "?" + urlencode(params), headers=headers)


def run(url: str, strategy: str, key: str | None) -> dict:
    req = build_request(url, strategy, key)
    try:
        with _OPENER.open(req, timeout=120) as resp:  # fixed https host
            data = json.loads(resp.read(30 * 1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        msg = ""
        try:
            msg = json.loads(exc.read(64 * 1024).decode("utf-8")).get("error", {}).get("message", "")
        except Exception:
            pass
        hint = " (quota exceeded - set PSI_API_KEY)" if exc.code == 429 else ""
        return {"strategy": strategy, "error": redact(f"HTTP {exc.code}: {msg[:300]}{hint}", key)}
    except Exception as exc:  # network errors, timeouts
        return {"strategy": strategy, "error": redact(f"{exc.__class__.__name__}: {str(exc)[:200]}", key)}
    return summarize(data, strategy)


def summarize(data: dict, strategy: str) -> dict:
    lh = data.get("lighthouseResult", {})
    audits = lh.get("audits", {})
    out = {
        "strategy": strategy,
        "tested_url": lh.get("finalDisplayedUrl") or lh.get("finalUrl"),
        "lighthouse_version": lh.get("lighthouseVersion"),
        "scores": {c: (round(lh["categories"][c]["score"] * 100) if lh.get("categories", {}).get(c, {}).get("score")
                       is not None else None) for c in CATEGORIES},
        "lab": {m: {"value": audits.get(m, {}).get("displayValue"),
                    "numeric": audits.get(m, {}).get("numericValue")} for m in LAB_METRICS},
    }
    for label, block in (("field_page", data.get("loadingExperience")),
                         ("field_origin", data.get("originLoadingExperience"))):
        if block and block.get("metrics"):
            out[label] = {"overall": block.get("overall_category"),
                          "metrics": {k: {"p75": v.get("percentile"), "category": v.get("category")}
                                      for k, v in block["metrics"].items()}}
        else:
            out[label] = None
    opps = []
    for aid, a in audits.items():
        det = a.get("details") or {}
        if det.get("type") == "opportunity" and (a.get("score") or 0) < 0.9:
            opps.append({"id": aid, "title": a.get("title"), "savings": a.get("displayValue"),
                         "ms": det.get("overallSavingsMs") or 0})
    out["opportunities"] = sorted(opps, key=lambda o: -o["ms"])[:10]
    failing = []
    for cat in ("seo", "best-practices", "accessibility"):
        for ref in lh.get("categories", {}).get(cat, {}).get("auditRefs", []):
            a = audits.get(ref.get("id"), {})
            if a.get("score") == 0 and ref.get("weight", 0) > 0:
                failing.append({"category": cat, "id": ref["id"], "title": a.get("title")})
    out["failing_audits"] = failing[:30]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="PageSpeed Insights summary")
    ap.add_argument("urls", nargs="+", help="One or more page URLs (max 5)")
    ap.add_argument("--strategy", choices=["mobile", "desktop", "both"], default="mobile")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    key = os.environ.get("PSI_API_KEY") or None
    strategies = ["mobile", "desktop"] if args.strategy == "both" else [args.strategy]
    results = []
    for raw in args.urls[:5]:
        try:
            url = normalize_input_url(raw)
            validate_url(url)
        except UnsafeURLError as exc:
            results.append({"url": raw, "error": f"invalid url: {exc}"})
            continue
        for st in strategies:
            r = run(url, st, key)
            r["url"] = url
            results.append(r)
            status = r.get("error") or f"performance={r['scores'].get('performance')}"
            print(f"{st:8} {url} -> {status}")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"source": "Google PageSpeed Insights API v5", "api_key_used": bool(key),
                   "results": results}, fh, ensure_ascii=False, indent=1)
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
