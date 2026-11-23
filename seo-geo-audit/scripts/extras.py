"""Pure helpers for collect.py: analytics detection, forms, contact links, hreflang and asset summaries.

No network access and no file access in this module. Everything here reads data that
collect.py already extracted from third-party pages, so all strings stay untrusted data.
All regular expressions are anchored on literal text and use bounded quantifiers, and
inline scripts are length-capped by the caller, so nothing here can backtrack badly.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

# --------------------------------------------------------------------------- analytics

# (tool, regex on the lowercase script/iframe URL, regex for an id on the original URL or None)
_SRC_RULES = [
    ("Google Tag Manager", r"googletagmanager\.com/(?:gtm\.js|ns\.html)", r"[?&]id=(GTM-[A-Z0-9]{4,10})"),
    ("Google Analytics (gtag.js)", r"googletagmanager\.com/gtag/js",
     r"[?&]id=((?:G|AW|DC)-[A-Z0-9]{4,12}|UA-\d{4,10}-\d{1,3})"),
    ("Universal Analytics (obsolete)", r"google-analytics\.com/(?:analytics|ga)\.js", None),
    ("Meta Pixel", r"connect\.facebook\.net/[^/]{2,12}/fbevents\.js", None),
    ("Microsoft Clarity", r"clarity\.ms/tag/", r"clarity\.ms/tag/([a-z0-9]{6,14})"),
    ("Hotjar", r"static\.hotjar\.com/c/hotjar-", r"hotjar-(\d{5,9})\.js"),
    ("Yandex Metrika", r"mc\.yandex\.(?:ru|com)/metrika/", None),
    ("TikTok Pixel", r"analytics\.tiktok\.com/i18n/pixel/", None),
    ("LinkedIn Insight", r"snap\.licdn\.com/li\.lt", None),
    ("Matomo", r"(?:matomo|piwik)\.(?:js|php)", None),
    ("Plausible", r"plausible\.io/js/", None),
    ("Fathom", r"cdn\.usefathom\.com", None),
    ("Segment", r"cdn\.segment\.com/analytics\.js", None),
    ("Mixpanel", r"cdn\.mxpnl\.com|cdn\.mixpanel\.com", None),
    ("Amplitude", r"cdn\.amplitude\.com", None),
    ("Cloudflare Web Analytics", r"static\.cloudflareinsights\.com/beacon", None),
    ("Vercel Analytics", r"/_vercel/insights/", None),
    ("HubSpot", r"js\.hs-scripts\.com|js\.hs-analytics\.net", r"/(\d{4,10})\.js"),
]
SRC_RULES = [(t, re.compile(r), re.compile(i, re.I) if i else None) for t, r, i in _SRC_RULES]

_CONSENT_RULES = [
    ("Cookiebot", r"consent\.cookiebot\.com"), ("OneTrust", r"cdn\.cookielaw\.org|onetrust\.com"),
    ("Usercentrics", r"usercentrics\.eu"), ("CookieYes", r"cdn-cookieyes\.com"),
    ("Iubenda", r"cdn\.iubenda\.com"), ("Osano", r"osano\.com"),
    ("Complianz", r"complianz"), ("Cookie Law Info", r"cookie-law-info"),
]
CONSENT_RULES = [(t, re.compile(r)) for t, r in _CONSENT_RULES]

_ANTISPAM_RULES = [
    ("reCAPTCHA", r"google\.com/recaptcha|gstatic\.com/recaptcha|recaptcha\.net"),
    ("hCaptcha", r"hcaptcha\.com"), ("Cloudflare Turnstile", r"challenges\.cloudflare\.com/turnstile"),
    ("Friendly Captcha", r"friendlycaptcha"), ("ALTCHA", r"altcha"),
]
ANTISPAM_RULES = [(t, re.compile(r)) for t, r in _ANTISPAM_RULES]

GA_ID = re.compile(r"gtag\(\s*['\"]config['\"]\s*,\s*['\"]((?:G|AW|DC)-[A-Z0-9]{4,12}|UA-\d{4,10}-\d{1,3})['\"]")
UA_ID = re.compile(r"ga\(\s*['\"]create['\"]\s*,\s*['\"](UA-\d{4,10}-\d{1,3})['\"]")
GTM_ID = re.compile(r"(?:['\"]script['\"]\s*,\s*['\"]dataLayer['\"]\s*,\s*|gtm\.js\?id=)['\"]?(GTM-[A-Z0-9]{4,10})")
FB_ID = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"]?(\d{6,20})")
CLARITY_ID = re.compile(r"\"clarity\"\s*,\s*\"script\"\s*,\s*\"([a-z0-9]{6,14})\"")
HOTJAR_ID = re.compile(r"hjid\s*:\s*(\d{5,9})")
YM_ID = re.compile(r"ym\(\s*(\d{5,10})\s*,\s*['\"]init")
TTQ_ID = re.compile(r"ttq\.load\(\s*['\"]([A-Z0-9]{10,24})")
EVENT_PATTERNS = {
    "gtag_event": re.compile(r"gtag\(\s*['\"]event['\"]"),
    "fbq_track": re.compile(r"fbq\(\s*['\"]track(?:Custom)?['\"]"),
    "dataLayer_push": re.compile(r"dataLayer\.push\("),
    "ym_goal": re.compile(r"reachGoal"),
    "matomo_event": re.compile(r"_paq\.push\(\s*\[\s*['\"]trackEvent['\"]"),
}


def _norm_id(value: str) -> str:
    return value.upper() if re.match(r"(?i)(g|aw|dc|ua|gtm)-", value) else value


def add_if(add, tool, ids):
    if ids:
        add(tool, ids)


def detect_analytics(script_srcs, inline_scripts, iframe_srcs) -> dict:
    """Standard analytics, consent and anti-spam snippets found in a page's source.

    Static source only: tags injected later by a tag manager, after consent or by
    server-side tagging are not visible here.
    """
    tools: dict[str, set] = {}

    def add(tool, ids=()):
        tools.setdefault(tool, set()).update(_norm_id(i) for i in ids if i)

    consent, antispam = set(), set()
    for src in list(script_srcs)[:80] + list(iframe_srcs)[:30]:
        if not isinstance(src, str):
            continue
        low = src.lower()
        for tool, rx, id_rx in SRC_RULES:
            if rx.search(low):
                m = id_rx.search(src) if id_rx else None
                add(tool, [m.group(1)] if m else [])
        for name, rx in CONSENT_RULES:
            if rx.search(low):
                consent.add(name)
        for name, rx in ANTISPAM_RULES:
            if rx.search(low):
                antispam.add(name)
    events: Counter = Counter()
    datalayer = False
    for text in list(inline_scripts)[:40]:
        if not isinstance(text, str) or not text:
            continue
        if "gtag(" in text:
            ids = GA_ID.findall(text)
            for i in ids:
                add("Universal Analytics (obsolete)" if i.startswith("UA-") else "Google Analytics (gtag.js)", [i])
        if "ga(" in text and "create" in text:
            for i in UA_ID.findall(text):
                add("Universal Analytics (obsolete)", [i])
        # An inline script counts only when it actually initialises the tool (a call with an ID).
        # A URL or a name inside a settings object (e.g. a CMS config with "enabled: false") does not.
        if "GTM-" in text:
            add_if(add, "Google Tag Manager", GTM_ID.findall(text)[:3])
        if "fbq(" in text:
            add_if(add, "Meta Pixel", FB_ID.findall(text)[:3])
        if '"clarity"' in text:
            add_if(add, "Microsoft Clarity", CLARITY_ID.findall(text)[:2])
        if "hjid" in text:
            add_if(add, "Hotjar", HOTJAR_ID.findall(text)[:2])
        if "ym(" in text:
            add_if(add, "Yandex Metrika", YM_ID.findall(text)[:3])
        if "ttq.load" in text:
            add_if(add, "TikTok Pixel", TTQ_ID.findall(text)[:2])
        if "_paq.push" in text:
            add("Matomo")
        if "dataLayer" in text:
            datalayer = True
        for name, rx in EVENT_PATTERNS.items():
            n = len(rx.findall(text))
            if n:
                events[name] += n
    return {"tools": [{"tool": t, "ids": sorted(i)[:5]} for t, i in sorted(tools.items())],
            "consent": sorted(consent), "anti_spam": sorted(antispam),
            "datalayer": datalayer, "event_snippets": dict(events)}


def summarize_analytics(real_pages: list) -> dict:
    n = len(real_pages)
    tool_pages: Counter = Counter()
    tool_ids: dict[str, set] = defaultdict(set)
    consent, antispam, events = set(), set(), Counter()
    without, datalayer_pages = [], 0
    both_on_page = 0
    for p in real_pages:
        a = p.get("analytics") or {}
        names = set()
        for t in a.get("tools", []):
            names.add(t["tool"])
            tool_ids[t["tool"]].update(t.get("ids", []))
        for name in names:
            tool_pages[name] += 1
        consent.update(a.get("consent", []))
        antispam.update(a.get("anti_spam", []))
        events.update(a.get("event_snippets", {}))
        datalayer_pages += 1 if a.get("datalayer") else 0
        if not names:
            without.append(p.get("url"))
        ga4 = any(i.startswith("G-") for t in a.get("tools", []) if t["tool"].startswith("Google Analytics")
                  for i in t.get("ids", []))
        if "Google Tag Manager" in names and ga4:
            both_on_page += 1
    flags = []
    if n and not tool_pages:
        flags.append({"code": "no_analytics_detected",
                      "detail": "no standard analytics or tag-manager snippet in the page source; it may load after "
                                "consent, via server-side tagging or be absent. Confirm in a browser (network tab)"})
    if any(i.startswith("UA-") for ids in tool_ids.values() for i in ids) or "Universal Analytics (obsolete)" in tool_pages:
        flags.append({"code": "obsolete_universal_analytics",
                      "detail": "Universal Analytics (UA-) stopped processing data in July 2023; migrate to GA4"})
    ga4_ids = sorted({i for t, ids in tool_ids.items() if t.startswith("Google Analytics") for i in ids if i.startswith("G-")})
    if len(ga4_ids) > 1:
        flags.append({"code": "multiple_ga4_ids", "detail": f"{len(ga4_ids)} GA4 measurement IDs in the source: "
                                                            + ", ".join(ga4_ids[:5])})
    if both_on_page:
        flags.append({"code": "gtm_and_direct_gtag",
                      "detail": f"{both_on_page} page(s) load both Google Tag Manager and gtag.js with a GA4 ID: "
                                "events may be counted twice; check the GTM container for a second GA4 tag"})
    for tool in ("Google Tag Manager", "Google Analytics (gtag.js)", "Meta Pixel"):
        c = tool_pages.get(tool, 0)
        if n >= 3 and 0 < c < n:
            flags.append({"code": "tracking_on_some_pages_only",
                          "detail": f"{tool} found on {c} of {n} crawled pages: a template or page type is missing it"})
    return {
        "tools": [{"tool": t, "ids": sorted(tool_ids[t])[:8], "pages": c} for t, c in tool_pages.most_common()],
        "pages_without_tracking": without[:20], "pages_without_tracking_count": len(without),
        "consent_tools": sorted(consent), "anti_spam_scripts": sorted(antispam),
        "event_snippets_in_source": dict(events), "datalayer_pages": datalayer_pages,
        "flags": flags,
        "note": "Static page source only. Whether events actually fire (form submits, phone/messenger clicks) "
                "needs a browser with network inspection or the analytics debug view and is not checked here.",
    }


# --------------------------------------------------------------------------- forms & contacts

def summarize_forms(real_pages: list) -> dict:
    """Unique forms across pages, with the signals that matter for spam and data quality."""
    unique: dict[tuple, dict] = {}
    pages_with_forms, js_forms = 0, []
    for p in real_pages:
        forms = p.get("forms") or []
        if forms:
            pages_with_forms += 1
        elif (p.get("orphan_fields") or 0) > 0:
            js_forms.append(p.get("url"))
        page_protected = bool((p.get("analytics") or {}).get("anti_spam"))
        for f in forms:
            names = tuple(sorted(x.get("name") or x.get("type") or "" for x in f.get("fields", [])))
            key = (f.get("action_host"), f.get("method"), names)
            u = unique.get(key)
            if u is None:
                u = unique[key] = {**f, "pages": 0, "example_url": p.get("url"),
                                   "protected": bool(f.get("captcha") or f.get("honeypot_suspected") or page_protected)}
            u["pages"] += 1
    forms = sorted(unique.values(), key=lambda x: -x["pages"])
    return {
        "pages_with_forms": pages_with_forms,
        "unique_forms": len(forms),
        "forms": forms[:15],
        "forms_without_visible_spam_protection": sum(1 for f in forms if not f["protected"]),
        "forms_with_get_method": sum(1 for f in forms if f.get("method") == "get" and (f.get("has_email") or f.get("has_phone"))),
        "forms_posting_insecurely": sum(1 for f in forms if f.get("action_insecure")),
        "forms_without_required_fields": sum(1 for f in forms if f.get("field_count") and not f.get("required_count")),
        "forms_without_submit_button": sum(1 for f in forms if not f.get("has_submit")),
        "pages_with_js_form_suspected": js_forms[:10],
        "note": "Read from HTML only: nothing was submitted. Server-side validation, rate limiting, the "
                "confirmation message and delivery to the manager need an authorised test submission.",
    }


CONTACT_KINDS = ("tel", "mailto", "whatsapp", "telegram", "viber", "messenger", "signal", "sms", "skype")


def summarize_contacts(real_pages: list) -> dict:
    totals: Counter = Counter()
    pages: Counter = Counter()
    for p in real_pages:
        for kind, n in (p.get("contact_links") or {}).items():
            if n:
                totals[kind] += n
                pages[kind] += 1
    return {"links": dict(totals), "pages": dict(pages)}


# --------------------------------------------------------------------------- hreflang

HREFLANG_RX = re.compile(r"^(?:x-default|[a-z]{2,3}(?:-[a-z]{4})?(?:-(?:[a-z]{2}|\d{3}))?)$", re.I)
# ISO 639-1 (plus deprecated aliases Google still reads) and ISO 3166-1 alpha-2 (plus XK). Three-letter
# language codes and numeric regions (es-419) are accepted without a list check.
ISO_639_1 = set("""aa ab ae af ak am an ar as av ay az ba be bg bi bm bn bo br bs ca ce ch co cr cs cu cv cy da
de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik
io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk ml mn mr ms
mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm
sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi yo za zh zu
in iw ji jw mo sh""".split())
ISO_3166_1 = set("""ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br
bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et
fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq
ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml
mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps
pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl
tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws xk ye yt za zm zw""".split())
COMMON_MISTAKES = {"uk": "gb", "en-uk": "en-GB"}


def hreflang_code_problem(code: str) -> str | None:
    """None when the code is valid, else a short reason (with the usual fix)."""
    code = (code or "").strip()
    if not HREFLANG_RX.match(code):
        return "not a language[-region] code"
    if code.lower() == "x-default":
        return None
    parts = code.lower().split("-")
    lang = parts[0]
    if len(lang) == 2 and lang not in ISO_639_1:
        return "unknown language" + (" (Ukrainian is 'uk', not 'ua')" if lang == "ua" else "")
    region = parts[-1] if len(parts) > 1 and len(parts[-1]) == 2 else None
    if region and region not in ISO_3166_1:
        return "unknown region" + (" (the United Kingdom is 'GB', e.g. en-GB)" if region == "uk" else "")
    return None


def hreflang_missing(pages: list, key, same_site_fn, limit: int) -> list[str]:
    """Same-site alternate URLs named in hreflang annotations that were not crawled."""
    have = {key(p.get("final_url") or p.get("url") or "") for p in pages}
    out: list[str] = []
    for p in pages:
        for e in p.get("hreflang") or []:
            href = e.get("href")
            if not href or not same_site_fn(href) or key(href) in have or href in out:
                continue
            out.append(href)
            if len(out) >= limit:
                return out
    return out


def _lang_primary(code: str) -> str:
    return (code or "").lower().split("-")[0]


def hreflang_check(pages: list, extra: dict, key, same_site_fn, fetched: int = 0) -> dict:
    """Validate hreflang annotations on crawled pages, using fetched alternates for return links.

    `extra` maps key(url) to an analyze_page-shaped record (or {"error": ..} / {"status": ..})
    for alternates that were fetched on top of the crawl.
    """
    info = {}
    for p in pages:
        info[key(p.get("final_url") or p.get("url") or "")] = p
    info.update(extra)
    issues: list[dict] = []
    counts: Counter = Counter()
    codes: set = set()
    with_hreflang, unverified, external = 0, 0, 0
    x_default = False

    def add(kind, page, other=None, detail=None):
        counts[kind] += 1
        if len(issues) < 60:
            issues.append({"type": kind, "page": page, "other": other, "detail": detail})

    for p in pages:
        entries = [e for e in (p.get("hreflang") or []) if isinstance(e, dict)]
        if not entries:
            continue
        with_hreflang += 1
        url = p.get("final_url") or p.get("url")
        me = key(url)
        seen: dict[str, str] = {}
        self_entry = None
        for e in entries:
            code, href = (e.get("hreflang") or "").strip(), e.get("href")
            problem = hreflang_code_problem(code)
            if problem:
                add("invalid_code", url, href, f"'{code}': {problem}")
                continue
            codes.add(code.lower())
            if code.lower() == "x-default":
                x_default = True
            if href and code.lower() in seen and key(href) != seen[code.lower()]:
                add("duplicate_code", url, href, f"'{code}' points to two different URLs")
            seen.setdefault(code.lower(), key(href or ""))
            if href and key(href) == me:
                self_entry = code
        canon = (p.get("canonical") or [None])[0]
        if canon and key(canon) != me:
            by_url = {key(e.get("href") or ""): (e.get("hreflang") or "") for e in entries}
            target_code = by_url.get(key(canon))
            if target_code is None:
                add("canonical_not_in_set", url, canon, "its canonical is not among its hreflang alternates, so "
                                                        "Google ignores the annotations")
            elif self_entry and _lang_primary(target_code) != _lang_primary(self_entry) \
                    and target_code.lower() != "x-default":
                add("cross_locale_canonical", url, canon, f"the '{self_entry}' page canonicalises to the "
                                                          f"'{target_code}' version, which hides it from search")
        if self_entry is None:
            add("missing_self_reference", url, None, "the page does not list itself among its alternates")
        elif p.get("lang") and self_entry.lower() != "x-default" \
                and _lang_primary(self_entry) != _lang_primary(p.get("lang")):
            add("lang_mismatch", url, None, f"html lang='{p.get('lang')}' but its own hreflang is '{self_entry}'")
        for e in entries:
            href, code = e.get("href"), e.get("hreflang")
            if not href or key(href) == me or not HREFLANG_RX.match(code or ""):
                continue
            if not same_site_fn(href):
                external += 1
                continue
            other = info.get(key(href))
            if other is None:
                unverified += 1
                continue
            status = other.get("status")
            if other.get("error") or (status and status != 200):
                add("alternate_error", url, href, other.get("error") or f"HTTP {status}")
                continue
            if "title" not in other:
                continue
            if key(other.get("final_url") or href) != key(href):
                add("alternate_redirects", url, href, f"redirects to {other.get('final_url')}")
            robots = ((other.get("meta_robots") or "") + " " + (other.get("x_robots_tag") or "")).lower()
            if "noindex" in robots:
                add("alternate_noindex", url, href, "the alternate is noindex")
            canon = other.get("canonical") or []
            if canon and key(canon[0]) != key(other.get("final_url") or href):
                add("alternate_canonical_elsewhere", url, href, f"its canonical is {canon[0]}")
            back = [x for x in (other.get("hreflang") or []) if isinstance(x, dict)]
            if not any(key(x.get("href") or "") == me for x in back):
                add("no_return_link", url, href, "the alternate does not link back"
                    if back else "the alternate has no hreflang annotations")
    return {
        "pages_with_hreflang": with_hreflang,
        "codes": sorted(codes),
        "x_default_present": x_default,
        "alternates_fetched": fetched,
        "unverified_alternates": unverified,
        "external_alternates": external,
        "issue_counts": dict(counts),
        "issues": issues,
    }


# --------------------------------------------------------------------------- assets & links

KB = 1024
THRESHOLDS = {"image": (200 * KB, 500 * KB, 1024 * KB), "stylesheet": (100 * KB, 300 * KB, 600 * KB),
              "script": (100 * KB, 300 * KB, 600 * KB)}
MODERN_FORMATS = {"webp", "avif"}
RASTER = {"jpeg", "jpg", "png", "gif", "webp", "avif", "bmp"}
SHORT_CACHE_SECONDS = 7 * 24 * 3600


def cache_max_age(headers: dict) -> int | None:
    cc = (headers.get("cache-control") or "").lower()
    m = re.search(r"(?:s-)?max-age=(\d{1,10})", cc)
    if m:
        return int(m.group(1))
    if "no-store" in cc or "no-cache" in cc:
        return 0
    return None


def asset_record(kind: str, url: str, res: dict, pages_using: int = 1) -> dict:
    headers = res.get("headers") or {}
    length = headers.get("content-length", "")
    size = int(length) if length.isdigit() else (res.get("body_bytes") if res.get("status") == 200
                                                  and not res.get("truncated") and res.get("body_bytes") else None)
    ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
    m = re.search(r"image/([a-z0-9.+-]+)", ctype)
    fmt = m.group(1).replace("svg+xml", "svg") if m else None
    if kind == "image" and not fmt:
        ext = re.search(r"\.([a-z0-9]{3,4})(?:$|\?)", url.lower())
        fmt = ext.group(1) if ext else None
    age = cache_max_age(headers)
    return {"kind": kind, "url": url, "status": res.get("status"), "error": res.get("error"),
            "bytes": size, "content_type": ctype or None, "format": fmt,
            "content_encoding": (headers.get("content-encoding") or "").lower() or None,
            "cache_max_age": age,
            "has_cache_header": bool(headers.get("cache-control") or headers.get("expires")),
            "pages": pages_using}


def summarize_assets(items: list[dict]) -> dict:
    out: dict = {"checked": len(items)}
    for kind in ("image", "stylesheet", "script"):
        rows = [i for i in items if i["kind"] == kind]
        if not rows:
            continue
        measured = [i for i in rows if i.get("bytes") is not None and (i.get("status") or 0) < 400]
        t1, t2, t3 = THRESHOLDS[kind]
        entry = {
            "checked": len(rows), "measured": len(measured),
            "errors": sum(1 for i in rows if i.get("error") or (i.get("status") or 0) >= 400),
            "total_kb": round(sum(i["bytes"] for i in measured) / KB),
            f"over_{t1 // KB}kb": sum(1 for i in measured if i["bytes"] > t1),
            f"over_{t2 // KB}kb": sum(1 for i in measured if i["bytes"] > t2),
            f"over_{t3 // KB}kb": sum(1 for i in measured if i["bytes"] > t3),
            "largest": [{"url": i["url"], "kb": round(i["bytes"] / KB), "format": i.get("format"),
                         "pages": i.get("pages")} for i in sorted(measured, key=lambda x: -x["bytes"])[:8]],
            "no_cache_header": sum(1 for i in rows if not i.get("has_cache_header") and (i.get("status") or 0) < 400),
            "short_cache": sum(1 for i in rows if i.get("cache_max_age") is not None
                               and i["cache_max_age"] < SHORT_CACHE_SECONDS and (i.get("status") or 0) < 400),
        }
        if kind == "image":
            raster = [i for i in measured if (i.get("format") or "") in RASTER]
            entry["formats"] = dict(Counter(i.get("format") or "unknown" for i in rows).most_common(8))
            entry["modern_format_share_pct"] = (int(100 * sum(1 for i in raster if i["format"] in MODERN_FORMATS)
                                                    / len(raster)) if raster else None)
        else:
            entry["uncompressed_text"] = sum(1 for i in measured if i["bytes"] > 2 * KB and not i.get("content_encoding"))
        out[kind + "s"] = entry
    return out


def classify_external(res: dict) -> str:
    if res.get("error"):
        return "unreachable"
    status = res.get("status") or 0
    if 200 <= status < 400:
        return "ok"
    if status in (401, 403, 429, 451, 999):
        return "bot_blocked"
    if status >= 500:
        return "server_error"
    return "broken"


def pick_external(pages: list, limit: int, per_host: int = 2) -> list[tuple[str, str]]:
    """Up to `limit` external URLs spread across hosts: [(url, first page it was found on)]."""
    from urllib.parse import urlsplit
    by_host: dict[str, list[tuple[str, str]]] = {}
    seen: set = set()
    for p in pages:
        for u in p.get("external_urls") or []:
            if u in seen:
                continue
            seen.add(u)
            host = (urlsplit(u).hostname or "").lower()
            by_host.setdefault(host, []).append((u, p.get("url")))
    out: list[tuple[str, str]] = []
    for rnd in range(per_host):
        for items in by_host.values():
            if rnd < len(items) and len(out) < limit:
                out.append(items[rnd])
    return out


# --------------------------------------------------------------------------- site structure

def architecture(home: str, edges: dict, aliases: dict, crawled: set, sitemap: list, deep_after: int = 3) -> dict:
    """Click depth from the home page over the crawled link graph, weakly linked pages and orphan suspects.

    edges: crawled page key -> internal link keys found on it. aliases: requested key -> final key
    (redirects). Depth is exact only inside the crawled part of the site; links to pages that were not
    crawled get a depth but contribute no links of their own.
    """
    def resolve(k):
        return aliases.get(k, k)

    graph = {resolve(src): {resolve(d) for d in dsts} for src, dsts in edges.items()}
    home = resolve(home)
    depth = {home: 0}
    queue = [home]
    for node in queue:  # BFS; the list grows while iterating
        for nxt in sorted(graph.get(node, ())):
            if nxt not in depth:
                depth[nxt] = depth[node] + 1
                queue.append(nxt)
    inlinks = Counter()
    for src, dsts in graph.items():
        for d in dsts:
            if d != src:
                inlinks[d] += 1
    crawled_r = {resolve(k) for k in crawled}
    sitemap_r = list(dict.fromkeys(resolve(k) for k in sitemap))
    coverage = len(crawled_r & set(sitemap_r)) / len(sitemap_r) if sitemap_r else None
    return {
        "depth_distribution": {str(k): v for k, v in sorted(Counter(depth.values()).items())},
        "pages_deeper_than_3_clicks": [k for k, d in sorted(depth.items(), key=lambda x: -x[1]) if d > deep_after][:20],
        "crawled_not_reachable_from_home": sorted(k for k in crawled_r if k not in depth)[:20],
        "weakly_linked_crawled_pages": sorted((k for k in crawled_r if k != home and inlinks.get(k, 0) <= 1),
                                              key=lambda k: inlinks.get(k, 0))[:20],
        "sitemap_urls_not_linked": [k for k in sitemap_r if k != home and inlinks.get(k, 0) == 0][:30],
        "sitemap_coverage": round(coverage, 2) if coverage is not None else None,
        "note": "Computed from the crawled pages only. With low sitemap_coverage a page may be linked from a page "
                "the crawl did not reach, so treat sitemap_urls_not_linked as orphan suspects, not proof.",
    }


TITLE_WORD = re.compile(r"[^\W\d_]{3,}", re.UNICODE)


def cannibalization(real_pages: list, threshold: float = 0.7) -> list[dict]:
    """Pairs of pages whose titles (minus words shared by most titles, e.g. the brand) or H1s nearly match:
    candidates for pages competing for the same query."""
    rows = []
    for p in real_pages:
        words = {w.lower() for w in TITLE_WORD.findall(p.get("title") or "")}
        h1 = next((h.get("text") for h in p.get("headings", []) if h.get("level") == 1 and h.get("text")), "")
        rows.append((p.get("final_url") or p.get("url"), p.get("title") or "", words, " ".join(h1.lower().split())))
    if len(rows) >= 4:
        df = Counter(w for _, _, words, _ in rows for w in words)
        common = {w for w, n in df.items() if n > len(rows) / 2}
        rows = [(u, t, words - common, h1) for u, t, words, h1 in rows]
    out = []
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            (u1, t1, w1, h1), (u2, t2, w2, h2) = rows[i], rows[j]
            if u1 == u2:
                continue
            reason, score = None, 0.0
            if len(w1) >= 2 and len(w2) >= 2:
                score = len(w1 & w2) / len(w1 | w2)
                if score >= threshold:
                    reason = "similar titles"
            if not reason and h1 and h1 == h2:
                reason, score = "same H1", 1.0
            if reason:
                out.append({"pages": [u1, u2], "titles": [t1[:120], t2[:120]], "reason": reason,
                            "similarity": round(score, 2)})
                if len(out) >= 15:
                    return out
    return out
