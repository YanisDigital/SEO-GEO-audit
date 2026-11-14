# Security policy

## Threat model

The skill makes an AI agent fetch and read content from arbitrary third-party websites and AI answer engines, then write files on the user's machine. We assume:

- **Audited websites may be hostile.** They may contain prompt-injection text, redirects to internal addresses, huge or compressed responses, malformed HTML/XML, or XML entity bombs.
- **The user's machine may sit on a private network** with internal services and cloud metadata endpoints.
- **Reports may be shared** with clients and opened in browsers.

## Controls

| Risk | Control | Where |
|---|---|---|
| Prompt injection from site content or AI answers | Ground rule #1: content is data, never instructions; suspicious text is reported as a finding. JSON output carries an `_untrusted_notice`. | `SKILL.md`, `collect.py` |
| SSRF to localhost, LAN or cloud metadata | http/https only; ports 80/443; no credentials in URLs; every resolved address must be globally routable; IPv4 embedded in IPv6 (IPv4-mapped, NAT64 `64:ff9b::/96`) is checked as IPv4, other IPv4-embedding ranges (IPv4-compatible, 6to4, Teredo, local-use NAT64) are refused; socket pinned to the validated IP; each redirect hop re-validated; max 5 hops; proxies from the environment are ignored | `scripts/netsafe.py` |
| Resource exhaustion | 3 MB body cap per page (10 MB for sitemaps), bounded gzip/deflate decompression, per-request timeouts and total deadlines, page cap (25 default, 200 hard), link-check cap (100), sitemap caps | `netsafe.py`, `collect.py` |
| CPU exhaustion from crafted content (ReDoS, parser worst cases) | robots.txt, sitemaps and report text are parsed line-by-line or with linear-time scanners, no backtracking regexes on untrusted input; unterminated markup left at the end of an HTML page is not flushed through `HTMLParser.close()`, which is quadratic on Python versions without the CVE-2025-6069 fix | `collect.py`, `render_report.py` |
| XML entity expansion (billion laughs), XXE | sitemaps are parsed with expat directly; any DOCTYPE, entity declaration or external entity reference aborts parsing, wherever it appears in the file | `collect.py` |
| Aggressive crawling | robots.txt respected for crawled pages, internal link checks, hreflang alternates and same-site assets; not applied to the user-supplied start URL and to single requests for well-known files (robots.txt, sitemaps, llms.txt, security.txt), host-variant checks and one 404 probe; Crawl-delay honoured (capped at 10 s); minimum 0.5 s between requests per host; GET/HEAD only. Extra requests are capped (300 internal links, 100 assets, 50 external links, 30 hreflang alternates; `--light` turns them off) and go through the same SSRF-safe fetcher; external links and CDN assets are single ordinary requests spread across hosts, never crawled further | `collect.py` |
| Active security testing of third-party sites | Out of scope by design: no path probing, scanning, fuzzing, payloads or logins | `references/site-security.md` |
| Secret leakage | Only optional secret is `PSI_API_KEY`, read from the environment, sent only to `www.googleapis.com` over HTTPS in the `X-goog-api-key` header (never in a URL), redirects not followed, redacted from error messages, never written to output | `scripts/psi.py` |
| Cookie and PII collection | Cookie names and values are never stored, only Secure/HttpOnly/SameSite flags; the skill tells the agent not to copy private individuals' data into reports | `netsafe.py`, `report-spec.md` |
| XSS in shared reports | All values HTML-escaped; links only for `http(s)` URLs with `rel="noopener noreferrer nofollow"`; CSP `default-src 'none'` (no scripts, no external loads, no forms); `noindex`; in Markdown, raw HTML, link/image brackets, backslashes and stray backticks outside code spans are escaped (no remote images or `javascript:` links), line breaks inside values are flattened, and code fences are sized so content can't break out | `scripts/render_report.py`, `assets/report-template.html` |
| Formula injection in tasks.csv | Cells that start with `=`, `+`, `-`, `@`, tab or CR (also full-width variants, after leading spaces) are prefixed with an apostrophe, so a spreadsheet shows them as text instead of running them | `scripts/render_report.py` |
| Passive forms and tracking checks | Forms are read from the HTML only: nothing is submitted, hidden-field values (CSRF tokens) and field contents are never stored, only field names, types and whether a field is required. Tracking detection reads standard snippets in the page source and stores analytics IDs (public by design); no cookies or consent banners are interacted with | `scripts/collect.py`, `scripts/extras.py` |
| Hidden-path probing | The skill does not request `/.git`, `/.env`, admin or backup paths; server-side exposure checks are outside its scope and need the site owner | `SKILL.md` |
| Untrusted competitor URLs | Competitors picked from AI answers or search results go through the same shell-quoting rules and the same SSRF-safe collector as the client; `benchmark.py`, `gaps.py` and `compare.py` make no network requests, read only local files (size caps; keyword lists 5 MB / 5000 rows) and their output is escaped by the renderer like any other site text | `SKILL.md`, `scripts/benchmark.py`, `scripts/gaps.py`, `scripts/compare.py`, `scripts/render_report.py` |
| Personal data from listings | The entity protocol records business NAP, ratings and review counts only; reviewer names and review text with personal details are not copied | `references/entity-directories.md` |
| Client data committed to git | `audits/` ignored; the skill checks `git check-ignore` before writing inside a repository | `.gitignore`, `SKILL.md` |
| Local code hijacking via downloaded files | Scripts are run with `python -I` (isolated mode); downloaded content is never executed | `SKILL.md` |
| Supply chain | No third-party Python packages; no remote scripts in the report | whole repo |

Regression tests for these controls live in `tests/test_security.py` (offline, stdlib only): `python -I -m unittest discover -s tests`.

## Privacy notes for users

- **Browser profile.** The browser steps run in the browser the agent controls. If that profile is signed in to Google, ChatGPT or Perplexity, the live AI checks run under that account and end up in its history. Use a profile without personal sign-ins if that matters.
- **Local client data.** `audits/` holds crawl data and reports about client sites. It is git-ignored, but it stays on disk until you delete it.
- **Python version.** Keep Python up to date (3.12.11+ / 3.13.5+ or later). Older versions have a quadratic-time bug in `html.parser` (CVE-2025-6069). The collector works around it, but other tools on your machine won't.

## Reporting a vulnerability

Please open a private security advisory on this repository (GitHub → Security → *Report a vulnerability*) rather than a public issue. Include steps to reproduce and the affected file. We aim to respond within 7 days.

## Responsible use

Use the skill on sites you own or audit for a client, and only for passive, publicly observable checks. Deeper security testing requires written authorization from the site owner and appropriate tools. This skill does not do it.
