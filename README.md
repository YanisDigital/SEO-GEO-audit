# seo-geo-audit — an Agent Skill for SEO + GEO/AEO website audits

Give Claude a website URL and get:

- **`report.html`** — a self-contained report: scores by area, strengths, weaknesses with evidence, a snapshot of visibility in AI answers (Perplexity, Google AI Overviews, ChatGPT), optional competitor comparison.
- **`tz.md`** — a developer-ready action plan: tasks grouped into *do now / next 30 days / strategic*, each with steps, a code or text example, and acceptance criteria.

It covers classic SEO (indexability, canonicals, sitemaps, on-page, structured data, Core Web Vitals, mobile/JS rendering, hreflang, local) and **GEO/AEO** (AI crawler access in robots.txt, rendering for non-JS crawlers, answer-shaped content, entity signals, llms.txt, live answer-engine checks). It also checks passive trust and security hygiene (HTTPS, security headers, mixed content, disclosed versions).

Reports are written in the language you talk to Claude in.

## Install

Claude Code (personal skills):

```bash
git clone https://github.com/YanisDigital/SEO-GEO-audit.git
cp -r SEO-GEO-audit/seo-geo-audit ~/.claude/skills/
```

Or copy the `seo-geo-audit/` folder into a project's `.claude/skills/`. The skill also works in other Agent Skills–compatible clients that can run Python.

**Requirements:** Python 3.9+ (standard library only, no `pip install`). A browser tool (Claude's built-in browser, Claude in Chrome, or a Playwright MCP) is optional. It enables the rendered-page check and the live AI-answer checks.

**Recommended:** a free [PageSpeed Insights API key](https://developers.google.com/speed/docs/insights/v5/get-started) in the `PSI_API_KEY` environment variable. The anonymous API quota is shared and usually exhausted (HTTP 429). Without a key the skill falls back to reading pagespeed.web.dev in the browser, or marks Core Web Vitals as unverified.

```bash
# macOS/Linux (add to your shell profile)
export PSI_API_KEY="your-key"
# Windows PowerShell (persistent for the user)
[Environment]::SetEnvironmentVariable("PSI_API_KEY", "your-key", "User")
```

Restrict the key in Google Cloud Console to the PageSpeed Insights API only.

## Use

> Audit https://example.com — competitors: competitor-a.com, competitor-b.com, region Kyiv

Outputs go to `./audits/<domain>-<date>/` (`crawl.json`, `psi.json`, `report.json`, `report.html`, `tz.md`).

## Layout

```
seo-geo-audit/
  SKILL.md                    workflow and ground rules
  references/                 checklists loaded on demand
    seo-checklist.md
    geo-aeo-checklist.md
    site-security.md
    report-spec.md            report.json schema, scoring, task format
  scripts/
    netsafe.py                hardened HTTP client (SSRF-safe, size/time caps)
    collect.py                passive crawler -> crawl.json
    psi.py                    PageSpeed Insights summary -> psi.json
    render_report.py          report.json -> report.html + tz.md
  assets/report-template.html
```

## Security model

This skill reads content from websites you don't control, so it was designed defensively. See [SECURITY.md](SECURITY.md) for details. In short:

- **Prompt-injection aware:** all site content and AI answers are treated as data. The skill tells the agent never to follow instructions found in them and to report such text as a finding.
- **Passive only:** no form submissions, logins, path probing, scanning or payloads.
- **SSRF-safe networking:** only http/https on ports 80/443, all resolved IPs must be public, the connection is pinned to the validated IP (DNS-rebinding safe), and every redirect hop is re-validated.
- **Polite:** respects robots.txt and Crawl-delay, 1 request/second, 25 pages by default.
- **Bounded:** response size caps, bounded decompression, XML entity/DOCTYPE rejection, timeouts.
- **No secrets in the repo:** the only optional key comes from the environment and is never logged or written.
- **Safe output:** the HTML report escapes all content, has a strict CSP (no scripts, no external requests) and `noindex`.
- **Client data stays out of git:** `audits/` is in `.gitignore`.

## Limitations

- AI answers vary by user, location and time; live checks are a dated snapshot.
- No access to Google Search Console, analytics, backlink databases or server logs. Recommendations involving them are labelled as such.
- JavaScript-only content is detected heuristically by the crawler and confirmed in the browser when one is available.

## License

MIT. See [LICENSE](LICENSE).
