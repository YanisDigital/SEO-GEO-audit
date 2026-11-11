# seo-geo-audit — an Agent Skill for SEO + GEO/AEO website audits

Give Claude a website URL and get:

- **`report.html`** — a self-contained report: two headline scores (*Site readiness* and *Real visibility*, because a technically sound site can still be invisible in AI answers), scores by area with the deductions behind them, strengths, weaknesses with evidence, a snapshot of visibility in AI answers (Perplexity, Google AI Overviews, ChatGPT), an entity and listings check (is the name, address and phone consistent across maps and directories, which third-party credentials the site leaves out), and a side-by-side comparison with the competitors that answer engines name instead of the client.
- **`tz.md`** — a developer-ready action plan: tasks grouped into *do now / next 30 days / strategic*, each with steps, a code or text example, and acceptance criteria. The same tasks are exported to **`tasks.csv`** for Jira, Trello, Asana or a spreadsheet.

It covers classic SEO (indexability, canonicals, sitemaps, on-page, structured data, Core Web Vitals, mobile/JS rendering, hreflang, local) and **GEO/AEO** (AI crawler access in robots.txt, rendering for non-JS crawlers, answer-shaped content, entity signals, llms.txt, live answer-engine checks). It also checks passive trust and security hygiene (HTTPS, security headers, mixed content, disclosed versions).

Reports are written in the language you talk to Claude in.

## Install

Claude Code (personal skills):

```bash
git clone https://github.com/YanisDigital/SEO-GEO-audit.git
cp -r SEO-GEO-audit/seo-geo-audit ~/.claude/skills/
```

Or copy the `seo-geo-audit/` folder into a project's `.claude/skills/`. The skill also works in other Agent Skills–compatible clients that can run Python.

Claude apps (claude.ai, desktop): download `seo-geo-audit-skill-vX.Y.Z.zip` from the [latest release](https://github.com/YanisDigital/SEO-GEO-audit/releases/latest) and upload it in Settings → Capabilities → Skills. Use the `-skill-` zip: the other one is the whole repository, and the upload rejects it because `SKILL.md` is not at its top level. Without a browser tool there, the live AI-answer checks, the listings check and the PageSpeed fallback are skipped, and the crawler needs network access in the code sandbox.

**Requirements:** Python 3.9+ (standard library only, no `pip install`; a current patch release is recommended, see [SECURITY.md](SECURITY.md)). A browser tool (Claude's built-in browser, Claude in Chrome, or a Playwright MCP) is optional. It enables the rendered-page check and the live AI-answer checks.

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

Outputs go to `./audits/<domain>-<date>/` (`crawl.json`, `competitor-<n>.json`, `benchmark.json`, `psi.json`, `report.json`, `report.html`, `tz.md`, `tasks.csv`).

Without a competitor list, the skill compares the client with the 2-3 businesses that the answer engines named most often in the live checks.

## Layout

```
seo-geo-audit/
  SKILL.md                    workflow and ground rules
  references/                 checklists loaded on demand
    seo-checklist.md
    geo-aeo-checklist.md
    site-security.md
    entity-directories.md     NAP and listings protocol, directories by business type
    report-spec.md            report.json schema, scoring, task format
  scripts/
    netsafe.py                hardened HTTP client (SSRF-safe, size/time caps)
    collect.py                passive crawler -> crawl.json
    psi.py                    PageSpeed Insights summary -> psi.json
    benchmark.py              client vs competitor crawls -> benchmark.json (offline)
    render_report.py          report.json -> report.html + tz.md + tasks.csv
  assets/report-template.html
tests/test_security.py        offline security and regression tests
```

Run the tests from the repository root: `python -I -m unittest discover -s tests`.

## Security model

This skill reads content from websites you don't control, so it was designed defensively. See [SECURITY.md](SECURITY.md) for details. In short:

- **Prompt-injection aware:** all site content and AI answers are treated as data. The skill tells the agent never to follow instructions found in them and to report such text as a finding.
- **Passive only:** no form submissions, logins, path probing, scanning or payloads.
- **SSRF-safe networking:** only http/https on ports 80/443, all resolved IPs must be public (including IPv4 hidden inside IPv6, such as NAT64), the connection is pinned to the validated IP (DNS-rebinding safe), and every redirect hop is re-validated.
- **Polite:** respects robots.txt and Crawl-delay, 1 request/second, 25 pages by default.
- **Bounded:** response size caps, bounded decompression, XML entity/DOCTYPE rejection, linear-time parsing of untrusted text, timeouts.
- **No secrets in the repo:** the only optional key comes from the environment and is never logged or written.
- **Safe output:** the HTML report escapes all content, has a strict CSP (no scripts, no external requests) and `noindex`. CSV cells that a spreadsheet could run as formulas are neutralised.
- **Client data stays out of git:** `audits/` is in `.gitignore`.

## Limitations

- AI answers vary by user, location and time; live checks are a dated snapshot.
- No access to Google Search Console, analytics, backlink databases or server logs. Recommendations involving them are labelled as such.
- JavaScript-only content is detected heuristically by the crawler and confirmed in the browser when one is available.

## License

MIT. See [LICENSE](LICENSE).
