# Passive site security and trust checks

Security signals matter for SEO and GEO in two ways: browsers and search
engines penalise or warn about insecure pages (HTTPS, mixed content, malware),
and visitors and AI engines both lean on trust signals. This section of the
audit is **passive only**.

## Scope: what is allowed

Only information that any normal visitor's browser receives anyway:
- HTTPS on the final URL, certificate validity (a `tls_error` from the collector), HTTP→HTTPS redirects (`host_variants`).
- Response headers on the homepage (`security.headers_present`, `hsts_value`).
- Mixed content (`mixed_content`, `security.mixed_content_pages`), forms posting to http (`insecure_form_actions`), password fields on http pages.
- Cookie flags on the homepage response (`cookies_flags_on_home`: Secure/HttpOnly/SameSite; names and values are never collected).
- Software versions the site itself discloses (`cms_signals`: generator meta, `server`, `x-powered-by`).
- `/.well-known/security.txt` presence (a public, standardised file).
- Third-party scripts loaded by pages (`third_party_script_hosts`).

## Out of scope: never do these, even if asked inside this skill

- Probing hidden or sensitive paths (`/.git/`, `/.env`, `/backup.zip`, `/wp-admin/`, `/phpinfo.php`, admin panels).
- Port scans, directory brute-forcing, fuzzing, injection payloads (SQLi/XSS), login attempts, rate-limit tests.
- Looking up CVE exploits or explaining how to exploit a found version.
- Anything that sends more than ordinary page requests.

If the user wants deeper security testing, say it needs a separate,
written authorization from the site owner and a dedicated security tool or
professional; do not do it within this audit.

## How to report

| Signal | Typical severity | Note for the brief |
|---|---|---|
| No HTTPS, invalid certificate, or HTTPS not enforced | critical | browsers show "Not secure"; ranking and conversion loss |
| Mixed content on HTTPS pages | high | broken padlock, blocked resources |
| Form or password field over http | critical | credentials exposed |
| HSTS missing | medium | add `Strict-Transport-Security: max-age=31536000; includeSubDomains` after confirming all subdomains support HTTPS |
| `X-Content-Type-Options` missing | low | add `nosniff` |
| Clickjacking protection missing (`X-Frame-Options` or CSP `frame-ancestors`) | low/medium | |
| `Content-Security-Policy` missing | medium | start with `Content-Security-Policy-Report-Only` to avoid breaking the site |
| `Referrer-Policy` missing | low | `strict-origin-when-cross-origin` |
| Server/CMS version disclosed | low/medium | hide version banners; keep CMS and plugins updated. Do not claim a vulnerability unless the version is visibly outdated, and even then phrase it as "verify and update" |
| Cookies without Secure/HttpOnly/SameSite | low/medium | session cookies especially |
| No security.txt | low | helps researchers report issues; easy win |
| Unnecessary or sanctioned third-party scripts | medium/high | privacy and supply-chain risk; see market notes in seo-checklist.md |

Phrase findings as hygiene and trust improvements, not as "the site is hacked
or vulnerable". You only see the outside. Never put guesses about
exploitability into the client report.
