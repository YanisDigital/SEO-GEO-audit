# Classic SEO checklist

Use this as a map of what to look at in `crawl.json` / `psi.json` and in the browser.
Every finding in the report needs evidence (URL, field value, header, screenshot
observation). Skip checks that do not apply to the business type.

## Contents
1. Indexability and crawling
2. Site architecture and internal linking
3. On-page
4. Content quality and E-E-A-T
5. Structured data
6. Performance and Core Web Vitals
7. Mobile and rendering
8. International and local
9. Market-specific notes
10. Severity guide

---

## 1. Indexability and crawling

| Check | Where in crawl.json | Problem when |
|---|---|---|
| robots.txt reachable | `robots_txt.status` | not 200 (404 is acceptable but note it; 5xx is critical: Google may stop crawling) |
| Blanket block | `robots_txt.blocks_all_for_star` | true on a production site → critical |
| Important paths blocked | `robots_txt.sample_paths_blocked_for_googlebot`, `crawl_issues.blocked_by_robots` | key templates or CSS/JS blocked |
| Sitemap exists and declared | `sitemap.url_count`, `robots_txt.sitemaps_declared` | missing, not declared in robots, errors, off-site or http:// URLs, no `lastmod` |
| Status codes | `site_summary.status_codes`, `link_check` | 4xx/5xx on linked pages, chains > 1 hop |
| Host consolidation | `host_variants`, `host_variants_consolidated` | http/https/www/non-www resolve to different final URLs, or 302 instead of 301/308 |
| 404 handling | `not_found_handling` | `soft_404_suspected` (200 on garbage URL) or redirect of all 404s to home |
| noindex | `site_summary.pages_noindex`, `x_robots_tag` | noindex on pages that should rank |
| Canonical | `canonical`, `canonical_self`, `pages_without_canonical` | missing on key pages, pointing to another URL without reason, pointing to http or redirected URL |
| Duplicate URLs | query/trailing-slash variants in link lists | the same page reachable at several URLs without canonical |

## 2. Site architecture and internal linking
- Key commercial pages reachable from the homepage within 1-2 clicks (look at homepage `links.internal_unique` and nav headings).
- `links.empty_anchor_text` (icon-only links without accessible text) and `javascript_links` (not crawlable).
- Orphan suspicion: sitemap URLs never linked from crawled pages.
- Breadcrumbs (visible and `BreadcrumbList` schema) on deep sites.
- Pagination and faceted navigation: query-string pages competing with clean category URLs.

## 3. On-page
| Element | Guideline | Field |
|---|---|---|
| Title | unique, ~30-60 chars, primary topic first, brand at end | `title`, `title_length`, `duplicate_titles` |
| Meta description | unique, ~70-160 chars, states the offer/answer, has a reason to click | `meta_description*`, `duplicate_descriptions` |
| H1 | exactly one, matches search intent, not the logo | `h1_count`, `duplicate_h1` |
| Heading outline | logical H2/H3, no skipped levels used for styling | `headings`, `heading_levels_skipped` |
| Images | descriptive `alt` on meaningful images, width/height set, modern formats, lazy below the fold | `images.*` |
| html lang | present and matches content language | `lang` |
| Open Graph / Twitter | og:title, og:description, og:image on shareable pages | `open_graph`, `twitter_card` |
| URLs | readable, lowercase, hyphens, stable | page URLs |

Character counts are guidance, not law: Google rewrites titles and snippets.
Flag a length issue only when it truncates the key message or is clearly
uninformative.

## 4. Content quality and E-E-A-T
- Thin pages: `pages_thin_content_lt_300_words`. A thin contact page is fine; a thin service or category page is not.
- Does each key page answer the visitor's main questions (price range, process, timing, guarantees, delivery, location)?
- Experience and expertise: real photos, case studies, named authors with credentials, reviews, certifications.
- Trust: About page, physical address, phone, legal entity details, privacy policy, refund/delivery terms, HTTPS.
- Freshness: `published_time`, `modified_time`, `time_tags`, sitemap `lastmod`. Stale "2019" content on a blog is a weakness.
- Duplicate or boilerplate text across many pages (same `meta_description` everywhere is a hint).

## 5. Structured data
- Expect at least `Organization` (or `LocalBusiness` subtype) with `name`, `url`, `logo`, `sameAs`, contact info on the homepage.
- By page type: `Product` + `Offer` (+ `AggregateRating` only if reviews are real and visible), `Service`, `Article`/`BlogPosting` with `author` and dates, `BreadcrumbList`, `FAQPage` (Google shows FAQ rich results only for a narrow set of authoritative sites since 2023, but the markup still helps machines understand Q&A), `Event`, `Recipe`, `JobPosting`, `Course` as relevant.
- `json_ld.parse_errors` > 0 → broken JSON-LD (high).
- Markup must match visible content; fake ratings are a policy violation, never recommend them.
- Recommend validation in Google's Rich Results Test and validator.schema.org as an acceptance criterion.

## 6. Performance and Core Web Vitals
Thresholds (75th percentile of real users, the CrUX "field" data in `psi.json`):

| Metric | Good | Needs improvement | Poor |
|---|---|---|---|
| LCP | <= 2.5 s | <= 4.0 s | > 4.0 s |
| INP | <= 200 ms | <= 500 ms | > 500 ms |
| CLS | <= 0.1 | <= 0.25 | > 0.25 |

- Prefer field data (`field_page`, then `field_origin`) over lab data; say which one you used. Lab TBT is only a proxy for INP.
- If PSI failed, fall back to `ttfb_ms`, `html_bytes`, scripts/styles counts, image dimensions and formats, and say the CWV verdict is unverified.
- Typical fixes: compress and resize hero images (WebP/AVIF), preload the LCP image, `fetchpriority="high"`, defer non-critical JS, remove unused third-party scripts, set width/height on media, server/CDN caching, `content_encoding` (gzip/br) enabled.

## 7. Mobile and rendering
- `viewport` meta present with `width=device-width`.
- `likely_client_side_rendered`: content appears only after JavaScript. Confirm in the browser by comparing the raw HTML word count with the rendered page. If true, search engines may index late or partially and most AI crawlers (which usually do not execute JS) see an empty page → high/critical. Fix: SSR/SSG/prerendering.
- Tap targets, font sizes, intrusive interstitials (pop-ups covering content on mobile) — check visually.

## 8. International and local
- hreflang: reciprocal, includes self-reference and `x-default`, valid codes (`uk`, not `ua`), URLs return 200 and are canonical.
- Local business: NAP (name, address, phone) consistent on site and in schema; `tel:` links (`links.tel_links`); embedded map; city/area pages for real service areas only; reviews. Google Business Profile cannot be verified from the site — recommend checking it and list it as a limitation.

## 9. Market-specific notes
- Ukraine-targeted sites: Russian-owned services (Yandex.Metrica, Yandex maps/widgets, VK pixels, etc.) are blocked in Ukraine by sanctions; if found in `third_party_script_hosts`, flag as high (data leak + broken functionality for local users + reputational risk). Consumer-facing sites of Ukrainian businesses must have a Ukrainian version that loads by default (Law on the State Language, art. 27); check `lang`, hreflang and which version the root URL serves. Phrase this as a compliance note to verify with a lawyer, not legal advice.
- EU-targeted sites: analytics/ads scripts loading before consent is a GDPR/ePrivacy risk; note it as a trust issue (verify in the browser).

## 10. Severity guide
- **critical** — blocks indexing or visibility of the site or of a key section, or exposes users (sitewide noindex, robots `Disallow: /`, HTTPS broken, 5xx on key pages, content invisible without JS on key pages).
- **high** — materially reduces rankings, AI citations or conversions on key pages (missing/duplicate titles on money pages, no Organization schema, poor CWV field data, broken canonicals, AI search bots blocked unintentionally).
- **medium** — best-practice gaps with moderate impact (missing alt texts at scale, weak meta descriptions, missing breadcrumbs, no llms.txt for a docs-heavy site).
- **low** — polish (minor length issues, missing og:image on secondary pages).
