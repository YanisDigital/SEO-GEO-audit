# Entity and listings protocol

Answer engines decide who a business is from many sources, not only its own
site: maps, directories, review platforms, registries and media. When those
sources disagree (an old address, a different phone, a missing credential),
engines trust the business less or repeat the wrong facts. This protocol finds
those gaps. It is passive: search, open public pages, read.

## Contents
1. Baseline: what the site says
2. Brand searches
3. Listings to check, by business type
4. What to record
5. Claims gap
6. Turning it into findings and tasks

---

## 1. Baseline: what the site says

`crawl.json` → `site_summary.entity` lists the name, phones and addresses the
site states (from JSON-LD, microdata and `tel:` links), plus the profile and
`sameAs` links it points to. Several different phones or addresses are fine
for a multi-location business, a problem otherwise. Write the canonical
version into `entity.site_nap` in report.json.

If `entity` is empty (no markup, no `tel:` links), take NAP from the contact
page text and note that the site gives machines nothing structured to read.
That is a finding of its own.

## 2. Brand searches

In Google (and Bing if available), without signing in, run 3-4 searches:
- `<brand>`
- `<brand> <city>`
- `<brand> reviews`
- `<brand> <street or phone>`: finds old or duplicate listings

Note which listings and profiles appear on the first page, the knowledge
panel or Maps card if shown, and any result that states a different address,
phone, name or status ("permanently closed", "moved"). Open up to 8 of the
most relevant listings. Prioritise the sources the answer engines cited in
the live checks (geo-aeo-checklist.md §6): those are the ones that shape AI
answers in this category.

## 3. Listings to check, by business type

Starting points, not a checklist to complete. Check what exists and what the
engines cite. Use only public pages; don't sign in or claim anything.

| Business type | Listings |
|---|---|
| Any local business | Google Maps card, Bing Places (bing.com/maps), Apple Maps (if viewable), Facebook page, Yelp, BBB (US), Nextdoor (US) |
| Medical / dental (US) | Healthgrades, Zocdoc, Vitals, WebMD Care, US News Doctors, professional association locators (for orthodontists: AAO "Find an Orthodontist"; device/brand provider locators such as Invisalign's) |
| Legal (US) | Avvo, Justia, FindLaw, Martindale-Hubbell, Super Lawyers, state bar directory |
| Home services | Angi, HomeAdvisor, Thumbtack, Houzz, BBB |
| Restaurants, hotels | Tripadvisor, Yelp, OpenTable, Booking.com, Expedia |
| B2B, SaaS, agencies | LinkedIn company page, G2, Capterra, Clutch, Crunchbase, Product Hunt, Wikipedia/Wikidata (only if notable) |
| E-commerce | Trustpilot, marketplace storefronts where the brand sells, Google Merchant reviews where shown |
| Ukraine | Google Maps; company registries (Opendatabot, YouControl) for the legal entity name and address; medical: Doc.ua, Helsi, Likarni.com; e-commerce: Prom.ua, Rozetka, Hotline.ua; services: OLX; IT employers: DOU, Work.ua |

For other countries, use the equivalent national directories and registries.

## 4. What to record

Per listing, into `entity.listings` in report.json:

```json
{"source": "Healthgrades", "url": "https://...", "name": "ok", "address": "mismatch",
 "phone": "ok", "rating": "4.8", "reviews": "37", "note": "lists the old Lakewood, CA address"}
```

`name` / `address` / `phone`: `ok`, `mismatch` or `missing` compared with
`site_nap`. Formatting differences (Ste vs Suite, phone punctuation) are `ok`.
Record rating and review count as shown; don't copy reviewer names or review
text with personal details.

## 5. Claims gap

While reading listings and media, note facts that strengthen trust but that
the site doesn't state: awards and rankings, board certifications,
memberships, provider tiers, years in business, notable clients, press
mentions. Also note claims on the site that no third party confirms. Record
them in `entity.claims_gap`:

```json
{"claim": "Castle Connolly Top Doctor 2025", "found_on": "US News", "url": "https://...", "on_site": false}
```

Facts confirmed by third parties are what answer engines repeat most readily.
A credential that exists only off-site is an easy win: put it on the site,
with a link to the source.

## 6. Turning it into findings and tasks

- Wrong address or phone on a listing that the engines cite, or a missing or
  outdated Maps card: **high**, `area_key: "local"`.
- Several listings with inconsistent NAP: **medium**, `local`.
- No structured NAP on the site (no LocalBusiness/Organization markup):
  covered by the schema findings, don't double-count.
- Third-party credentials missing from the site: **medium**, `onpage` (E-E-A-T).
- No `sameAs` linking the site to its main profiles: **low**, `schema`.

Tasks name the exact listing URL, the wrong value and the correct one, and who
can fix it (usually the owner, through the platform's own "claim" or "suggest
an edit" flow; the auditor never does this). Include the `sameAs` list in the
JSON-LD task.
