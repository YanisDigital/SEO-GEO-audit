# Vertical profiles

The general checklists apply to every site. This file adds what matters most
for a given type of business: extra checks, the schema that fits, the queries
to use in live checks, and where severities shift. Pick one primary profile in
the Analyse step of SKILL.md; add a second only if the business really is both (a clinic
with an online shop). State the chosen profile in the report's assumptions.

## Contents
1. Local services (default for a business with an address)
2. Medical, dental, health (YMYL)
3. Legal and financial (YMYL)
4. E-commerce
5. SaaS and B2B
6. Restaurants, hotels, hospitality
7. Media, blogs, publishers

---

## 1. Local services
Plumbers, salons, studios, repair, schools, agencies with walk-in clients.
- **Decides visibility:** Google Maps card (categories, reviews, photos, hours), NAP consistency across listings, one page per service and per area served.
- **Check:** service pages exist for each main service; area pages have unique content (not a city name swapped into a template); click-to-call on mobile; hours and address in text, not only in an image or map embed.
- **Schema:** `LocalBusiness` subtype (`HomeAndConstructionBusiness`, `BeautySalon`…), `address`, `geo`, `openingHoursSpecification`, `areaServed`, `sameAs`; `Service` for main services.
- **Live-check queries:** "<service> <area>", "best <service> near <landmark>", "<service> price <city>", "emergency <service> <city>" when relevant.
- **Severity shifts:** missing or wrong Maps card → high; templated area pages → medium (risk of thin/doorway content).

## 2. Medical, dental, health (YMYL)
Clinics, dentists, orthodontists, therapists, pharmacies, wellness.
- **Decides visibility:** trust in the practitioner. Google's quality guidelines treat health as "Your Money or Your Life": expertise and accountability carry more weight than anywhere else, and answer engines prefer sources with named, credentialed authors.
- **Check:** each practitioner has a profile page (education, licence/board certification, memberships, years of practice, photo); medical content names its author or reviewer and a review date; insurance and payment options are stated; prices or price ranges for common treatments; before/after photos follow local rules (consent, no misleading claims); booking is easy on mobile; no guarantees of results.
- **Schema:** `Dentist` / `MedicalClinic` / `Physician` with `address`, `telephone`, `openingHoursSpecification`, `medicalSpecialty`; `Person` for practitioners with `hasCredential`, `alumniOf`, `memberOf`; `sameAs` to professional listings. `FAQPage` markup no longer produces Google rich results for most sites, but the visible Q&A still helps answer engines.
- **Listings:** see entity-directories.md (Healthgrades, Zocdoc, association locators, national equivalents such as Doc.ua and Helsi).
- **Live-check queries:** "best <specialty> in <area>", "<treatment> cost <city>", "<treatment> for adults/kids <city>", "<specialty> that accepts <insurance>", "how long does <treatment> take".
- **Severity shifts:** no practitioner credentials on the site → high; medical content without author/reviewer → medium; credentials stated off-site but not on-site → medium (see claims gap).

## 3. Legal and financial (YMYL)
Law firms, notaries, accountants, financial advisers, insurance brokers.
- **Decides visibility:** named, licensed professionals and clear jurisdiction. Engines cite directories (Avvo, Justia, national bar registers) heavily.
- **Check:** attorney/adviser profiles with bar or licence numbers and jurisdictions; practice-area pages per service; fee structure explained (hourly, fixed, contingency, free consultation); disclaimers present but not hiding the content; case results stated within the rules of the jurisdiction.
- **Schema:** `LegalService` / `Attorney` or `FinancialService` / `AccountingService`; `Person` with `hasCredential`; `areaServed`.
- **Live-check queries:** "<practice area> lawyer <city>", "how much does a <service> cost <country>", "do I need a lawyer for <situation>".
- **Severity shifts:** no named professionals or licence data → high.

## 4. E-commerce
- **Decides visibility:** product data quality. Shopping results and answer engines read structured product data and merchant feeds: price, availability, reviews, shipping and returns.
- **Check:** `Product` schema with `offers` (`price`, `priceCurrency`, `availability`), `aggregateRating` only for genuine on-page reviews, `brand`, `gtin`/`mpn` where they exist; category pages have unique intro text and are indexable; faceted navigation doesn't create indexable duplicates (canonical/noindex on filter combinations); out-of-stock handling (no soft 404s); shipping and returns policy pages, linked in `MerchantReturnPolicy`/`OfferShippingDetails` where possible; product images with alt text; site search results not indexable.
- **Schema:** `Product`, `Offer`, `BreadcrumbList`, `Organization` with `sameAs`, `MerchantReturnPolicy`.
- **Live-check queries:** "best <product type> for <use>", "<product> price", "where to buy <product> in <country>", "<brand> vs <competitor brand>", "<product> review".
- **Severity shifts:** missing or invalid `Product`/`Offer` data on product pages → high; indexable filter duplicates at scale → high; thin category pages → medium.
- **Benchmark tip:** crawl competitors' category and product pages, not only the homepage (pass a category URL to collect.py).

## 5. SaaS and B2B
- **Decides visibility:** being in the comparison set. Answer engines answer "best X for Y" and "X alternatives" from comparison pages, review platforms (G2, Capterra) and documentation.
- **Check:** clear one-line "what it is / for whom" on the homepage; pricing page with real numbers or tiers; comparison and alternatives pages ("<product> vs <competitor>"); use-case and industry pages; public, crawlable documentation (not only in an app or behind JavaScript); changelog; customer stories with names; llms.txt is more useful here than elsewhere (docs-heavy sites).
- **Schema:** `SoftwareApplication` (with `offers`, `applicationCategory`, `operatingSystem`), `Organization`, `FAQPage` where visible Q&A exists, `BreadcrumbList` for docs.
- **Listings:** G2, Capterra, Product Hunt, Crunchbase, LinkedIn, GitHub if open source.
- **Live-check queries:** "best <category> software for <audience>", "<product> alternatives", "<product> vs <competitor>", "<product> pricing", "how to <job the product does>".
- **Severity shifts:** no pricing information → medium-high; docs not crawlable → high for developer tools; absent from review platforms that the engines cite → medium.

## 6. Restaurants, hotels, hospitality
- **Decides visibility:** platforms (Google Maps, Tripadvisor, Booking, OpenTable) more than the site itself; menus and booking.
- **Check:** menu as HTML text (not only a PDF or image); prices; opening hours incl. holidays; booking link works on mobile; photos; dietary information; hotel: room types, amenities, policies as text.
- **Schema:** `Restaurant` (`servesCuisine`, `menu`, `acceptsReservations`, `priceRange`) or `Hotel`/`LodgingBusiness` (`amenityFeature`, `checkinTime`), `address`, `geo`.
- **Live-check queries:** "best <cuisine> restaurant in <area>", "<cuisine> near <landmark>", "hotel with <amenity> in <city>", "where to eat in <area>".
- **Severity shifts:** menu only as PDF/image → high; inconsistent hours across platforms → high.

## 7. Media, blogs, publishers
- **Decides visibility:** authorship, freshness and originality; answer engines cite pages with clear authors, dates and original data.
- **Check:** author pages with bios and expertise; publication and update dates visible and in markup; original reporting or data, not rewrites; topic hubs that link related articles; paywall markup if content is paywalled; Google News/Discover basics (large images, `max-image-preview:large`).
- **Schema:** `Article`/`NewsArticle` with `author` (`Person` with `url`), `datePublished`, `dateModified`, `publisher`; `BreadcrumbList`.
- **Live-check queries:** the site's core topics phrased as questions ("what is…", "how to…", "<topic> statistics <year>").
- **Severity shifts:** no author information → high; no dates → medium.
