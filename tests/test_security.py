"""Security regression tests for the seo-geo-audit scripts (stdlib only, offline).

Run from the repository root:
    python -I -m unittest discover -s tests -v
"""

import os
import re
import sys
import time
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seo-geo-audit", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import benchmark  # noqa: E402
import collect  # noqa: E402
import compare  # noqa: E402
import gaps  # noqa: E402
import netsafe  # noqa: E402
import psi  # noqa: E402
import render_report  # noqa: E402

FAST = 5.0  # seconds; the vulnerable versions took minutes on these inputs


def timed(fn, *args):
    start = time.monotonic()
    result = fn(*args)
    return result, time.monotonic() - start


def raw_html_outside_code(md: str) -> bool:
    """Minimal CommonMark inline scan: is there a raw '<' outside code spans?"""
    i, n = 0, len(md)
    while i < n:
        c = md[i]
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "`":
            j = i
            while j < n and md[j] == "`":
                j += 1
            run, k, close = j - i, j, None
            while k < n:
                if md[k] == "`":
                    m = k
                    while m < n and md[m] == "`":
                        m += 1
                    if m - k == run:
                        close = m
                        break
                    k = m
                else:
                    k += 1
            i = close if close is not None else j
            continue
        if c == "<":
            return True
        i += 1
    return False


class SSRFTests(unittest.TestCase):
    def test_ipv4_embedded_in_ipv6_is_checked(self):
        blocked = [
            "64:ff9b::7f00:1",        # NAT64 -> 127.0.0.1
            "64:ff9b::a9fe:a9fe",     # NAT64 -> 169.254.169.254 (cloud metadata)
            "64:ff9b::a00:1",         # NAT64 -> 10.0.0.1
            "::127.0.0.1",            # IPv4-compatible
            "::ffff:127.0.0.1",       # IPv4-mapped
            "2002:7f00:1::",          # 6to4 -> 127.0.0.1
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
            "64:ff9b:1::1",           # local-use NAT64
        ]
        for addr in blocked:
            with self.subTest(addr=addr):
                self.assertFalse(netsafe._is_public_ip(addr))

    def test_private_and_special_addresses_blocked(self):
        for addr in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.169.254",
                     "100.64.0.1", "0.0.0.0", "::1", "fe80::1%eth0", "fd00::1", "224.0.0.1"):
            with self.subTest(addr=addr):
                self.assertFalse(netsafe._is_public_ip(addr))

    def test_public_addresses_allowed(self):
        for addr in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "64:ff9b::808:808"):
            with self.subTest(addr=addr):
                self.assertTrue(netsafe._is_public_ip(addr))

    def test_url_validation(self):
        for url in ("file:///etc/passwd", "http://user:pw@example.com/", "http://example.com:8080/",
                    "gopher://example.com/", "http://exa mple.com/"):
            with self.subTest(url=url):
                with self.assertRaises(netsafe.UnsafeURLError):
                    netsafe.validate_url(url)


class RobotsTests(unittest.TestCase):
    def test_no_quadratic_blowup_on_blank_lines(self):
        text = "\n" * 500_000 + "User-agent: *\nDisallow:\n"
        _, elapsed = timed(collect.parse_robots, text, "https://example.com", ["/"])
        self.assertLess(elapsed, FAST)

    def test_explicit_group_detection(self):
        text = ("# User-agent: ClaudeBot\n"
                "User-agent: GPTBot # training\n"
                "Disallow: /\n\n"
                "user-agent:perplexitybot\n"
                "Allow: /\n")
        robots, _ = collect.parse_robots(text, "https://example.com", ["/"])
        bots = robots["ai_bots"]
        self.assertTrue(bots["GPTBot"]["explicit_group"])
        self.assertTrue(bots["PerplexityBot"]["explicit_group"])
        self.assertFalse(bots["ClaudeBot"]["explicit_group"])
        self.assertFalse(bots["GPTBot"]["homepage_allowed"])


class SitemapXMLTests(unittest.TestCase):
    URLSET = (b'<?xml version="1.0" encoding="UTF-8"?>'
              b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
              b'<url><loc> https://example.com/a </loc><lastmod>2026-01-01</lastmod></url>'
              b'<url><loc>https://example.com/b</loc></url></urlset>')

    def test_parses_urlset(self):
        tag, entries = collect.parse_sitemap_xml(self.URLSET)
        self.assertEqual(tag, "urlset")
        self.assertEqual(entries, [("https://example.com/a", "2026-01-01"), ("https://example.com/b", None)])

    def test_parses_index_and_respects_limit(self):
        xml = (b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
               + b"".join(b"<sitemap><loc>https://example.com/s%d.xml</loc></sitemap>" % i for i in range(10))
               + b"</sitemapindex>")
        tag, entries = collect.parse_sitemap_xml(xml, limit=3)
        self.assertEqual(tag, "sitemapindex")
        self.assertEqual(len(entries), 3)

    def test_rejects_entity_expansion(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
                b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
                b"<urlset><url><loc>&lol2;</loc></url></urlset>")
        with self.assertRaises(collect.XMLRejected):
            collect.parse_sitemap_xml(bomb)

    def test_rejects_doctype_hidden_after_long_comment(self):
        xml = (b"<?xml version=\"1.0\"?><!--" + b"x" * 20_000 + b"-->"
               b'<!DOCTYPE urlset [<!ENTITY ext SYSTEM "file:///etc/passwd">]>'
               b"<urlset><url><loc>&ext;</loc></url></urlset>")
        with self.assertRaises(collect.XMLRejected):
            collect.parse_sitemap_xml(xml)

    def test_malformed_xml_is_a_value_error(self):
        with self.assertRaises(ValueError):
            collect.parse_sitemap_xml(b"<urlset><url><loc>x</url>")


class HTMLParsingTests(unittest.TestCase):
    @staticmethod
    def page(body: bytes) -> dict:
        return {"body": body, "headers": {"content-type": "text/html; charset=utf-8"},
                "final_url": "https://example.com/", "status": 200}

    def test_unterminated_markup_does_not_hang(self):
        (page, _), elapsed = timed(collect.analyze_page, "https://example.com/",
                                   self.page(b"<p>hi</p>" + b"<a" * 200_000), "example.com")
        self.assertLess(elapsed, FAST)
        self.assertIn("unterminated markup", page["parse_error"])

    def test_normal_page_still_parsed(self):
        html = b"<html><head><title>T</title></head><body><h1>Hello</h1><p>Hello world</p></body></html>"
        page, _ = collect.analyze_page("https://example.com/", self.page(html), "example.com")
        self.assertIsNone(page["parse_error"])
        self.assertEqual(page["title"], "T")
        self.assertEqual(page["h1_count"], 1)
        self.assertEqual(page["word_count"], 3)


    def test_svg_title_is_not_the_page_title(self):
        html = (b"<html><head><title>Real Title</title></head><body>"
                b"<svg><title>logo</title><path d='M0'/></svg><svg/>"
                b"<p>Text</p><title>stray</title></body></html>")
        page, _ = collect.analyze_page("https://example.com/", self.page(html), "example.com")
        self.assertEqual(page["title"], "Real Title")


class HeadFallbackTests(unittest.TestCase):
    def test_failed_head_is_rechecked(self):
        self.assertTrue(collect.head_unreliable({"status": 404}))
        self.assertTrue(collect.head_unreliable({"status": 405}))
        self.assertTrue(collect.head_unreliable({"error": "network_error: timeout"}))

    def test_good_or_blocked_head_is_final(self):
        self.assertFalse(collect.head_unreliable({"status": 200}))
        self.assertFalse(collect.head_unreliable({"status": 301}))
        self.assertFalse(collect.head_unreliable({"error": "blocked: DNS resolution failed"}))


class MarkdownTests(unittest.TestCase):
    md = staticmethod(render_report.md_text)

    def test_backtick_flood_is_fast(self):
        for text in ("`" * 5000, "`a" * 50_000, ("``" + "x" * 10) * 10_000):
            with self.subTest(size=len(text)):
                _, elapsed = timed(self.md, text)
                self.assertLess(elapsed, FAST)

    def test_raw_html_is_escaped(self):
        out = self.md('<img src=x onerror=alert(1)> and <script>alert(1)</script>')
        self.assertFalse(raw_html_outside_code(out))
        self.assertNotIn("<", out)

    def test_links_and_images_are_neutralised(self):
        for text in ("![t](https://tracker.example/p.png)", "[click](javascript:alert(1))",
                     "[ref]: https://evil.example/"):
            with self.subTest(text=text):
                out = self.md(text)
                self.assertIsNone(re.search(r"(?<!\\)[\[\]]", out), out)

    def test_code_spans_are_kept(self):
        out = self.md('Add `<link rel="canonical" href="https://example.com/">` to the head')
        self.assertIn('`<link rel="canonical" href="https://example.com/">`', out)
        self.assertFalse(raw_html_outside_code(out))

    def test_joined_values_cannot_pair_backticks_across_each_other(self):
        line = f"### {self.md('`a')} [P1] {self.md('`<img src=x onerror=alert(1)>`')}"
        self.assertFalse(raw_html_outside_code(line))

    def test_backslash_cannot_unbalance_a_code_span(self):
        line = self.md("x\\") + self.md("`<img src=x onerror=alert(1)>`")
        self.assertFalse(raw_html_outside_code(line))

    def test_line_breaks_are_flattened(self):
        out = self.md("`\n<script>alert(1)</script>\n`\r\n<b>x</b>")
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)

    def test_code_fence_cannot_be_closed_by_content(self):
        code = "```\n<script>alert(1)</script>\n````"
        fenced = render_report.fence(code)
        opening = fenced.split("\n", 1)[0]
        self.assertGreater(len(opening), 4)
        self.assertTrue(fenced.endswith("\n" + opening))


class PSITests(unittest.TestCase):
    def test_key_is_sent_in_header_not_url(self):
        req = psi.build_request("https://example.com/", "mobile", "test-key-123")
        self.assertNotIn("test-key-123", req.full_url)
        self.assertEqual(req.get_header("X-goog-api-key"), "test-key-123")
        self.assertTrue(req.full_url.startswith("https://www.googleapis.com/"))

    def test_no_key_no_header(self):
        req = psi.build_request("https://example.com/", "mobile", None)
        self.assertIsNone(req.get_header("X-goog-api-key"))

    def test_redirects_are_not_followed(self):
        handler = psi._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/"))

    def test_redact(self):
        self.assertEqual(psi.redact("err key=abc", "abc"), "err key=[REDACTED]")


class CSVTests(unittest.TestCase):
    def test_formula_cells_are_neutralised(self):
        for bad in ("=HYPERLINK(\"http://evil.example\",\"x\")", "+1+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)",
                    "\t=1", " =1", "＝1"):
            with self.subTest(bad=bad):
                self.assertTrue(render_report.csv_cell(bad).startswith("'"))
        self.assertEqual(render_report.csv_cell("Add JSON-LD"), "Add JSON-LD")

    def test_tasks_csv(self):
        d = {"tasks": [{"id": "T2", "wave": "30d", "priority": "P2", "title": "=cmd()", "steps": ["a", "b"]},
                       {"id": "T1", "wave": "now", "priority": "P1", "title": "Fix", "acceptance": ["ok"]}]}
        import csv
        import io
        rows = list(csv.reader(io.StringIO(render_report.render_csv(d, render_report.DEFAULT_LABELS))))
        self.assertEqual([r[0] for r in rows[1:]], ["T1", "T2"])  # sorted by wave
        self.assertEqual(rows[2][4], "'=cmd()")
        self.assertEqual(rows[2][6], "1. a\n2. b")


class ScoringTests(unittest.TestCase):
    REPORT = {
        "scores": [{"key": "technical", "area": "Technical SEO", "score": 50},
                   {"key": "onpage", "area": "On-page"},
                   {"key": "visibility", "area": "AI visibility"}],
        "weaknesses": [{"title": "a", "severity": "critical", "area": "Technical SEO"},
                       {"title": "b", "severity": "low", "area_key": "technical"},
                       {"title": "c", "severity": "bogus", "area": "On-page"},
                       {"title": "d", "severity": "high", "area_key": "visibility"}],
        "geo_visibility": {"checks": [
            {"query_type": "brand", "mentioned": True},
            {"query_type": "non_brand", "mentioned": False},
            {"query_type": "non_brand", "mentioned": True},
            {"query_type": "non-brand", "mentioned": "no", "cited_url": "https://example.com/"},
            {"query_type": "non_brand", "mentioned": "n/a"}]},
    }

    def test_area_scores_come_from_deductions(self):
        scores, readiness, warnings = render_report.compute_scores(self.REPORT)
        by_key = {x["key"]: x["score"] for x in scores}
        self.assertEqual(by_key["technical"], 73)   # 100 - 25 - 2
        self.assertEqual(by_key["onpage"], 94)      # unknown severity counts as medium
        self.assertEqual(readiness, 81)             # (73*1.5 + 94) / 2.5 = 81.4
        self.assertTrue(any("stated score 50" in w for w in warnings))

    def test_visibility_uses_only_non_brand_checks(self):
        vis = render_report.compute_visibility(self.REPORT)
        self.assertEqual((vis["hits"], vis["total"]), (2, 3))
        self.assertEqual(vis["score"], 53)          # (0 + 0.6 + 1) / 3

    def test_too_few_checks_is_not_measured(self):
        vis = render_report.compute_visibility({"geo_visibility": {"checks": [
            {"query_type": "non_brand", "mentioned": False}]}})
        self.assertIsNone(vis["score"])

    def test_html_escapes_deduction_titles(self):
        d = dict(self.REPORT, weaknesses=[{"title": "<script>x</script>", "severity": "high",
                                           "area_key": "technical"}])
        body, _ = render_report.render_html(d, render_report.DEFAULT_LABELS)
        self.assertNotIn("<script>", body)


class SanityFlagTests(unittest.TestCase):
    @staticmethod
    def pages(n, **kw):
        base = {"title": "Home", "status": 200, "word_count": 500, "parse_error": None}
        return [dict(base, url=f"https://example.com/{i}", **kw) for i in range(n)]

    def codes(self, *args):
        return {f["code"] for f in collect.sanity_flags(*args)}

    def test_healthy_crawl_has_no_flags(self):
        pages = [dict(p, title=f"Page {i}") for i, p in enumerate(self.pages(10))]
        links = [{"status": 200}] * 10
        self.assertEqual(self.codes(pages, links, [], 50, 25), set())

    def test_collection_problems_are_flagged(self):
        pages = self.pages(6, title="Just a moment...", word_count=10, status=403)
        links = [{"status": 404}] * 6
        failed = [{"url": "x", "error": "network_error"}] * 4
        self.assertEqual(self.codes(pages, links, failed, 100, 25),
                         {"bot_protection_suspected", "identical_titles", "mostly_empty_pages",
                          "most_links_broken", "many_fetch_failures"})

    def test_few_pages_reached(self):
        self.assertIn("few_pages_reached", self.codes(self.pages(2), [], [], 300, 25))


class EntityTests(unittest.TestCase):
    HTML = (b"<html><head><title>Clinic</title>"
            b"<meta property='og:site_name' content='Clinic LA'>"
            b"<script type='application/ld+json'>{\"@type\":\"Dentist\",\"name\":\"Clinic LA\","
            b"\"telephone\":\"+1 310-208-8273\",\"address\":{\"streetAddress\":\"1 Main St\","
            b"\"addressLocality\":\"Los Angeles\"},\"sameAs\":[\"https://www.instagram.com/clinic\"]}</script>"
            b"</head><body><div itemscope itemtype='https://schema.org/LocalBusiness'>"
            b"<span itemprop='streetAddress'>1 Main St<br>Ste 3</span>"
            b"<span itemprop='addressLocality'>Los Angeles</span>"
            b"<a href='tel:(310) 208-8273'>call</a></div>"
            b"<a href='https://www.facebook.com/clinic'>fb</a><a href='https://www.google.com/search?q=x'>g</a>"
            b"<a href='https://maps.app.goo.gl/abc'>map</a></body></html>")

    def test_nap_is_extracted_and_merged(self):
        page, _ = collect.analyze_page("https://example.com/", HTMLParsingTests.page(self.HTML), "example.com")
        ent = page["entity"]
        self.assertIn({"prop": "streetAddress", "value": "1 Main St Ste 3"}, ent["microdata_nap"])
        self.assertEqual(ent["profile_links"], ["https://maps.app.goo.gl/abc", "https://www.facebook.com/clinic"])
        summary = collect.summarize_entity([page])
        self.assertEqual(summary["names"][0]["value"], "Clinic LA")
        self.assertEqual(len(summary["phones"]), 1)          # same number in two formats
        self.assertEqual(summary["phones"][0]["pages"], 2)
        sources = {a["source"] for a in summary["addresses"]}
        self.assertEqual(sources, {"json-ld", "microdata"})

    def test_unclosed_itemprop_is_bounded(self):
        html = b"<html><body><span itemprop='telephone'>" + b"<b>x</b>" * 5000
        (page, _), elapsed = timed(collect.analyze_page, "https://example.com/",
                                   HTMLParsingTests.page(html), "example.com")
        self.assertLess(elapsed, FAST)


class BenchmarkTests(unittest.TestCase):
    @staticmethod
    def crawl(n_pages, **page_kw):
        base = {"title": "T", "word_count": 100, "question_headings": 0, "headings": [], "canonical": [],
                "ttfb_ms": 100, "html_bytes": 2048, "url": "https://a.example/",
                "structured_data": {"json_ld": {"types": [], "nodes": []}, "microdata_types": []}}
        pages = [dict(base, url=f"https://a.example/{i}", **page_kw) for i in range(n_pages)]
        return {"pages": pages, "final_origin": "https://www.a.example",
                "llms_txt": {"/llms.txt": {"status": 200, "looks_like_html": True}}}

    def test_soft_404_llms_txt_is_absent(self):
        self.assertFalse(benchmark.metrics(self.crawl(2), 2)["llms_txt"])

    def test_totals_use_the_sample_presence_uses_all(self):
        crawl = self.crawl(10, question_headings=1)
        crawl["pages"][9]["headings"] = [{"level": 1, "text": "Braces prices"}]
        m = benchmark.metrics(crawl, 3)
        self.assertEqual(m["question_headings"], 3)
        self.assertEqual(m["pages_analyzed"], 10)
        self.assertEqual(m["price_pages"], ["https://a.example/9"])

    def test_cost_question_is_not_a_price_page(self):
        crawl = self.crawl(1)
        crawl["pages"][0]["headings"] = [{"level": 2, "text": "How much does it cost?"}]
        self.assertEqual(benchmark.metrics(crawl, 1)["price_pages"], [])


class EntityRenderTests(unittest.TestCase):
    def test_entity_and_benchmark_are_escaped(self):
        evil = "<img src=x onerror=alert(1)>"
        d = {"entity": {"site_nap": {"name": evil}, "listings": [{"source": evil, "url": "javascript:alert(1)",
                                                                  "address": "mismatch", "note": evil}],
                        "claims_gap": [{"claim": evil, "found_on": evil, "on_site": False}]},
             "benchmark": {"pages_per_site": 3, "sites": [
                 {"role": "client", "host": evil, "url": "https://a.example/",
                  "metrics": {"schema_types": [evil], "price_pages": ["javascript:alert(1)"]}},
                 {"role": "competitor", "host": "b.example", "url": "https://b.example/", "metrics": {}}]},
             "benchmark_extra": {"b.example": {"maps_reviews": evil}}}
        body, _ = render_report.render_html(d, render_report.DEFAULT_LABELS)
        self.assertNotIn("<img", body)
        self.assertNotIn('href="javascript', body)


class CompareTests(unittest.TestCase):
    PREV = {"site": {"audit_date": "2026-01-01"},
            "scores": [{"key": "technical", "area": "Technical SEO"}],
            "weaknesses": [{"key": "no-canonical", "title": "No canonical tags", "severity": "medium",
                            "area_key": "technical"},
                           {"title": "Sitemap missing from robots.txt", "severity": "low", "area_key": "technical"},
                           {"title": "Old address on listings", "severity": "high", "area_key": "local"}],
            "geo_visibility": {"checks": [{"engine": "Perplexity", "query": "best x", "mentioned": False}]}}
    CUR = {"site": {"audit_date": "2026-02-01"},
           "scores": [{"key": "technical", "area": "Технічне SEO"}],
           "weaknesses": [{"key": "no-canonical", "title": "Canonical відсутній", "severity": "low",
                           "area_key": "technical"},
                          {"title": "Sitemap missing in robots.txt file", "severity": "low", "area_key": "technical"},
                          {"title": "No HSTS header", "severity": "medium", "area_key": "trust"}],
           "geo_visibility": {"checks": [{"engine": "perplexity", "query": "Best X ", "mentioned": True,
                                          "cited_url": "https://example.com/"}]}}

    def test_issues_are_tracked_by_key_then_title(self):
        w = compare.weakness_changes(self.PREV, self.CUR)
        self.assertEqual([x["title"] for x in w["fixed"]], ["Old address on listings"])
        self.assertEqual([x["title"] for x in w["new"]], ["No HSTS header"])
        self.assertEqual(len(w["still_open"]), 2)
        self.assertEqual(w["still_open"][0]["severity_before"], "medium")

    def test_areas_match_by_key_across_languages(self):
        areas = compare.area_changes(self.PREV, self.CUR)
        self.assertEqual(areas, [{"key": "technical", "area": "Технічне SEO", "before": 92, "after": 96}])

    def test_checks_match_case_insensitively(self):
        checks = compare.check_changes(self.PREV, self.CUR)
        self.assertEqual((checks[0]["before"], checks[0]["after"]), ("no", "cited"))

    def test_changes_section_is_escaped(self):
        evil = "<script>alert(1)</script>"
        ch = {"previous": {"audit_date": evil, "readiness": 50}, "current": {"readiness": 60},
              "areas": [{"area": evil, "before": 1, "after": 2}],
              "weaknesses": {"fixed": [{"title": evil}], "new": [], "still_open": []},
              "checks": [{"engine": evil, "query": evil, "before": evil, "after": "cited"}],
              "site_metrics": [{"metric": evil, "before": evil, "after": 1}]}
        html_out = render_report.render_changes(ch, render_report.DEFAULT_LABELS)
        self.assertNotIn("<script", html_out)


class GapsTests(unittest.TestCase):
    def write(self, name, text):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_keyword_files(self):
        rows = gaps.read_keywords(self.write("k.csv", "Ключова фраза;Популярність;Кластер\n"
                                                      "брекети ціна київ;70;Ціни\nбрекети ціна київ;70;Ціни\n"
                                                      "елайнери;inf;\n"))
        self.assertEqual(rows, [{"query": "брекети ціна київ", "popularity": 70, "cluster": "Ціни"},
                                {"query": "елайнери"}])
        self.assertEqual(gaps.read_keywords(self.write("k.txt", "a b\n\nc d\n")), [{"query": "a b"}, {"query": "c d"}])
        with self.assertRaises(ValueError):
            gaps.read_keywords(self.write("k.csv", "foo,bar\nx,y\n"))

    def test_matching_uses_pages_and_uncrawled_urls(self):
        crawl = {"pages": [{"title": "Braces for adults", "url": "https://a.example/adults",
                            "headings": [{"level": 1, "text": "Adult braces"}], "text_excerpt": "Invisalign too"}],
                 "uncrawled_urls": ["https://a.example/orthodontist-beverly-hills"]}
        pages = gaps.page_index(crawl)
        self.assertEqual(gaps.match(gaps.stems("braces for adults"), pages)["status"], "covered")
        bh = gaps.match(gaps.stems("orthodontist beverly hills"), pages)
        self.assertEqual((bh["status"], bh.get("url_only")), ("covered", True))
        self.assertEqual(gaps.match(gaps.stems("invisalign cost"), pages)["status"], "weak")
        self.assertEqual(gaps.match(gaps.stems("jaw surgery"), pages)["status"], "missing")

    def test_competitor_topics_skip_one_site_boilerplate(self):
        def site(host, heads):
            return {"final_origin": f"https://{host}", "pages": [
                {"title": "x", "url": f"https://{host}/{i}", "headings": [{"level": 2, "text": h}]}
                for i, h in enumerate(heads)]}
        client = site("c.example", ["Lingual braces guide", "Orthodontic treatment for kids"])
        comp = site("b.example", ["Quick links menu", "Quick links menu", "Lingual braces candidates",
                                  "Classic vintage car show"])
        vocab = gaps.niche_vocab([client, comp])
        topics = [t["topic"] for t in gaps.competitor_topics([comp], set(), vocab, set())]
        self.assertEqual(topics, ["Lingual braces candidates"])

    def test_gaps_section_is_escaped(self):
        evil = "<img src=x onerror=alert(1)>"
        g = {"queries_total": 1, "counts": {"missing": 1},
             "clusters": [{"cluster": evil, "queries": 1, "missing": 1}],
             "missing": [{"query": evil, "cluster": evil, "popularity": evil, "page": "javascript:alert(1)"}],
             "competitor_topics_missing": [{"topic": evil, "source": evil, "url": "javascript:x"}]}
        html_out = render_report.render_gaps(g, evil, render_report.DEFAULT_LABELS)
        self.assertNotIn("<img", html_out)
        self.assertNotIn('href="javascript', html_out)


if __name__ == "__main__":
    unittest.main()
