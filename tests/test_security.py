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

import collect  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
