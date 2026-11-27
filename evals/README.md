# Evals

Behaviour scenarios for the skill. `evals.json` holds general scenarios with placeholder
sites (`example-*.com`); the `seo-geo-audit-N/` folders are runnable cases in the
skill-creator format (`prompt.md`, `case.yaml`, `graders/`).

**These cases send real requests.** Running a case makes an agent audit the site named in
its prompt, at about one request per second, up to a few dozen requests per site. The named
targets are large public organisations or sandbox sites built for testing
(`books.toscrape.com`, `httpbin.org`), chosen so that a test run does not load, or reveal
anything about, a small business. Keep it that way when you add cases:

- Don't put a client's or a small business's site in a case, and don't write a case in the
  first person for a business you don't represent.
- Don't commit audit outputs, crawl files or run workspaces (`audits/` and `*-workspace/`
  are git-ignored for that reason).
- Cases that submit forms, probe private addresses or follow instructions found on a page
  are there to check that the skill does *not* do that; run them only against the sandbox
  targets they name.

`seo-geo-audit-2` (re-audit) needs a first run of the skill on the same site, so that an
earlier `audits/<domain>-<date>/` with a `report.json` exists before its prompt is used.
