"""Hardened, read-only HTTP fetching for the seo-geo-audit skill (stdlib only).

Security properties (keep them when editing this file):
- Only http/https URLs; no credentials in URLs; only ports 80 and 443.
- Every hostname is resolved and ALL returned addresses must be globally
  routable (blocks localhost, private LANs, link-local, cloud metadata such as
  169.254.169.254, CGNAT, multicast, reserved ranges) -> SSRF protection.
- The TCP connection is pinned to the validated IP, so a second DNS answer
  cannot redirect the request to an internal address (DNS rebinding).
- Redirects are followed manually; every hop is re-validated; hop count capped.
- GET/HEAD only. No cookies are stored or sent, no auth, no form submission.
- Response bodies are size-capped and decompression is bounded (zip bombs).
- TLS certificates are verified; failures are reported, never bypassed.
- No proxy/environment variables are honoured (http.client ignores them).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import zlib
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

USER_AGENT = "Mozilla/5.0 (compatible; SEO-GEO-Audit/1.0; passive read-only audit)"
ROBOTS_TOKEN = "SEO-GEO-Audit"
ALLOWED_PORTS = {80, 443}
MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 3 * 1024 * 1024
MAX_HEADER_VALUE = 1000
REDIRECT_CODES = {301, 302, 303, 307, 308}


class UnsafeURLError(ValueError):
    """Raised when a URL must not be fetched."""


def _is_public_ip(raw: str) -> bool:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def normalize_input_url(raw: str) -> str:
    """Accept 'example.com' or a full URL; return an absolute http(s) URL."""
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeURLError("empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    return raw


def validate_url(url: str) -> tuple[str, str, int]:
    """Return (scheme, ascii_host, port) or raise UnsafeURLError."""
    if any(ord(c) < 32 or c == " " for c in url):
        raise UnsafeURLError("URL contains whitespace or control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeURLError(f"scheme not allowed: {scheme or '(none)'}")
    if parts.username or parts.password:
        raise UnsafeURLError("credentials in URL are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeURLError(f"invalid hostname: {exc}") from None
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise UnsafeURLError("invalid port") from None
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError(f"port {port} not allowed (only 80/443)")
    return scheme, host_ascii, port


def resolve_public(host: str, port: int) -> str:
    """Resolve host; every address must be public. Returns one IP to pin."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"DNS resolution failed for {host}: {exc}") from None
    addrs = []
    for info in infos:
        addr = info[4][0]
        if addr not in addrs:
            addrs.append(addr)
    if not addrs:
        raise UnsafeURLError(f"no addresses for {host}")
    for addr in addrs:
        if not _is_public_ip(addr):
            raise UnsafeURLError(f"{host} resolves to a non-public address; refusing")
    return addrs[0]


def _request_target(url: str) -> str:
    parts = urlsplit(url)
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%:@!$'()*+,;/?-._~")
    return path + ("?" + query if query else "")


def _bounded_decompress(body: bytes, encoding: str, max_bytes: int) -> tuple[bytes, str | None]:
    encoding = (encoding or "").lower().strip()
    if encoding in ("", "identity"):
        return body, None
    try:
        if encoding in ("gzip", "x-gzip"):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            d = zlib.decompressobj()
        else:
            return b"", f"unsupported content-encoding: {encoding}"
        out = d.decompress(body, max_bytes)
        note = "decompressed body truncated at size cap" if d.unconsumed_tail else None
        return out, note
    except zlib.error as exc:
        return b"", f"decompression failed: {exc}"


def _summarize_cookies(values: list[str]) -> list[dict]:
    """Record cookie security flags only; never store names or values."""
    out = []
    for v in values[:20]:
        low = v.lower()
        out.append({
            "secure": "; secure" in low or low.endswith("secure"),
            "httponly": "httponly" in low,
            "samesite": ("samesite=" in low),
        })
    return out


class SafeFetcher:
    """Polite, rate-limited, SSRF-safe fetcher."""

    def __init__(self, delay: float = 1.0, timeout: float = 15.0,
                 max_bytes: int = DEFAULT_MAX_BYTES, total_deadline: float = 45.0):
        self.delay = max(0.5, float(delay))
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.total_deadline = total_deadline
        self._last_request: dict[str, float] = {}
        self.ctx = ssl.create_default_context()
        self.request_count = 0

    def _wait_turn(self, host: str) -> None:
        last = self._last_request.get(host)
        if last is not None:
            gap = time.monotonic() - last
            if gap < self.delay:
                time.sleep(self.delay - gap)
        self._last_request[host] = time.monotonic()

    def _one(self, url: str, method: str, max_bytes: int) -> dict:
        scheme, host, port = validate_url(url)
        ip = resolve_public(host, port)
        self._wait_turn(host)
        self.request_count += 1
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self.ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

        def pinned(address, timeout=None, source_address=None, *a, **kw):
            return socket.create_connection((ip, port), timeout, source_address)

        conn._create_connection = pinned  # pin socket to the validated IP
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "*",
            "Connection": "close",
        }
        start = time.monotonic()
        try:
            conn.request(method, _request_target(url), headers=headers)
            resp = conn.getresponse()
            ttfb_ms = int((time.monotonic() - start) * 1000)
            raw_headers: dict[str, list[str]] = {}
            for k, v in resp.getheaders():
                raw_headers.setdefault(k.lower(), []).append(v)
            chunks, size, truncated = [], 0, False
            if method != "HEAD":
                while True:
                    if time.monotonic() - start > self.total_deadline:
                        truncated = True
                        break
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > max_bytes:
                        truncated = True
                        break
            body = b"".join(chunks)[:max_bytes]
            total_ms = int((time.monotonic() - start) * 1000)
            return {
                "status": resp.status,
                "raw_headers": raw_headers,
                "body": body,
                "transfer_bytes": len(body),
                "truncated": truncated,
                "ttfb_ms": ttfb_ms,
                "total_ms": total_ms,
                "ip_version": 6 if ":" in ip else 4,
            }
        finally:
            conn.close()

    def fetch(self, url: str, method: str = "GET", max_bytes: int | None = None,
              follow_redirects: bool = True) -> dict:
        """Fetch a URL. Never raises for network problems; returns {'error': ...}."""
        max_bytes = max_bytes or self.max_bytes
        chain = []
        current = url
        result: dict = {"requested_url": url}
        for _ in range(MAX_REDIRECTS + 1):
            try:
                r = self._one(current, method, max_bytes)
            except UnsafeURLError as exc:
                result.update(error=f"blocked: {exc}", final_url=current, redirect_chain=chain)
                return result
            except ssl.SSLCertVerificationError as exc:
                msg = str(getattr(exc, "verify_message", "") or exc)
                code = ("tls_local_issuer_missing" if "local issuer" in msg
                        else "tls_cert_invalid")
                result.update(error=f"{code}: {msg[:200]}", final_url=current, redirect_chain=chain)
                return result
            except ssl.SSLError as exc:
                result.update(error=f"tls_error: {exc.__class__.__name__}: {exc.reason or exc}",
                              final_url=current, redirect_chain=chain)
                return result
            except (OSError, http.client.HTTPException) as exc:
                result.update(error=f"network_error: {exc.__class__.__name__}: {str(exc)[:200]}",
                              final_url=current, redirect_chain=chain)
                return result
            loc = (r["raw_headers"].get("location") or [None])[0]
            if follow_redirects and r["status"] in REDIRECT_CODES and loc:
                nxt = urljoin(current, loc.strip())
                chain.append({"url": current, "status": r["status"], "location": nxt[:2000]})
                current = nxt
                continue
            break
        else:
            result.update(error="too_many_redirects", final_url=current, redirect_chain=chain)
            return result

        enc = (r["raw_headers"].get("content-encoding") or [""])[0]
        body, note = _bounded_decompress(r["body"], enc, max_bytes)
        headers = {k: " | ".join(v)[:MAX_HEADER_VALUE] for k, v in r["raw_headers"].items()
                   if k != "set-cookie"}
        result.update(
            final_url=current,
            status=r["status"],
            headers=headers,
            cookies=_summarize_cookies(r["raw_headers"].get("set-cookie", [])),
            body=body,
            transfer_bytes=r["transfer_bytes"],
            body_bytes=len(body),
            truncated=r["truncated"],
            ttfb_ms=r["ttfb_ms"],
            total_ms=r["total_ms"],
            redirect_chain=chain,
        )
        if note:
            result["note"] = note
        return result


def decode_body(body: bytes, content_type: str | None) -> str:
    charset = None
    if content_type and "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip(" \"'")
    if not charset:
        head = body[:2048].lower()
        idx = head.find(b"charset=")
        if idx != -1:
            cand = head[idx + 8: idx + 40].strip(b" \"'").split(b"\"")[0].split(b"'")[0]
            cand = cand.split(b";")[0].split(b">")[0].split(b"/")[0].strip()
            charset = cand.decode("ascii", "ignore") or None
    for cs in (charset, "utf-8"):
        if not cs:
            continue
        try:
            return body.decode(cs, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


def strip_url(url: str) -> str:
    """Drop fragment and default port; lowercase scheme/host."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    netloc = host
    if p.port and p.port not in (80, 443):
        netloc = f"{host}:{p.port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
