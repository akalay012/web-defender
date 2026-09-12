"""Canonical URL/domain/network helpers.

This is the single ownership point for URL normalization, public-IP guards and
registrable-domain comparison. Compatibility wrappers remain semantic, not
version-numbered.
"""
import re, socket, ipaddress
from urllib.parse import urlparse, unquote_plus, unquote

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _TLD_EXTRACT = None

MAX_CONTENT_SIZE = 5 * 1024 * 1024
COMMON_MULTI_SUFFIXES = {"com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp"}

def normalize_url(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("URL boş.")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Geçersiz HTTP/HTTPS URL.")
    if len(url) > 4096:
        raise ValueError("URL çok uzun.")
    return url

def host_is_private(host):
    if not host:
        return True
    h = host.lower().rstrip(".")
    if h in {"localhost", "localhost.localdomain", "metadata",
             "metadata.google.internal", "169.254.169.254"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def host_is_raw_ip(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def _legacy_root_domain_fallback(hostname):
    """Fallback parser used only when PSL extraction is unavailable."""
    if not hostname:
        return ""
    host = hostname.lower().rstrip(".")
    if host_is_raw_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    suffix2 = ".".join(parts[-2:])
    if suffix2 in COMMON_MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def resolve_public_ips(host):
    """Hostun yalnızca public IP'lere çözümlendiğini doğrular."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    if not ips:
        raise ValueError("DNS çözümlemesi IP döndürmedi.")
    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise ValueError(f"Private/özel IP hedefi engellendi: {raw}")
    return ips

def read_limited_response(response, limit=MAX_CONTENT_SIZE):
    """Response gövdesini belleğe sınırsız almadan limitli okur."""
    chunks, total = [], 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        remaining = limit - total
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if total >= limit:
            break
    return b"".join(chunks)

def same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    pa_port = pa.port or (443 if pa.scheme == "https" else 80)
    pb_port = pb.port or (443 if pb.scheme == "https" else 80)
    return pa.scheme == pb.scheme and pa.hostname == pb.hostname and pa_port == pb_port

def severity_weight(sev):
    return {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}.get(sev, 0)

def full_decode(s):
    """Çok katmanlı URL encoding'i tamamen çöz."""
    seen = set()
    while s not in seen:
        seen.add(s)
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    return s

def get_canonical_root(host):
    """Single authoritative registrable-domain resolver.
    Uses tldextract when available; falls back to manual suffix list.
    Always use this for identity, cross-root exfil and destination ownership checks.
    """
    host = (host or "").strip(".").lower()
    if not host or host_is_raw_ip(host): return host
    if _TLD_EXTRACT:
        try:
            x = _TLD_EXTRACT(host)
            result = ".".join(p for p in (x.domain, x.suffix) if p)
            if result: return result
        except Exception:
            pass
    return _legacy_root_domain_fallback(host)

def get_root_domain(host):
    """Compatibility wrapper: all legacy callers use the canonical PSL authority."""
    return get_canonical_root(host)

def registrable_domain_v21(host):
    """Compatibility wrapper for V21 callers; never a second parser."""
    return get_canonical_root(host)

