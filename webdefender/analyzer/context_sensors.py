"""Network, context and passive-risk sensor mixin.

These methods gather transport, infrastructure, page-configuration and
intelligence observations. Configuration weakness is not itself threat proof.
"""
from ..metadata import USER_AGENT
from ..metadata import RUNNING_ON_PYTHONANYWHERE
from ..metadata import APP_VERSION
import base64, difflib
import os, re, json, time, ssl, socket, ipaddress, hashlib, math
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin, parse_qsl
from collections import Counter
import requests
from bs4 import BeautifulSoup

from .url_domain import (
    normalize_url, host_is_private, host_is_raw_ip, resolve_public_ips,
    read_limited_response, same_origin, severity_weight, full_decode,
    get_canonical_root, get_root_domain, registrable_domain_v21,
)
from .identity import (
    BRAND_KEYWORDS, SUSPICIOUS_TLDS, LEGITIMATE_BRAND_DOMAINS,
    brand_present, legitimate_brand_root, DANGEROUS_EXTENSIONS,
    ARCHIVE_EXTENSIONS, SHORTENER_HOSTS,
)
from ..state import THREAT_INTEL_STORE
from ..intelligence.policy import decision_weight as intelligence_decision_weight

REQUEST_TIMEOUT=15
MAX_CONTENT_SIZE=5*1024*1024
MAX_REDIRECTS=8
class ContextSensorsMixin:
    def probe_network(self, host):
        """TCP seviyesinde 80/443 portlarını HTTP'den bağımsız test eder.
        Bu sonuç bir tehdit hükmü değildir; yalnızca erişilebilirlik teşhisidir.
        """
        result = {"host": host, "ports": {}, "summary": "completed"}
        for port in (80, 443):
            started = time.perf_counter()
            item = {"port": port, "open": False, "latency_ms": None, "status": "unknown", "error": ""}
            try:
                # Önce DNS/IP güvenlik doğrulaması. Private/special hedeflere probe yapılmaz.
                resolve_public_ips(host)
                with socket.create_connection((host, port), timeout=3):
                    item["open"] = True
                    item["status"] = "open"
            except socket.timeout as exc:
                item["status"] = "timeout"
                item["error"] = str(exc) or "timeout"
            except ConnectionRefusedError as exc:
                item["status"] = "refused"
                item["error"] = str(exc)
            except OSError as exc:
                item["status"] = "network_error"
                item["error"] = str(exc)
            item["latency_ms"] = round((time.perf_counter()-started)*1000, 2)
            if RUNNING_ON_PYTHONANYWHERE:
                item["authoritative"] = False
                item["display_status"] = "hosting_unverified"
                item["note"] = "PythonAnywhere raw TCP sonucu hedef sunucunun gerçek port durumu olarak yorumlanmaz."
            else:
                item["authoritative"] = True
                item["display_status"] = item["status"]
            result["ports"][str(port)] = item
        result["authoritative"] = not RUNNING_ON_PYTHONANYWHERE
        self.results["network_probe"] = result

    def safe_get(self, session, url, timeout=REQUEST_TIMEOUT, max_redirects=MAX_REDIRECTS):
        current = url
        history = []
        for _ in range(max_redirects + 1):
            p = urlparse(current)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise ValueError("Redirect geçersiz bir hedefe gidiyor.")
            # V32.4.2: Two-stage SSRF guard (TOCTOU mitigation).
            # Stage 1: Validate that all resolved IPs are public before connecting.
            # Stage 2: Re-validate after the connection attempt if the response
            # triggers a redirect to a new host (handled by next loop iteration).
            # Note: requests internally re-resolves the hostname; a fast-flipping
            # DNS entry could theoretically bypass stage 1. Full mitigation requires
            # binding to the pre-resolved IP, which is left for a network-layer
            # control (e.g. an egress firewall / allow-list) in production.
            resolve_public_ips(p.hostname)
            # Additional guard: reject if hostname resolves to a private range
            # at connection time by checking again post-resolve (best-effort).
            try:
                _post_ips = socket.getaddrinfo(p.hostname, None, type=socket.SOCK_STREAM)
                for _ai in _post_ips:
                    _ip_str = _ai[4][0]
                    _ip_obj = ipaddress.ip_address(_ip_str)
                    if (_ip_obj.is_private or _ip_obj.is_loopback or
                            _ip_obj.is_link_local or _ip_obj.is_reserved):
                        raise ValueError(f"SSRF: hostname re-resolved to private IP {_ip_str}")
            except ValueError:
                raise
            except Exception:
                pass  # DNS failure here is handled by the subsequent request
            r = session.get(current, timeout=timeout, allow_redirects=False,
                            verify=True, stream=True)
            if r.status_code not in (301, 302, 303, 307, 308):
                return r, history, current
            location = r.headers.get("Location")
            if not location:
                return r, history, current
            target = urljoin(current, location)
            tp = urlparse(target)
            if tp.scheme not in ("http", "https") or not tp.hostname:
                r.close()
                raise ValueError("Redirect HTTP/HTTPS dışı veya geçersiz hedefe gidiyor.")
            resolve_public_ips(tp.hostname)
            history.append({
                "status": r.status_code, "from": current,
                "location": location, "target": target,
                "external": not same_origin(current, target),
            })
            r.close()
            current = target
        raise requests.TooManyRedirects(f"{max_redirects} redirect sınırı aşıldı.")

    def fetch_with_scheme_fallback(self, session, url):
        """Try requested URL first. If HTTPS transport itself cannot be established,
        optionally probe the same host/path over HTTP. The fallback is explicit in
        results and never treated as equivalent HTTPS security.
        """
        attempts = []
        candidates = [url]
        p = urlparse(url)
        if p.scheme == "https":
            http_url = p._replace(scheme="http", netloc=(p.hostname or "") + ((":" + str(p.port)) if p.port and p.port not in (443, 80) else "")).geturl()
            candidates.append(http_url)

        last_exc = None
        for idx, candidate in enumerate(candidates):
            try:
                r, history, final = self.safe_get(session, candidate)
                attempts.append({"url": candidate, "ok": True, "status": r.status_code})
                return r, history, final, attempts, (idx > 0)
            except (requests.ConnectionError, requests.Timeout, ssl.SSLError, OSError) as exc:
                last_exc = exc
                attempts.append({"url": candidate, "ok": False, "error": str(exc)[:300]})
        if last_exc:
            raise last_exc
        raise requests.ConnectionError("HTTP/HTTPS bağlantısı kurulamadı.")

    def check_url_intelligence(self, url):
        p = urlparse(url)
        host  = p.hostname or ""
        path  = p.path
        query = p.query

        # Çok katmanlı decode
        decoded_full = full_decode(url)
        double_encoded = decoded_full != url
        self.results["url_intelligence"]["double_encoded"] = double_encoded
        if double_encoded:
            self.add_finding(
                "Çok katmanlı URL encoding", "high",
                "URL birden fazla kez encode edilmiş. Güvenlik filtrelerini atlatmak için kullanılan bir tekniktir.",
                "url",
                f"Orijinal : {url[:200]}\nDecode   : {decoded_full[:200]}",
                0.93,
            )

        # Parametreleri decode edilmiş query ile çözümle
        decoded_query = full_decode(query)
        params = parse_qsl(decoded_query, keep_blank_values=True) or \
                 parse_qsl(query,         keep_blank_values=True)

        tracking_re = re.compile(
            r"^(utm_[a-z0-9_]+|gclid|fbclid|msclkid|ref|referrer|"
            r"affiliate|aff|campaign|click|pid|tracking)$", re.I,
        )
        # ── GENİŞLETİLMİŞ redirect regex — followup, next, service vs. dahil ──
        redirect_re = re.compile(
            r"^(url|uri|u|next|redirect|redirect_uri|return|return_to|"
            r"continue|dest|destination|target|goto|followup|follow_up|"
            r"after|after_login|success_url|callback|redir|r|forward|"
            r"location|link|out|exit|ref_url|service|from|back|jump|"
            r"forward_url|returnurl|redirecturl|nexturl|landingpage)$",
            re.I,
        )
        sensitive_re = re.compile(
            r"(token|secret|password|passwd|api[_-]?key|session|auth|"
            r"credential|access_token|refresh_token|private|apikey|key)$",
            re.I,
        )

        brand_in_params = []
        for k, v in params:
            decoded_v = full_decode(v)
            encoded   = decoded_v != v
            self.results["url_intelligence"]["parameters"].append({
                "name": k, "value_preview": decoded_v[:200], "encoded": encoded,
            })
            if encoded:
                self.results["url_intelligence"]["encoded_parameters"].append(k)
            if tracking_re.match(k):
                self.results["url_intelligence"]["tracking_parameters"].append(k)
            if redirect_re.match(k):
                self.results["url_intelligence"]["redirect_parameters"].append(k)
            if sensitive_re.search(k):
                self.results["url_intelligence"]["sensitive_parameter_names"].append(k)
                self.add_finding(
                    f"Hassas parametre adı URL'de görünüyor: {k}", "medium",
                    "Sorgu parametresinde kimlik/oturum bilgisi içerebilecek isim tespit edildi.",
                    "url", k, 0.85,
                )
            for brand in BRAND_KEYWORDS:
                if brand_present(brand, decoded_v):
                    brand_in_params.append(f"{k}={brand}")

        self.results["url_intelligence"]["brand_in_params"] = list(set(brand_in_params))
        self.results["url_intelligence"]["path"]        = path
        self.results["url_intelligence"]["query_count"] = len(params)

        # Giriş sayfası sinyali
        login_re = re.compile(
            r"(signin|sign.in|login|log.in|logon|auth|authenticate|"
            r"account|verify|verification|secure|security|banking|"
            r"giri[sş]|uyelik|üyelik)",
            re.I,
        )
        self.results["url_intelligence"]["login_page"] = (
            bool(login_re.search(path)) or bool(login_re.search(decoded_full))
        )

        # Path içindeki marka adları
        brand_in_path = [b for b in BRAND_KEYWORDS if b in (path + decoded_full).lower()]
        self.results["url_intelligence"]["brand_in_path"] = list(set(brand_in_path))

        # ── Credential Harvesting tespiti ──────────────────────────────────
        # IP/sahte host + gerçek markaya yönlendiren redirect parametresi
        rp_keys = self.results["url_intelligence"]["redirect_parameters"]
        if rp_keys:
            rp_values = " ".join(
                full_decode(v)
                for k, v in params
                if redirect_re.match(k)
            )
            trusted_dest = any(ld in rp_values.lower() for ld in LEGITIMATE_BRAND_DOMAINS)
            is_fake_host = host_is_raw_ip(host) or \
                           get_root_domain(host) not in LEGITIMATE_BRAND_DOMAINS

            if trusted_dest and is_fake_host:
                self.add_finding(
                    "Credential Harvesting: Güvenilir siteye yönlendirme tuzağı", "critical",
                    "Sahte/IP host üzerinden gerçek bir marka sitesine yönlendiren parametre bulundu. "
                    "Bilgi çalındıktan sonra gerçek siteye yönlendiren klasik phishing tekniğidir.",
                    "phishing",
                    f"Host: {host} | Redirect params: {', '.join(rp_keys)} | Değer: {rp_values[:300]}",
                    0.97,
                )
            else:
                self.add_finding(
                    "Potansiyel yönlendirme parametresi", "medium",
                    "URL'de dış yönlendirme amacıyla kullanılabilen parametre adı bulundu.",
                    "url", ", ".join(rp_keys), 0.75,
                )

        # Şüpheli TLD
        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld.lower() in SUSPICIOUS_TLDS:
            self.results["url_intelligence"]["suspicious_tld"] = True
            self.add_finding(
                f"Şüpheli TLD: {tld}", "medium",
                "Bu TLD phishing ve kötü amaçlı siteler tarafından yoğun şekilde kullanılır.",
                "domain", host, 0.75,
            )

    def check_security_headers(self, headers):
        specs = {
            "Strict-Transport-Security":   ("HTTPS zorunluluğu",                    "medium"),
            "Content-Security-Policy":     ("Kaynak çalıştırma politikasını sınırlar","medium"),
            "X-Content-Type-Options":      ("MIME sniffing koruması",               "low"),
            "X-Frame-Options":             ("Clickjacking koruması",                "medium"),
            "Referrer-Policy":             ("Referrer bilgilerinin kontrolü",        "low"),
            "Permissions-Policy":          ("Tarayıcı özelliklerine erişimi sınırlar","low"),
            "Cross-Origin-Opener-Policy":  ("Cross-origin pencere izolasyonu",      "low"),
            "Cross-Origin-Resource-Policy":("Cross-origin kaynak erişimi",          "low"),
            "Cross-Origin-Embedder-Policy":("Cross-origin embed kontrolü",          "low"),
        }
        lower = {k.lower(): v for k, v in headers.items()}
        for name, (desc, sev) in specs.items():
            present = name.lower() in lower
            self.results["security_headers"][name] = {
                "present": present,
                "value":   lower.get(name.lower(), "")[:1000],
                "description": desc,
                "severity": sev,
            }

        proto = self.results["domain_info"]["protocol"]
        if proto == "https" and "strict-transport-security" not in lower:
            self.add_finding(
                "HSTS eksik", "medium",
                "HTTPS var ama Strict-Transport-Security header'ı bulunamadı.",
                "headers", "Strict-Transport-Security: missing", 1.0,
            )
        if "x-content-type-options" not in lower:
            self.add_finding(
                "MIME sniffing koruması eksik", "low",
                "X-Content-Type-Options header'ı bulunamadı.",
                "headers", "X-Content-Type-Options: missing", 1.0,
            )
        if "x-frame-options" not in lower and "content-security-policy" not in lower:
            self.add_finding(
                "Clickjacking koruması görünür değil", "medium",
                "X-Frame-Options veya CSP frame-ancestors direktifi bulunamadı.",
                "headers", "X-Frame-Options/CSP: missing", 1.0,
            )

    def check_cookies(self, response):
        # Doğru yol: ham header listesi (birden fazla Set-Cookie için)
        try:
            raw_list = response.raw.headers.get_all("Set-Cookie") or []
        except Exception:
            raw_list = []
        if not raw_list:
            combined = response.headers.get("Set-Cookie", "")
            if combined:
                raw_list = [combined]

        proto = self.results["domain_info"]["protocol"]
        for value in raw_list:
            name    = value.split("=", 1)[0].strip()
            low     = value.lower()
            secure  = bool(re.search(r"(?:^|;)\s*secure(?:;|$|\s)", low))
            httponly= bool(re.search(r"(?:^|;)\s*httponly(?:;|$|\s)", low))
            same_m  = re.search(r"(?:^|;)\s*samesite\s*=\s*([^;\s]+)", low)
            issues  = []
            if not secure   and proto == "https": issues.append("Secure eksik")
            if not httponly:                       issues.append("HttpOnly eksik")
            if not same_m:                         issues.append("SameSite eksik")
            self.results["cookies"].append({
                "name": name, "secure": secure, "httponly": httponly,
                "samesite": same_m.group(1) if same_m else "",
                "issues": issues,
            })
            if issues:
                self.add_finding(
                    "Cookie güvenlik bayrakları eksik", "medium",
                    f"{name} cookie'sinde: {', '.join(issues)}.",
                    "cookies", name, 0.98,
                )

    def check_csp(self, headers):
        csp = headers.get("Content-Security-Policy", "")
        if not csp:
            return
        directives, issues = {}, []
        for part in csp.split(";"):
            bits = part.strip().split()
            if not bits:
                continue
            directives[bits[0]] = bits[1:]
            if "'unsafe-inline'" in bits[1:]: issues.append(f"{bits[0]}: unsafe-inline")
            if "'unsafe-eval'"   in bits[1:]: issues.append(f"{bits[0]}: unsafe-eval")
            if "*"               in bits[1:]: issues.append(f"{bits[0]}: wildcard")
        self.results["csp"] = {
            "present": True, "value": csp[:4000],
            "directives": directives, "issues": issues,
        }
        if "default-src" not in directives and "script-src" not in directives:
            self.add_finding(
                "CSP kapsamı sınırlı olabilir", "low",
                "CSP mevcut ama default-src/script-src direktifleri görünmüyor.",
                "csp", csp[:500], 0.9,
            )
        if issues:
            self.add_finding(
                "CSP içinde gevşek direktifler", "medium",
                "; ".join(issues), "csp", "; ".join(issues), 0.95,
            )

    def check_technology(self, response, body):
        tech = []
        server = response.headers.get("Server")
        powered = response.headers.get("X-Powered-By")
        if server:  tech.append(f"Server: {server}")
        if powered: tech.append(f"X-Powered-By: {powered}")

        patterns = {
            "WordPress": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
            "jQuery":    [r"jquery(?:\.min)?\.js", r"jquery[.-][0-9]"],
            "Bootstrap": [r"bootstrap(?:\.min)?\.(?:css|js)"],
            "React":     [r"react-dom", r"__react"],
            "Vue.js":    [r"vue(?:\.min)?\.js"],
            "Angular":   [r"ng-version", r"angular(?:\.min)?\.js"],
            "Next.js":   [r"/_next/static/", r"__NEXT_DATA__"],
            "PHP":       [r"\.php(?:[?#]|$)"],
            "Django":    [r"csrfmiddlewaretoken"],
            "ASP.NET":   [r"__VIEWSTATE"],
            "Cloudflare":[r"cf-ray"],
        }
        haystack = body + "\n" + "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
        for name, pats in patterns.items():
            if any(re.search(pat, haystack, re.I) for pat in pats):
                tech.append(name)
        self.results["technology"] = list(dict.fromkeys(tech))

    def check_well_known(self, session, base_url, path, key):
        target = urljoin(base_url, "/" + path.lstrip("/"))
        try:
            r, _, final = self.safe_get(session, target, timeout=10, max_redirects=4)
            body = read_limited_response(r, 512 * 1024)
            self.results["well_known"][key] = {
                "status_code": r.status_code, "exists": r.status_code == 200,
                "url": final, "size": len(body),
            }
            r.close()
        except Exception as exc:
            self.results["well_known"][key] = {
                "status_code": None, "exists": False,
                "url": target, "error": str(exc),
            }

    def build_feature_vector(self):
        cats=[f.get("category") for f in self.results["findings"]]
        sev=[f.get("severity") for f in self.results["findings"]]
        ui=self.results["url_intelligence"]
        html_forms=self.results["forms"]
        patterns=self.results["suspicious_patterns"]
        features={
            "raw_ip": self.results["domain_info"]["is_ip"],
            "http": self.results["domain_info"]["protocol"] == "http",
            "double_encoded": ui.get("double_encoded",False),
            "suspicious_tld": ui.get("suspicious_tld",False),
            "login_page": ui.get("login_page",False),
            "brand_path": bool(ui.get("brand_in_path")),
            "brand_params": bool(ui.get("brand_in_params")),
            "redirect_params": bool(ui.get("redirect_parameters")),
            "sensitive_params": bool(ui.get("sensitive_parameter_names")),
            "many_redirects": self.results["http"]["redirect_count"] >= 3,
            "external_redirect": any(x.get("external") for x in self.results["http"]["redirects"]),
            "external_form": any(x.get("external_action") for x in html_forms),
            "password_form": any(any((i.get("type") or "").lower()=="password" for i in x.get("inputs",[])) for x in html_forms),
            "dangerous_download": any(x.get("dangerous_type") for x in self.results["downloads"]),
            "obfuscation": any(x.get("pattern") in {"eval()","atob()","String.fromCharCode"} for x in patterns),
            "mixed_content": bool(self.results["mixed_content"]),
            "critical_finding": "critical" in sev,
            "high_finding": "high" in sev,
            "phishing_category": "phishing" in cats,
            "credential_theft_category": "credential_theft" in cats,
            "malware_category": "malware" in cats,
            "behavior_category": "behavior" in cats,
            "multiple_correlations": len(self.results["defender"].get("correlations",[])) >= 2,
            "tls_invalid": self.results["domain_info"]["protocol"]=="https" and self.results["ssl_info"].get("checked") and not self.results["ssl_info"].get("valid"),
            "passive_guarded": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 15,
            "passive_elevated": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 30,
            "passive_high": self.results["defender"].get("passive_analysis",{}).get("score",0) >= 55,
        }
        self.results["defender"]["feature_vector"] = {k: bool(v) for k,v in features.items()}

    def check_generic_runtime_risk(self, original_url):
        """Marka listesine bağımlı kalmadan runtime phishing/credential sinyallerini korele eder."""
        b=self.results.get("browser",{}) or {}
        final=b.get("final_url") or self.results.get("final_url") or original_url
        host=(urlparse(final).hostname or "").lower(); root=get_root_domain(host)
        initial=(urlparse(original_url).path or "/").lower(); fp=(urlparse(final).path or "/").lower()
        sem=b.get("semantic_dom") or {}; forms=b.get("forms") or self.results.get("forms") or []
        inputs=sem.get("inputs") or []
        sensitive=[]
        for i in inputs:
            blob=" ".join(str(i.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
            if i.get("type")=="password" or re.search(r"password|passwd|parola|şifre|otp|one.?time|verification|verify|pin|cvv|cvc|card|kart|iban|wallet|seed|recovery",blob,re.I): sensitive.append(i)
        loginish=bool(re.search(r"/(login|signin|sign-in|auth|account|verify|verification|secure|wallet|payment)(?:/|$)",fp,re.I))
        if loginish and fp != initial:
            self.add_finding("Tarayıcı giriş/doğrulama sayfasına yönlendi","medium","Başlangıç adresi browser çalıştıktan sonra giriş/doğrulama bağlamlı bir path'e geçti.","redirect",f"{original_url} -> {final}",.82)
        # Marka adı hostname içinde taklit ediliyorsa sayfa metninden bağımsız güçlü sinyal.
        labels=[x for x in host.split('.') if x and x not in {'www','com','net','org','app','site','online'}]
        impersonated=[]; typo=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand,root): continue
            if any(brand_present(brand,x) for x in labels): impersonated.append(brand)
            elif len(brand)>=5:
                for x in labels:
                    token=re.sub(r'[^a-z0-9]','',x.lower())
                    if len(token)>=4 and difflib.SequenceMatcher(None,brand,token).ratio()>=.82:
                        typo.append((brand,x)); break
        if impersonated:
            self.add_finding("Alan adında marka taklidi sinyali","high","Hostname tanınan bir marka adını içeriyor ancak kök domain o markanın bilinen resmi alan adı değil.","phishing",f"host={host}; brand={','.join(sorted(set(impersonated))[:8])}",.96)
        if typo:
            self.add_finding("Alan adında typosquatting benzerliği","high","Domain etiketi bilinen bir markaya yazım olarak çok benziyor ancak resmi alan adı değil.","phishing",str(typo[:8]),.88)
        if sensitive:
            self.add_finding("Runtime DOM hassas bilgi alanı içeriyor","medium","Render edilen DOM parola/OTP/kart/hesap benzeri hassas giriş alanı içeriyor. Tek başına saldırı kanıtı değildir; diğer sinyallerle korele edilir.","forms",f"sensitive_fields={len(sensitive)}; final={final}",.82)
        if sensitive and (impersonated or typo):
            self.add_finding("Marka taklidi ile hassas bilgi isteme birlikte","critical","Şüpheli marka/domain yapısı ile hassas bilgi alanları aynı sayfada birlikte gözlendi.","credential_theft",f"host={host}; sensitive_fields={len(sensitive)}",.995)
        if sensitive and loginish and (self.results.get('defender',{}).get('passive_analysis',{}).get('score',0)>=10):
            self.add_finding("Şüpheli domain + login + hassas alan korelasyonu","high","Login/doğrulama sayfası, hassas giriş alanı ve yükselmiş domain riski birlikte gözlendi.","credential_theft",f"final={final}; sensitive_fields={len(sensitive)}",.92)
        # Tüm form action hedeflerini değerlendir, formu asla submit etme.
        for f in forms[:100]:
            action=str(f.get('action') or final)
            try: ar=get_root_domain(urlparse(urljoin(final,action)).hostname or '')
            except Exception: ar=''
            fsens=bool(f.get('has_password') or f.get('has_otp') or f.get('has_card'))
            if fsens and ar and ar!=root:
                self.add_finding("Hassas form farklı kök domaine gönderiliyor","critical","Parola/OTP/kart içeren formun action hedefi sayfanın kök domaininden farklı.","credential_theft",action[:500],.995)

    def check_live_threat_intelligence(self, url):
        """Canlı IOC kaynakları yardımcı kanıt olarak kullanılır; davranış motorunun yerine geçmez."""
        ti=self.results['threat_intelligence']; ti['checked']=True
        headers={'User-Agent':f'WebDefender/{APP_VERSION} security-scanner'}
        # PhishTank doğrudan URL lookup. app_key opsiyonel, anahtarsız kullanım daha sık rate-limit olabilir.
        try:
            data={'url':url,'format':'json'}
            key=os.getenv('PHISHTANK_APP_KEY','').strip()
            if key: data['app_key']=key
            r=requests.post('https://checkurl.phishtank.com/checkurl/',data=data,headers=headers,timeout=6)
            ti['sources'].append({'name':'PhishTank','status':r.status_code})
            if r.ok:
                j=r.json(); rr=j.get('results') or {}
                if rr.get('in_database') and rr.get('valid') and rr.get('verified'):
                    ti['matches'].append({'source':'PhishTank','type':'verified_phishing','url':url})
                    self.add_finding('PhishTank doğrulanmış phishing eşleşmesi','critical','URL PhishTank veritabanında doğrulanmış aktif phishing kaydıyla eşleşti.','phishing',url,.999)
        except Exception as e: ti['errors'].append({'source':'PhishTank','error':str(e)[:220]})
        # OpenPhish community feed. İsteğe bağlı kapatılabilir; feed bellekte sadece bu tarama için kontrol edilir.
        if os.getenv('ENABLE_OPENPHISH','1').lower() not in ('0','false','no','off'):
            try:
                r=requests.get('https://openphish.com/feed.txt',headers=headers,timeout=7,stream=True)
                ti['sources'].append({'name':'OpenPhish Community','status':r.status_code})
                if r.ok:
                    _chunks=[]; _total=0
                    for _chunk in r.iter_content(65536,decode_unicode=False):
                        if not _chunk: continue
                        _chunks.append(_chunk); _total += len(_chunk)
                        if _total >= 10*1024*1024: break
                    _feed_raw=b''.join(_chunks)[:10*1024*1024]
                    norm=url.rstrip('/').lower(); host=(urlparse(url).hostname or '').lower()
                    lines=_feed_raw.decode('utf-8','replace').splitlines()[:100000]
                    exact=any(x.strip().rstrip('/').lower()==norm for x in lines)
                    hostmatch=any((urlparse(x.strip()).hostname or '').lower()==host for x in lines if x.startswith(('http://','https://')))
                    if exact or hostmatch:
                        ti['matches'].append({'source':'OpenPhish','type':'phishing_feed','match':'exact' if exact else 'host'})
                        self.add_finding('OpenPhish güncel feed eşleşmesi','critical','URL veya host güncel OpenPhish phishing feed içinde bulundu.','phishing',f"match={'exact' if exact else 'host'}; {url}",.995 if exact else .97)
            except Exception as e: ti['errors'].append({'source':'OpenPhish','error':str(e)[:220]})

    def check_cve_intelligence(self):
        """Gözlenen teknoloji/sürüm için NVD adaylarını getirir. Aktif exploit/probe yapmaz."""
        if os.getenv('ENABLE_CVE_INTEL','1').lower() in ('0','false','no','off'): return
        tech=self.results.get('technology') or []
        products=[]
        for item in tech:
            m=re.search(r'(?i)(wordpress|jquery|bootstrap|next\\.js|php|django|angular|vue(?:\\.js)?)[ /:_-]*v?([0-9]+(?:\\.[0-9]+){1,3})',str(item))
            if m: products.append((m.group(1),m.group(2)))
        self.results['cve_intelligence']['products']=[{'product':a,'version':b} for a,b in products[:4]]
        for product,version in products[:3]:
            try:
                q=requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0',params={'keywordSearch':f'{product} {version}','resultsPerPage':8},headers={'User-Agent':f'WebDefender/{APP_VERSION}'},timeout=7)
                if not q.ok: continue
                for v in q.json().get('vulnerabilities',[])[:8]:
                    c=v.get('cve') or {}; cid=c.get('id'); desc=''
                    for d in c.get('descriptions',[]):
                        if d.get('lang')=='en': desc=d.get('value',''); break
                    if cid: self.results['cve_intelligence']['candidates'].append({'cve':cid,'product':product,'version':version,'description':desc[:500],'status':'candidate_not_confirmed'})
            except Exception as e:
                self.results['errors'].append({'module':'cve_intelligence','error':str(e)[:220]})

    def check_malware_intelligence(self, url):
        """URLhaus + ThreatFox canlı zenginleştirme; sonuçları Web Defender'ın kendi IOC hafızasına da yazar."""
        ti=self.results['threat_intelligence']; host=(urlparse(url).hostname or '').lower()
        # URLhaus Community API artık Auth-Key gerektiriyor.
        key=os.getenv('ABUSECH_AUTH_KEY','').strip()
        if not key:
            ti['sources'].append({'name':'URLhaus/ThreatFox','status':'not_configured','note':'ABUSECH_AUTH_KEY gerekli'})
            return
        headers={'Auth-Key':key,'User-Agent':f'WebDefender/{APP_VERSION}'}
        try:
            r=requests.post('https://urlhaus-api.abuse.ch/v1/url/',data={'url':url},headers=headers,timeout=7)
            ti['sources'].append({'name':'URLhaus','status':r.status_code})
            if r.ok:
                j=r.json()
                if j.get('query_status')=='ok':
                    ti['matches'].append({'source':'URLhaus','type':'malware_url','status':j.get('url_status'),'threat':j.get('threat')})
                    payloads=j.get("payloads") if isinstance(j.get("payloads"),list) else []
                    THREAT_INTEL_STORE.upsert("url",url,"URLhaus",threat_type=j.get("threat") or "malware_url",malware_family=payloads[0].get("signature") if payloads else None,confidence=100,last_seen=j.get("last_online"),raw=j)
                    for px in payloads[:100]:
                        sh=str(px.get("response_sha256") or px.get("sha256_hash") or px.get("sha256") or "").lower()
                        if re.fullmatch(r"[0-9a-f]{64}",sh):
                            THREAT_INTEL_STORE.upsert("sha256",sh,"URLhaus",threat_type="malware_payload",
                                malware_family=px.get("signature"),confidence=100,first_seen=px.get("firstseen"),last_seen=px.get("lastseen"),
                                expires_at=_expiry(px.get("lastseen") or px.get("firstseen"),180),raw=px)
                    self.add_finding('URLhaus malware URL eşleşmesi','critical','URL, URLhaus malware dağıtım verisinde eşleşti.','malware',json.dumps({'status':j.get('url_status'),'threat':j.get('threat'),'tags':j.get('tags')},ensure_ascii=False)[:800],.995)
        except Exception as e: ti['errors'].append({'source':'URLhaus','error':str(e)[:220]})
        # ThreatFox: URL ve domain IOC araması.
        for term in [url,host]:
            if not term: continue
            try:
                r=requests.post('https://threatfox-api.abuse.ch/api/v1/',json={'query':'search_ioc','search_term':term,'exact_match':True},headers=headers,timeout=7)
                ti['sources'].append({'name':'ThreatFox','status':r.status_code,'term':term[:120]})
                if r.ok:
                    j=r.json(); data=j.get('data') if j.get('query_status')=='ok' else []
                    if isinstance(data,list) and data:
                        x=data[0]; ti['matches'].append({'source':'ThreatFox','type':x.get('threat_type'),'ioc':x.get('ioc'),'malware':x.get('malware_printable')})
                        ioc_type='url' if str(x.get('ioc_type','')).lower()=='url' else ('ip' if 'ip' in str(x.get('ioc_type','')).lower() else 'domain')
                        THREAT_INTEL_STORE.upsert(ioc_type,x.get('ioc'),'ThreatFox',threat_type=x.get('threat_type'),malware_family=x.get('malware_printable') or x.get('malware'),confidence=x.get('confidence_level'),first_seen=x.get('first_seen'),last_seen=x.get('last_seen'),raw=x)
                        self.add_finding('ThreatFox malware IOC eşleşmesi','critical','URL/domain güncel malware IOC verisiyle eşleşti.','malware',json.dumps({'ioc':x.get('ioc'),'threat_type':x.get('threat_type'),'malware':x.get('malware_printable'),'confidence':x.get('confidence_level')},ensure_ascii=False)[:800],.99)
            except Exception as e: ti['errors'].append({'source':'ThreatFox','error':str(e)[:220]})

    def check_rdap_domain_v21(self, domain):
        """IANA RDAP bootstrap -> authoritative registry RDAP. Cached 24h."""
        domain=registrable_domain_v21(domain)
        cached=_cache_get("rdap:"+domain)
        if cached is not None: return cached
        out={"domain":domain,"observed":False,"age_days":None,"created":None,"expires":None,"registrar":None,"source":"IANA RDAP bootstrap"}
        try:
            global _RDAP_BOOTSTRAP
            now=time.time()
            with _TRUST_CACHE_LOCK:
                if not _RDAP_BOOTSTRAP["services"] or now-_RDAP_BOOTSTRAP["loaded_at"]>86400:
                    r=requests.get("https://data.iana.org/rdap/dns.json",timeout=(3,5),headers={"User-Agent":USER_AGENT})
                    r.raise_for_status()
                    _RDAP_BOOTSTRAP={"loaded_at":now,"services":r.json().get("services",[])}
            tld=domain.rsplit(".",1)[-1].lower()
            bases=[]
            for tlds,urls in _RDAP_BOOTSTRAP["services"]:
                if tld in [x.lower() for x in tlds]:
                    bases=urls; break
            if not bases: raise ValueError("TLD için RDAP bootstrap servisi bulunamadı")
            data=None
            for base in bases[:2]:
                try:
                    rr=requests.get(base.rstrip("/")+"/domain/"+quote(domain,safe=".-"),timeout=(3,6),
                                    headers={"Accept":"application/rdap+json, application/json","User-Agent":USER_AGENT})
                    if rr.status_code==200: data=rr.json(); break
                except Exception: continue
            if not data: raise ValueError("RDAP domain yanıtı alınamadı")
            events={str(e.get("eventAction","")).lower():e.get("eventDate") for e in data.get("events",[]) if isinstance(e,dict)}
            created=events.get("registration") or events.get("registered")
            expiry=events.get("expiration") or events.get("expiry")
            age=None
            if created:
                try:
                    dt=datetime.fromisoformat(created.replace("Z","+00:00"))
                    age=(datetime.now(timezone.utc)-dt.astimezone(timezone.utc)).days
                except Exception: pass
            registrar=None
            for ent in data.get("entities",[]) or []:
                roles=[str(x).lower() for x in ent.get("roles",[])]
                if "registrar" in roles:
                    vc=ent.get("vcardArray")
                    if isinstance(vc,list) and len(vc)>1:
                        for item in vc[1]:
                            if item and item[0]=="fn": registrar=item[3]; break
                    break
            out.update({"observed":True,"age_days":age,"created":created,"expires":expiry,"registrar":registrar})
        except Exception as exc:
            out["error"]=str(exc)[:300]
        _cache_put("rdap:"+domain,out,24)
        return out

    def check_email_dns_v21(self, domain):
        """SPF/DMARC/CAA are organization-context signals, not proof of web safety."""
        domain=registrable_domain_v21(domain)
        cached=_cache_get("maildns:"+domain)
        if cached is not None: return cached
        out={"domain":domain,"spf":None,"dmarc":None,"dmarc_policy":None,"caa":[],"observed":False}
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=1.5; resolver.lifetime=2.5
            try:
                for a in resolver.resolve(domain,"TXT"):
                    txt="".join(x.decode(errors="replace") if isinstance(x,bytes) else str(x) for x in getattr(a,"strings",[])) or a.to_text().strip('"')
                    if txt.lower().startswith("v=spf1"): out["spf"]=txt[:700]; break
            except Exception: pass
            try:
                for a in resolver.resolve("_dmarc."+domain,"TXT"):
                    txt="".join(x.decode(errors="replace") if isinstance(x,bytes) else str(x) for x in getattr(a,"strings",[])) or a.to_text().strip('"')
                    if "v=dmarc1" in txt.lower():
                        out["dmarc"]=txt[:700]
                        m=re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)",txt,re.I)
                        out["dmarc_policy"]=m.group(1).lower() if m else None
                        break
            except Exception: pass
            try: out["caa"]=[x.to_text()[:300] for x in resolver.resolve(domain,"CAA")][:20]
            except Exception: pass
            out["observed"]=True
        except Exception as exc: out["error"]=str(exc)[:250]
        _cache_put("maildns:"+domain,out,12)
        return out

    def check_asn_context_v21(self, ips):
        """ASN is infrastructure context only. Cloud hosting is never a safety verdict."""
        cached_key="asn:"+",".join(sorted(ips or [])[:4])
        cached=_cache_get(cached_key)
        if cached is not None: return cached
        out={"items":[],"observed":False,"source":"Team Cymru DNS"}
        known={"13335":"Cloudflare","15169":"Google","16509":"Amazon AWS","8075":"Microsoft","54113":"Fastly","20940":"Akamai","32934":"Meta"}
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=1.5; resolver.lifetime=2.5
            for ip in (ips or [])[:4]:
                try:
                    obj=ipaddress.ip_address(ip)
                    if obj.version!=4: continue
                    q=".".join(reversed(ip.split(".")))+".origin.asn.cymru.com"
                    txt=resolver.resolve(q,"TXT")[0].to_text().strip('"')
                    parts=[x.strip() for x in txt.split("|")]
                    asn=parts[0].split()[0] if parts else ""
                    out["items"].append({"ip":ip,"asn":"AS"+asn if asn else None,
                        "provider_context":known.get(asn),"prefix":parts[1] if len(parts)>1 else None,
                        "country":parts[2] if len(parts)>2 else None})
                except Exception: continue
            out["observed"]=bool(out["items"])
        except Exception as exc: out["error"]=str(exc)[:250]
        _cache_put(cached_key,out,12)
        return out

    def run_trust_context_v21(self):
        root=registrable_domain_v21(self.results.get("domain_info",{}).get("hostname") or "")
        ips=self.results.get("dns",{}).get("addresses") or []
        out={}
        jobs={}
        with ThreadPoolExecutor(max_workers=4) as ex:
            jobs[ex.submit(self.check_rdap_domain_v21,root)]="rdap"
            jobs[ex.submit(self.check_email_dns_v21,root)]="email_dns"
            jobs[ex.submit(self.check_asn_context_v21,ips)]="asn"
            jobs[ex.submit(tranco_rank_v21,root)]="tranco"
            for fut in as_completed(jobs):
                name=jobs[fut]
                try: out[name]=fut.result()
                except Exception as exc: out[name]={"error":str(exc)[:250]}
        # Positive/context score. Never subtracted from threat.
        score=0; ev=[]
        rd=out.get("rdap",{}); age=rd.get("age_days")
        if isinstance(age,int):
            if age>=365*5: score+=22; ev.append("Domain 5+ yıllık")
            elif age>=365*2: score+=15; ev.append("Domain 2+ yıllık")
            elif age<7:
                self.add_finding("Çok yeni kayıtlı domain","high",f"RDAP kaydına göre domain yaklaşık {age} günlük.","domain_age",str(rd),.85)
            elif age<30:
                self.add_finding("Yeni kayıtlı domain","medium",f"RDAP kaydına göre domain yaklaşık {age} günlük.","domain_age",str(rd),.72)
        tr=out.get("tranco",{}); rank=tr.get("rank")
        if isinstance(rank,int):
            if rank<=10000: score+=25; ev.append("Tranco top-10k bağlamı")
            elif rank<=100000: score+=16; ev.append("Tranco top-100k bağlamı")
            elif rank<=1000000: score+=8; ev.append("Tranco top-1M bağlamı")
        md=out.get("email_dns",{})
        if md.get("spf"): score+=4; ev.append("SPF mevcut")
        if md.get("dmarc"): score+=5; ev.append("DMARC mevcut")
        if md.get("dmarc_policy") in ("reject","quarantine"): score+=3; ev.append("DMARC politikası sıkı")
        if md.get("caa"): score+=3; ev.append("CAA mevcut")
        ai=out.get("asn",{})
        if any(x.get("provider_context") for x in ai.get("items",[])): score+=3; ev.append("Bilinen büyük altyapı sağlayıcısı bağlamı")
        self.results["trust_context_v21"]={"score":min(score,100),"signals":ev,"sensors":out,
            "principle":"Trust Context yalnızca bağlamdır; Threat Evidence skorundan çıkarılmaz."}
        self.build_identity_trust_v21()

    def run_network_behavior_v22(self):
        b=self.results.get("browser",{}) or {}; final=b.get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or "")
        hooks=b.get("runtime_hooks") or {}; sem=b.get("semantic_dom") or {}; inputs=sem.get("inputs") or []
        sensitive=any(str(i.get("type","")).lower()=="password" or re.search(
            r"otp|one.?time|verification|cvv|cvc|cc-number|card|iban|password|parola|şifre",
            " ".join(str(i.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")),re.I) for i in inputs)
        events=[]
        for kind,rows in (("fetch",hooks.get("fetches") or []),("xhr",hooks.get("xhr") or []),
                          ("beacon",hooks.get("beacons") or []),("form_submit",hooks.get("form_submits") or [])):
            for x in rows[:100]:
                u=urljoin(final,str(x.get("url") or x.get("action") or "")); rr=registrable_domain_v21(urlparse(u).hostname or "")
                if rr: events.append({"kind":kind,"url":u[:700],"root":rr,"cross_site":rr!=root,
                                      "has_body":bool(x.get("has_body")),"method":str(x.get("method") or "")[:20]})
        for x in (b.get("requests") or [])[:250]:
            if str(x.get("method","")).upper() in ("POST","PUT","PATCH"):
                u=str(x.get("url") or ""); rr=registrable_domain_v21(urlparse(u).hostname or "")
                if rr: events.append({"kind":"network_write","url":u[:700],"root":rr,"cross_site":rr!=root,
                                      "has_body":bool(x.get("has_post_data")),"method":str(x.get("method") or "")})
        for x in b.get("websockets") or []:
            u=str(x.get("url") or ""); rr=registrable_domain_v21(urlparse(u).hostname or "")
            if rr: events.append({"kind":"websocket","url":u[:700],"root":rr,"cross_site":rr!=root,"has_body":False,"method":"WS"})
        cross=[e for e in events if e["cross_site"]]; writes=[e for e in cross if e["has_body"] or e["kind"] in ("beacon","form_submit")]
        if sensitive and writes:
            self.add_finding("Hassas arayüz + harici veri gönderimi","critical",
                "Hassas giriş alanları varken farklı registrable domaine veri taşıyabilen runtime istekleri gözlendi.",
                "data_exfiltration",json.dumps(writes[:12],ensure_ascii=False),.985)
        elif writes:
            self.add_finding("Harici runtime veri gönderimi","medium",
                "Farklı registrable domaine gövdeli runtime trafiği gözlendi; tek başına saldırı kanıtı değildir.",
                "network_exfil",json.dumps(writes[:12],ensure_ascii=False),.72)
        self.results["network_behavior_v22"]={"page_root":root,"sensitive_ui":sensitive,"events":events[:220],
            "cross_site_count":len(cross),"cross_site_write_count":len(writes)}

    def run_js_payload_v23(self):
        b=self.results.get("browser",{}) or {}; h=self.results.get("http",{}) or {}; html=str(b.get("html") or h.get("html") or "")
        if not html: self.results["js_payload_v23"]={"observed":False,"reason":"HTML yok"}; return
        soup=BeautifulSoup(html[:700000],"html.parser")
        scripts="\n".join((x.string or x.get_text() or "") for x in soup.find_all("script"))[:600000]
        decoded=[]; indicators=Counter()
        for m in re.finditer(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/])',scripts):
            if len(decoded)>=20: break
            try:
                raw=base64.b64decode(m.group(1),validate=True)
                if len(raw)<=65536:
                    text=raw.decode("utf-8","replace")
                    if sum(c.isprintable() or c in "\\r\\n\\t" for c in text)/max(1,len(text))>.82:
                        decoded.append({"encoding":"base64","sample":text[:900]})
            except Exception: pass
        corpus=(scripts+" "+" ".join(x["sample"] for x in decoded)).lower()
        pats={"dynamic_code":r"\beval\s*\(|new\s+function\s*\(","decoder_chain":r"atob\s*\(|fromcharcode|decodeuricomponent\s*\(",
              "credential_terms":r"password|passwd|otp|one.?time|cvv|cvc|credit.?card|seed.?phrase",
              "exfil_api":r"sendbeacon\s*\(|fetch\s*\(|xmlhttprequest","anti_analysis":r"webdriver|devtools|debugger\s*;|headless"}
        for k,p in pats.items(): indicators[k]=len(re.findall(p,corpus,re.I))
        score=min(100,indicators["dynamic_code"]*12+indicators["decoder_chain"]*7+min(indicators["credential_terms"],5)*8+min(indicators["anti_analysis"],5)*8)
        if decoded and indicators["dynamic_code"] and indicators["credential_terms"]:
            self.add_finding("Decode edilmiş scriptte hassas veri + dinamik kod zinciri","high",
                "Statik çözülen metinde hassas veri terimleri ve dinamik kod göstergeleri birlikte bulundu; içerik çalıştırılmadı.",
                "javascript",json.dumps({"indicators":dict(indicators),"samples":decoded[:4]},ensure_ascii=False),.91)
        self.results["js_payload_v23"]={"observed":True,"decoded_count":len(decoded),"indicators":dict(indicators),
            "score":score,"decoded_samples":decoded[:8],"execution_policy":"decoded content never executed"}

    def run_visual_impersonation_v24(self):
        b=self.results.get("browser",{}) or {}; sem=b.get("semantic_dom") or {}; final=b.get("final_url") or self.results.get("final_url") or ""
        root=registrable_domain_v21(urlparse(final).hostname or ""); html=str(b.get("html") or "")
        soup=BeautifulSoup(html[:500000],"html.parser") if html else None; logos=[]; assets=[]
        if soup:
            for tag in soup.find_all(["img","svg","link"],limit=180):
                src=tag.get("src") or tag.get("href") or ""; alt=" ".join(str(tag.get(k,"")) for k in ("alt","title","aria-label","class","id"))
                if src: assets.append(urljoin(final,src)[:700])
                if re.search(r"logo|brand|facebook|google|microsoft|airbnb|paypal|apple|instagram",alt+" "+src,re.I):
                    logos.append({"src":urljoin(final,src)[:700],"label":alt[:300]})
        blob=" ".join([str(sem.get("title",""))," ".join(sem.get("headings") or [])," ".join(sem.get("buttons") or []),str(sem.get("visible_text",""))[:50000]]).lower()
        brands=[x for x in BRAND_KEYWORDS if brand_present(x,blob)]
        mism=(self.results.get("identity_semantic_v18",{}) or {}).get("brand_mismatches") or []
        if mism and logos:
            self.add_finding("Görsel marka kimliği + domain uyuşmazlığı","high",
                "DOM içindeki logo/brand göstergeleri ile marka-domain uyuşmazlığı birlikte gözlendi.",
                "phishing",json.dumps({"brands":brands[:10],"logos":logos[:8],"page_root":root},ensure_ascii=False),.90)
        roots=Counter(registrable_domain_v21(urlparse(x).hostname or "") for x in assets if urlparse(x).hostname)
        self.results["visual_impersonation_v24"]={"page_root":root,"brand_tokens":brands[:20],"logo_candidates":logos[:20],
            "asset_roots":roots.most_common(15),"screenshot_sha256":b.get("screenshot_sha256"),
            "note":"Görsel/DOM kanıtı tek başına güvenlik hükmü değildir."}

