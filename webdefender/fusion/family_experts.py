"""Threat-family expert and semantic-analysis mixin.

Experts consume observations/canonical evidence and emit hypotheses. They do
not own the final EngineDecision.
"""
from ..analyzer.url_domain import ARCHIVE_EXTENSIONS
from ..analyzer.url_domain import DANGEROUS_EXTENSIONS
from ..analyzer.url_domain import SHORTENER_HOSTS
from ..analyzer.url_domain import full_decode
from ..guards.pipeline import reject
import requests
from ..analyzer.url_domain import host_is_raw_ip
from ..metadata import APP_VERSION
import difflib, os
import re, math, hashlib, json
from urllib.parse import urlparse, urljoin
from collections import Counter

from ..analyzer.url_domain import get_root_domain, get_canonical_root, severity_weight
from ..analyzer.identity import (
    BRAND_KEYWORDS, LEGITIMATE_BRAND_DOMAINS, brand_present, legitimate_brand_root
)

class ThreatFamilyExpertsMixin:
    def check_phishing_heuristics(self, url):
        p           = urlparse(url)
        host        = p.hostname or ""
        path        = p.path
        is_ip       = host_is_raw_ip(host)
        root        = get_root_domain(host)
        decoded_url = full_decode(url)
        scheme      = p.scheme.lower()

        score   = 0
        signals = []

        # 1. Ham IP adresi
        if is_ip:
            score += 40
            signals.append(f"Ham IP adresi: {host}")
            self.add_finding(
                "Ham IP adresi ile erişim", "critical",
                "Meşru kurumsal siteler asla ham IP adresi üzerinden hizmet vermez. "
                "Phishing/malware altyapısının güçlü göstergesidir.",
                "phishing", f"Host: {host}", 0.95,
            )

        # 2. HTTP + login sayfası
        login_re = re.compile(
            r"(signin|sign.in|login|auth|account|verify|secure|giri[sş])", re.I,
        )
        if scheme == "http" and login_re.search(decoded_url):
            score += 35
            signals.append("HTTP üzerinden kimlik doğrulama sayfası")
            self.add_finding(
                "HTTP üzerinden giriş/kimlik doğrulama sayfası", "critical",
                "Şifresiz HTTP bağlantısı üzerinden giriş sayfası sunuluyor. "
                "Kimlik bilgileri ağda açık metin olarak iletilir.",
                "phishing", f"Scheme: {scheme} | Path: {path}", 1.0,
            )

        # 3. Marka taklidi (domain impersonation)
        found_brands = []
        for brand in BRAND_KEYWORDS:
            bc = brand.replace("-", "").replace(".", "")
            hc = host.replace("-",  "").replace(".", "")
            if bc in hc:
                real = any(
                    host.endswith(ld) or root == ld
                    for ld in LEGITIMATE_BRAND_DOMAINS
                    if brand_present(brand, ld)
                )
                if not real:
                    found_brands.append(brand)

        if found_brands:
            score += 35
            signals.append(f"Marka taklidi: {', '.join(found_brands)}")
            self.add_finding(
                f"Marka taklidi (Domain Impersonation): {', '.join(found_brands)}", "critical",
                "Domain adı tanınan bir markayı taklit ediyor ancak gerçek domain değil. "
                "Typosquatting veya brand impersonation saldırısının göstergesidir.",
                "phishing",
                f"Host: {host} | Markalar: {', '.join(found_brands)}",
                0.95,
            )

        # 4. Marka adı path/param'da var ama host IP/sahte
        brand_in_path   = self.results["url_intelligence"].get("brand_in_path",   [])
        brand_in_params = self.results["url_intelligence"].get("brand_in_params",  [])
        all_refs        = brand_in_path + brand_in_params

        if all_refs and (is_ip or root not in LEGITIMATE_BRAND_DOMAINS):
            score += 30
            signals.append(f"IP/sahte host + path/param'da marka: {', '.join(set(all_refs))}")
            already = any(
                f["title"].startswith("Credential Harvesting")
                for f in self.results["findings"]
            )
            if not already:
                self.add_finding(
                    "Marka referansı + sahte host (Phishing Tuzağı)", "critical",
                    "Sahte veya IP tabanlı bir host üzerinden tanınan marka adlarına atıf yapılıyor. "
                    "Kullanıcıyı kandırmak için tasarlanmış phishing tekniğidir.",
                    "phishing",
                    f"Host: {host} | Refs: {', '.join(set(all_refs))[:300]}",
                    0.96,
                )

        # 5. URL uzunluğu
        if len(url) > 100:
            score += 5
            signals.append(f"Uzun URL ({len(url)} karakter)")

        # 6. Aşırı alt domain
        subdomain_count = len(host.split(".")) - 2 if not is_ip else 0
        if subdomain_count >= 3:
            score += 15
            signals.append(f"Çok sayıda alt domain ({subdomain_count})")
            self.add_finding(
                "Aşırı alt domain kullanımı", "medium",
                "URL'de anormal sayıda alt domain bulunuyor. "
                "Gerçek domain izlenimi yaratmak için kullanılan phishing tekniğidir.",
                "phishing", host, 0.80,
            )

        # 7. @ işareti
        if "@" in p.netloc:
            score += 30
            signals.append("URL'de @ işareti")
            self.add_finding(
                "URL'de @ işareti tespit edildi", "high",
                "@ işaretinden önce gösterilen domain yanıltıcı olabilir; "
                "tarayıcı @ sonrasını gerçek host olarak kullanır.",
                "phishing", p.netloc, 1.0,
            )

        # 8. Punycode / IDN homograph
        if "xn--" in host.lower():
            score += 20
            signals.append("Punycode (IDN) domain")
            self.add_finding(
                "Punycode/IDN domain tespit edildi", "high",
                "Domain görsel olarak tanınan bir markayı taklit eden Punycode karakterler içerebilir "
                "(homograph saldırısı).",
                "phishing", host, 0.85,
            )

        # 9. Şüpheli keyword kombinasyonu
        kw_re = re.compile(
            r"(secure|update|verify|confirm|account|suspend|unusual|"
            r"alert|limited|validate|recover|unlock|free|win|prize|"
            r"güncelle|doğrula|hesap|askıya|uyarı|ücretsiz|kazan)",
            re.I,
        )
        kw_hits = list(set(kw_re.findall(decoded_url)))
        if len(kw_hits) >= 2:
            score += 10
            signals.append(f"Şüpheli keyword kombinasyonu: {', '.join(kw_hits)}")

        # Bilinen marka adının hostname içinde ek karakter/rakamla kullanılması.
        host_l=(host or "").lower()
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, host_l) and not legitimate_brand_root(brand, get_root_domain(host_l)):
                # Örn. shopee1.example gibi. Marka tokeni tek başına hüküm değildir.
                if brand in host_l:
                    self.add_finding(
                        f"Alan adında marka benzeri ifade: {brand}", "medium",
                        f"Hostname '{host}' içinde '{brand}' ifadesi bulunuyor ancak registrable domain markanın bilinen resmi domainlerinden biri değil.",
                        "phishing", f"host={host}; brand={brand}", 0.82)
                    signals.append(f"brand-like hostname: {brand}")
                    break

        self.results["phishing_signals"] = signals

        # Genel phishing özet bulgusu
        if score >= 50 and not any(
            f["title"].startswith("YÜKSEK RİSK")
            for f in self.results["findings"]
        ):
            self.add_finding(
                "YÜKSEK RİSK: Phishing Sitesi Özellikleri Tespit Edildi", "critical",
                f"Bu URL {score} puanlık phishing sinyal skoru aldı. "
                f"Sinyaller: {'; '.join(signals)}",
                "phishing", "; ".join(signals), 0.97,
            )

    def check_page_phishing_signals(self, html, base_url):
        host = urlparse(base_url).hostname or ""
        root = get_root_domain(host)
        soup = BeautifulSoup(html, "html.parser")

        # ── Marka görseli kontrolü ─────────────────────────────────────────
        img_text = " ".join(
            img.get("alt", "").lower() + " " + img.get("src", "").lower()
            for img in soup.find_all("img")
        )
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, img_text) and not legitimate_brand_root(brand, root):
                self.add_finding(
                    f"Sahte marka görseli: {brand}", "high",
                    f"Sayfa içeriğinde '{brand}' markasına ait görsel referans var "
                    f"ancak host ({host}) gerçek domain değil.",
                    "phishing", f"img references: {brand}", 0.85,
                )
                break

        # ── Form analizi: credential phishing ─────────────────────────────
        for form in soup.find_all("form"):
            action = full_decode(form.get("action", "")).lower()
            inputs      = form.find_all("input")
            input_types = [i.get("type", "").lower() for i in inputs]
            input_names = " ".join(i.get("name", "").lower() for i in inputs)

            has_password = "password" in input_types
            has_user     = any(
                n in input_names
                for n in ("email", "user", "login", "username", "phone", "mail", "tel")
            )

            if has_password and has_user:
                action_host = urlparse(urljoin(base_url, action)).hostname or ""
                if action_host and action_host != host:
                    self.add_finding(
                        "Kimlik bilgisi formu harici hosta gönderiyor", "critical",
                        "Şifre + kullanıcı adı içeren form sayfanın hostundan farklı bir "
                        "hedefe gönderiyor. Credential phishing'in kesin göstergesidir.",
                        "phishing",
                        f"Form action: {action[:200]} | Sayfa host: {host}",
                        0.99,
                    )
                elif host_is_raw_ip(host):
                    self.add_finding(
                        "IP tabanlı sitede kimlik bilgisi formu", "critical",
                        "Ham IP adresi üzerinden çalışan sitede email/şifre toplayan form var.",
                        "phishing", f"Form action: {action[:200]}", 0.98,
                    )

        # ── Sosyal mühendislik içerik analizi ─────────────────────────────
        urgency_re = re.compile(
            r"(hesab[ıi].{0,40}(askıya|donduruldu|kapatılacak|bloke)|"
            r"kimli[gğ]inizi.{0,30}do[gğ]rula|"
            r"your account.{0,40}(suspended|blocked|limited)|"
            r"verify.{0,30}identity|confirm.{0,30}account|"
            r"update.{0,30}(payment|billing|information)|"
            r"unusual.{0,30}activity|"
            r"güvenlik.{0,30}uyar|security.{0,30}alert)",
            re.I,
        )
        hits = urgency_re.findall(html)
        if hits:
            self.add_finding(
                "Sosyal mühendislik içeriği (Aciliyet/Baskı)", "high",
                "Kullanıcıyı panikletmeye yönlendiren ifadeler tespit edildi. "
                "Phishing sayfalarının tipik davranışıdır.",
                "phishing",
                "; ".join(set(m if isinstance(m, str) else m[0] for m in hits[:5])),
                0.88,
            )

        # ── Sayfa başlığında marka taklidi ────────────────────────────────
        title_tag  = soup.find("title")
        title_text = title_tag.get_text() if title_tag else ""
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, title_text) and not legitimate_brand_root(brand, root):
                self.add_finding(
                    f"Sayfa başlığında marka taklidi: {brand}", "high",
                    f"<title> etiketi '{brand}' içeriyor ama host gerçek domain değil.",
                    "phishing",
                    f"Title: {title_text[:100]} | Host: {host}",
                    0.87,
                )
                break

        # ── Favicon gerçek markadan çekiliyor mu? ─────────────────────────
        fav = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower())
        if fav:
            fav_href = fav.get("href", "")
            fav_host = urlparse(urljoin(base_url, fav_href)).hostname or ""
            if fav_host and fav_host != host:
                for brand in BRAND_KEYWORDS:
                    if brand in fav_host:
                        self.add_finding(
                            f"Favicon gerçek marka sitesinden çekiliyor: {brand}", "high",
                            "Sayfa ikonunu gerçek marka sitesinden çekiyor. "
                            "Meşru görünmek için kullanılan phishing tekniğidir.",
                            "phishing", fav_href[:200], 0.90,
                        )
                        break

    def check_suspicious_patterns(self, html):
        checks = [
            ("eval()",              r"\beval\s*\(",                                  "medium", "Dinamik JavaScript çalıştırma"),
            ("document.write",      r"document\.write\s*\(",                         "low",    "Dinamik HTML yazımı"),
            ("atob()",              r"\batob\s*\(",                                  "low",    "Base64 çözme"),
            ("String.fromCharCode", r"String[.]fromCharCode",                         "medium", "Kod gizleme"),
            ("document.cookie",     r"document\.cookie",                             "medium", "Cookie erişimi"),
            ("localStorage.get",    r"localStorage\.getItem\s*\(",                   "low",    "LocalStorage okuma"),
            ("window.location=",    r"window\.location\s*=|window\.location\.href\s*=","medium","JS yönlendirme"),
            ("shell_exec",          r"\bshell_exec\s*\(",                            "high",   "Sunucu komutu çalıştırma"),
            ("system()",            r"\bsystem\s*\(",                                "high",   "Sunucu komutu çalıştırma"),
            ("exec()",              r"\bexec\s*\(",                                  "high",   "Komut çalıştırma"),
            ("base64_decode",       r"\bbase64_decode\s*\(",                         "high",   "PHP base64 decode — kod gizleme"),
            ("keylogger keyword",   r"\bkeylogger\b",                                "high",   "Keylogger ifadesi"),
            ("backdoor keyword",    r"\bbackdoor\b",                                 "high",   "Backdoor ifadesi"),
        ]
        for name, pattern, sev, desc in checks:
            count = len(re.findall(pattern, html, re.I))
            if count:
                self.results["suspicious_patterns"].append({
                    "pattern": name, "count": count, "risk": sev, "description": desc,
                })

        # eval + obfuscation kombinasyonu
        has_eval = bool(re.search(r"\beval\s*\(", html, re.I))
        has_obf  = bool(re.search(r"\batob\s*\(|String[.]fromCharCode|unescape\s*\(", html, re.I))
        if has_eval and has_obf:
            self.add_finding(
                "JavaScript obfuscation sinyali (eval + decode)", "high",
                "eval() ile birlikte kod gizleme/çözme teknikleri görüldü. İncelenmelidir.",
                "javascript", "eval + obfuscation", 0.92,
            )

        # Cookie exfiltration
        if re.search(
            r"document\.cookie.{0,500}(?:fetch|XMLHttpRequest|sendBeacon|location)",
            html, re.I | re.S,
        ):
            self.add_finding(
                "Cookie Exfiltration sinyali", "high",
                "document.cookie ile birlikte ağ/yönlendirme API'si yakın bağlamda görüldü.",
                "javascript", "document.cookie + network API", 0.90,
            )

        # Keylogger davranışı (keydown + network)
        if re.search(
            r"(?:keydown|keypress|addEventListener\s*\(\s*['\"]key).{0,500}"
            r"(?:fetch|XMLHttpRequest|sendBeacon|location)",
            html, re.I | re.S,
        ):
            self.add_finding(
                "Keylogger davranış sinyali", "critical",
                "Klavye olayı dinleyicisi + ağ isteği birlikte tespit edildi. "
                "Kullanıcı girişlerini çalmaya yönelik teknik olabilir.",
                "javascript", "keyevent + network", 0.88,
            )

    def check_advanced_defender(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        host = (urlparse(base_url).hostname or "").lower()
        root = get_root_domain(host)
        defender = self.results["defender"]

        # 1) İndirme bağlantıları. Dosyayı indirmiyoruz/çalıştırmıyoruz; yalnızca link davranışını inceliyoruz.
        for a in soup.find_all("a", href=True)[:500]:
            href = urljoin(base_url, a.get("href", ""))
            path = urlparse(href).path.lower()
            ext = os.path.splitext(path)[1]
            download_attr = a.has_attr("download")
            if ext in DANGEROUS_EXTENSIONS or ext in ARCHIVE_EXTENSIONS or download_attr:
                item = {"url": href[:1200], "extension": ext, "download_attribute": download_attr,
                        "dangerous_type": ext in DANGEROUS_EXTENSIONS,
                        "external": (urlparse(href).hostname or "") != host}
                self.results["downloads"].append(item)
        dangerous = [x for x in self.results["downloads"] if x["dangerous_type"]]
        if dangerous:
            self.add_finding("Çalıştırılabilir/aktif içerik indirme bağlantısı", "high",
                f"Sayfada {len(dangerous)} adet çalıştırılabilir veya aktif içerik türünde indirme bağlantısı bulundu. Dosya otomatik olarak indirilmedi.",
                "malware", "; ".join(x["url"] for x in dangerous[:5]), 0.86)

        # 2) Meta refresh / JS redirect / popup / otomatik tetikleme davranışları.
        meta_refresh=[]
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content=meta.get("content", "")
                if "url=" in content.lower(): meta_refresh.append(content[:500])
        if meta_refresh:
            self.add_finding("Meta Refresh yönlendirmesi", "medium",
                "Sayfa tarayıcıyı meta refresh ile başka hedefe yönlendirebilir.", "redirect",
                "; ".join(meta_refresh[:5]), 0.82)

        js_redirect = bool(re.search(r"(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()", html, re.I))
        popup = bool(re.search(r"\bwindow\.open\s*\(", html, re.I))
        dyn_script = bool(re.search(r"createElement\s*\(\s*['\"]script['\"]|\.src\s*=.{0,250}(?:https?:)?//", html, re.I|re.S))
        if dyn_script:
            self.add_finding("Dinamik harici script yükleme davranışı", "medium",
                "JavaScript çalışma anında script oluşturuyor veya harici script adresi atıyor.",
                "javascript", "dynamic script loader", 0.78)

        # 3) Hassas veri erişimi + ağ aktarımı korelasyonu.
        reads_cookie = bool(re.search(r"document\.cookie", html, re.I))
        reads_storage = bool(re.search(r"(?:localStorage|sessionStorage)\.(?:getItem|\w+)", html, re.I))
        clipboard = bool(re.search(r"navigator\.clipboard|clipboardData", html, re.I))
        key_events = bool(re.search(r"(?:keydown|keyup|keypress|input).{0,180}(?:addEventListener|onkeydown|onkeyup|onkeypress|oninput)|addEventListener\s*\(\s*['\"](?:keydown|keyup|keypress|input)", html, re.I|re.S))
        network = bool(re.search(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket\s*\(|\.send\s*\(", html, re.I))
        obfuscation = bool(re.search(r"\beval\s*\(|\batob\s*\(|String[.]fromCharCode|unescape\s*\(|decodeURIComponent\s*\(", html, re.I))
        if (reads_cookie or reads_storage) and network and obfuscation:
            self.add_finding("Token/Cookie veri sızdırma korelasyonu", "critical",
                "Depolama/cookie erişimi, ağ gönderimi ve kod gizleme davranışları birlikte görüldü.",
                "credential_theft", "storage/cookie + network + obfuscation", 0.94)
        if key_events and network and obfuscation:
            self.add_finding("Girdi yakalama ve aktarım korelasyonu", "critical",
                "Klavye/girdi dinleme, ağ aktarımı ve obfuscation birlikte tespit edildi.",
                "credential_theft", "input events + network + obfuscation", 0.93)
        if clipboard and network:
            self.add_finding("Clipboard erişimi + ağ iletişimi", "high",
                "Sayfa pano verisine erişim ve ağ iletişimi davranışlarını birlikte içeriyor.",
                "privacy", "clipboard + network", 0.82)

        # 4) Credential form derin analizi.
        credential_forms=0; external_credential_forms=0; insecure_credential_forms=0
        for form in soup.find_all("form")[:100]:
            inputs=form.find_all(["input","textarea"])
            types=[(i.get("type") or "text").lower() for i in inputs]
            names=" ".join((i.get("name") or "")+" "+(i.get("autocomplete") or "") for i in inputs).lower()
            has_secret = "password" in types or bool(re.search(r"pass|otp|pin|cvv|cvc|card|token", names))
            has_identity = bool(re.search(r"email|user|login|phone|mail|account|kart|card", names))
            if has_secret and has_identity:
                credential_forms += 1
                action=urljoin(base_url, form.get("action") or base_url)
                ahost=(urlparse(action).hostname or host).lower()
                if get_root_domain(ahost) != root:
                    external_credential_forms += 1
                if urlparse(action).scheme != "https": insecure_credential_forms += 1
        if external_credential_forms:
            self.add_finding("Credential form farklı registrable domaine gönderiyor", "critical",
                f"{external_credential_forms} kimlik bilgisi formu sayfanın ana domaininden farklı bir domaine veri gönderiyor.",
                "credential_theft", f"page={root}; external_forms={external_credential_forms}", 0.98)
        if insecure_credential_forms:
            self.add_finding("Credential form HTTPS kullanmıyor", "critical",
                f"{insecure_credential_forms} hassas formun hedefi HTTPS değil.", "credential_theft",
                f"insecure_forms={insecure_credential_forms}", 0.99)

        # 5) Marka taklidi: title + görünür metin + form + domain kombinasyonu.
        title=(soup.title.get_text(" ", strip=True) if soup.title else "").lower()
        visible=soup.get_text(" ", strip=True).lower()[:250000]
        claimed=[]
        for brand in BRAND_KEYWORDS:
            if brand_present(brand, title) or brand_present(brand, visible):
                if not legitimate_brand_root(brand, root): claimed.append(brand)
        if claimed and credential_forms:
            self.add_finding("Marka taklidi + kimlik bilgisi toplama", "critical",
                "Sayfa tanınan marka isimleri kullanıyor ve kimlik bilgisi isteyen form içeriyor; domain ilgili markanın bilinen domaini değil.",
                "phishing", f"host={host}; brands={', '.join(sorted(set(claimed))[:8])}", 0.96)

        # 6) URL kısaltıcı / data URI / blob tabanlı indirme ve otomatik click sinyalleri.
        if root in SHORTENER_HOSTS:
            self.add_finding("URL kısaltıcı kullanımı", "medium",
                "Kısaltılmış URL gerçek hedefi kullanıcıdan gizleyebilir.", "url", host, 0.72)
        data_blob = bool(re.search(r"(?:href|src)\s*=\s*['\"](?:data:|blob:)", html, re.I))
        auto_click = bool(re.search(r"\.click\s*\(\)", html, re.I))
        if data_blob and auto_click:
            self.add_finding("Tarayıcı içinde üretilen otomatik indirme davranışı", "high",
                "data:/blob: kaynağı ile programatik click davranışı birlikte görüldü.",
                "malware", "data/blob + .click()", 0.88)

        # 7) V13.7 Sosyal mühendislik + malware aile sinyalleri.
        # Web taraması kanal/kurban bağlamını her zaman bilemez. Spear phishing, smishing,
        # vishing ve whaling yalnızca sayfa üzerinde destekleyici kanıt varsa "olası" olarak işaretlenir.
        social = self.results["defender"].setdefault("social_engineering", [])
        malware_families = self.results["defender"].setdefault("malware_families", [])
        lower = (title + " " + visible)[:250000]

        def family(name, confidence, evidence, category="social_engineering"):
            target = social if category == "social_engineering" else malware_families
            if not any(x.get("type") == name for x in target):
                target.append({"type": name, "confidence": round(confidence, 2), "evidence": evidence[:600]})

        # Phishing is supported by credential collection + impersonation/redirect evidence.
        if credential_forms and (claimed or external_credential_forms or js_redirect or meta_refresh):
            family("phishing", .94 if claimed or external_credential_forms else .78,
                   f"credential_forms={credential_forms}; brands={claimed[:5]}; external_forms={external_credential_forms}")

        # Targeted/whaling language is contextual evidence, never a definitive attribution.
        targeted_words = re.findall(r"\b(?:employee|staff|personnel|muhasebe|finans|ik|human resources|kurumsal|şirket hesabı|company account)\b", lower, re.I)
        executive_words = re.findall(r"\b(?:ceo|cfo|cto|chief executive|chief financial|genel müdür|yönetim kurulu|director|executive)\b", lower, re.I)
        if credential_forms and targeted_words:
            family("possible_spear_phishing", .66, "targeted language: " + ", ".join(sorted(set(targeted_words))[:8]))
        if credential_forms and executive_words:
            family("possible_whaling", .72, "executive language: " + ", ".join(sorted(set(executive_words))[:8]))

        # Channel references can suggest smishing/vishing, but a URL scan cannot prove delivery channel.
        sms_words = re.findall(r"\b(?:sms|whatsapp|mesaj|text message|doğrulama kodu|sms kodu)\b", lower, re.I)
        voice_words = re.findall(r"\b(?:telefonla ara|call us|call now|müşteri hizmetleri|polis|savcı|bankacı|kargo görevlisi)\b", lower, re.I)
        if credential_forms and sms_words:
            family("possible_smishing_landing_page", .60, "messaging/SMS context: " + ", ".join(sorted(set(sms_words))[:8]))
        if credential_forms and voice_words:
            family("possible_vishing_support_page", .58, "voice/call context: " + ", ".join(sorted(set(voice_words))[:8]))

        bait_words = re.findall(r"\b(?:free download|ücretsiz indir|crack|keygen|bedava oyun|ücretsiz film|hediye|ödül|prize|gift)\b", lower, re.I)
        if bait_words and (dangerous or self.results.get("downloads")):
            family("baiting", .82, "lure + download: " + ", ".join(sorted(set(bait_words))[:8]))
            self.add_finding("Yemleme / baiting sinyali", "high",
                "Ücretsiz içerik/ödül yemi ile indirme davranışı aynı sayfada birlikte görüldü.",
                "social_engineering", ", ".join(sorted(set(bait_words))[:8]), .82)

        # Browser-deliverable malware families are heuristic labels, not binary/file-signature verdicts.
        ransom_words = re.findall(r"\b(?:ransom|bitcoin payment|pay bitcoin|files encrypted|dosyalarınız şifrelendi|fidye|decrypt key)\b", lower, re.I)
        if ransom_words and dangerous:
            family("possible_ransomware_delivery", .78, ", ".join(sorted(set(ransom_words))[:8]), "malware")
        if dangerous and bait_words:
            family("possible_trojan_delivery", .76, "executable download disguised by lure", "malware")

        spyware_api = bool(re.search(r"getUserMedia\s*\(|getDisplayMedia\s*\(|MediaRecorder\s*\(|geolocation\.getCurrentPosition", html, re.I))
        if spyware_api and network:
            family("spyware_like_web_behavior", .74, "sensitive browser API + network", "malware")
            self.add_finding("Casus yazılım benzeri web davranışı", "high",
                "Kamera/mikrofon/ekran/konum gibi hassas tarayıcı API'leri ile ağ iletişimi birlikte görüldü.",
                "privacy", "sensitive browser API + network", .74)
        if key_events and network:
            family("keylogger_like_behavior", .86 if obfuscation else .70, "keyboard/input capture + network", "malware")
        if popup:
            family("adware_like_behavior", .55, "window.open / popup behavior", "malware")

        # Worm, DDoS and MITM cannot be established from a single passive page scan.
        # We expose related observable signals without falsely naming an attack.
        if self.results["domain_info"]["protocol"] == "https" and self.results["ssl_info"].get("checked") and not self.results["ssl_info"].get("valid"):
            self.add_finding("TLS güven zinciri problemi", "high",
                "TLS doğrulaması başarısız. Bu durum MITM kanıtı değildir ancak güvenli kanal doğrulanamadı.",
                "transport_security", self.results["ssl_info"].get("error", "")[:400], .88)

        # 8) Korelasyon motoru: tek zayıf sinyal yerine birleşik davranışlar.
        correlations=[]
        if claimed and credential_forms: correlations.append("brand_impersonation + credential_form")
        if external_credential_forms: correlations.append("credential_form + external_destination")
        if obfuscation and network and (reads_cookie or reads_storage): correlations.append("obfuscation + sensitive_storage + network")
        if key_events and network: correlations.append("input_capture + network")
        if dangerous and (obfuscation or js_redirect): correlations.append("dangerous_download + scripted_behavior")
        if meta_refresh and self.results["http"]["redirect_count"]: correlations.append("meta_redirect + http_redirect_chain")
        defender["correlations"] = correlations
        if len(correlations) >= 2:
            self.add_finding("Çoklu tehdit davranışı korelasyonu", "critical",
                f"Birbirini güçlendiren {len(correlations)} bağımsız davranış zinciri tespit edildi.",
                "behavior", "; ".join(correlations), 0.95)

        types=[]
        cats={f.get("category") for f in self.results["findings"]}
        if "phishing" in cats or "credential_theft" in cats: types.append("PHISHING / CREDENTIAL THEFT")
        if "malware" in cats: types.append("MALICIOUS DOWNLOAD / MALWARE DELIVERY")
        if "javascript" in cats or "behavior" in cats: types.append("SUSPICIOUS WEB BEHAVIOR")
        if "privacy" in cats: types.append("PRIVACY / DATA EXFILTRATION RISK")
        if "social_engineering" in cats or defender.get("social_engineering"): types.append("SOCIAL ENGINEERING")
        if defender.get("malware_families") and "MALICIOUS DOWNLOAD / MALWARE DELIVERY" not in types: types.append("MALWARE-LIKE BEHAVIOR")
        defender["threat_types"] = types
        defender["recommendations"] = (["Bu sayfaya parola, kart veya kişisel bilgi girmeyin.", "Dosya indirmeyin veya çalıştırmayın."] if types else ["Belirgin zararlı davranış korelasyonu bulunmadı; yine de alan adını ve içeriği doğrulayın."])

    def check_passive_defender(self, url):
        """İçerik erişilemese bile yalnızca yerel URL/DNS/TLS/ağ metadatasını değerlendirir.
        Bu katman phishing/malware hükmü üretmez; sadece pasif risk seviyesini yükseltir.
        """
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        root = self.results["domain_info"].get("root_domain") or host
        labels = [x for x in host.split(".") if x]
        root_label = root.split(".")[0] if root else ""
        signals=[]
        score=0

        def sig(code, points, text, evidence=""):
            nonlocal score
            score += points
            signals.append({"code":code,"points":points,"description":text,"evidence":evidence})

        # URL/host yapısı. Bunlar kanıt değil, risk göstergesidir.
        if len(host) >= 55: sig("long_hostname", 7, "Hostname olağandışı uzun.", str(len(host)))
        if len(labels) >= 5: sig("deep_subdomain", 8, "Çok katmanlı subdomain yapısı kullanılıyor.", str(len(labels)))
        if host.startswith("xn--") or ".xn--" in host: sig("punycode", 14, "Punycode/IDN hostname kullanılıyor.", host)
        hyphens=host.count("-")
        if hyphens >= 4: sig("many_hyphens", 6, "Hostname çok sayıda tire içeriyor.", str(hyphens))
        digits=sum(ch.isdigit() for ch in host)
        if digits >= 6: sig("many_digits", 5, "Hostname çok sayıda rakam içeriyor.", str(digits))
        if len(url) >= 180: sig("long_url", 6, "URL olağandışı uzun.", str(len(url)))
        if "@" in urlparse(url).netloc: sig("userinfo", 18, "URL authority bölümünde @ işareti var.", p.netloc)

        # Basit Shannon entropy. Random/otomatik üretilmiş label için yardımcı sinyal.
        if root_label:
            counts={c:root_label.count(c) for c in set(root_label)}
            entropy=-sum((n/len(root_label))*math.log2(n/len(root_label)) for n in counts.values())
            if len(root_label) >= 14 and entropy >= 3.6:
                sig("high_entropy_label", 7, "Ana domain etiketi yüksek karakter entropisine sahip.", f"entropy={entropy:.2f}")

        ui=self.results["url_intelligence"]
        if ui.get("suspicious_tld"): sig("suspicious_tld", 8, "TLD yerel risk listesinde.", root)
        if ui.get("double_encoded"): sig("double_encoding", 12, "Çok katmanlı URL encoding bulundu.")
        if ui.get("redirect_parameters"): sig("redirect_parameter", 6, "URL yönlendirme parametresi taşıyor.")
        if ui.get("sensitive_parameter_names"): sig("sensitive_parameter", 7, "URL hassas isimli parametre taşıyor.")
        if ui.get("brand_in_path") or ui.get("brand_in_params"):
            sig("brand_reference", 12, "URL yolu/parametresi bilinen marka adı içeriyor.")
        if ui.get("typosquatting_signals"):
            sig("typosquatting", 18, "Marka benzerliği/typosquatting sinyali bulundu.", "; ".join(map(str,ui.get("typosquatting_signals",[])[:3])))

        # Ağ metadatası. Connection refused tek başına kötü niyet değildir.
        http=self.results["http"]
        probe=self.results.get("network_probe",{})
        ports=probe.get("ports",{})
        p80=ports.get("80",{})
        p443=ports.get("443",{})
        # Kapalı/refused port tek başına kötü niyet göstergesi değildir; puan üretmez.
        # Yalnızca teşhis sinyali olarak raporlanır. Timeout da saldırı kanıtı değildir.
        if p80.get("status") in {"refused","timeout","network_error"}:
            signals.append({"code":"port80_"+p80.get("status","unknown"),"points":0,"description":"TCP/80 erişim durumu: "+p80.get("status","unknown"),"evidence":p80.get("error","")[:160]})
        if p443.get("status") in {"refused","timeout","network_error"}:
            signals.append({"code":"port443_"+p443.get("status","unknown"),"points":0,"description":"TCP/443 erişim durumu: "+p443.get("status","unknown"),"evidence":p443.get("error","")[:160]})
        if http.get("failure_kind") == "tls": sig("tls_transport_failure", 4, "TLS taşıma katmanında hata oluştu.")
        ssl_info=self.results["ssl_info"]
        if p.scheme=="https" and ssl_info.get("checked") and not ssl_info.get("valid"):
            sig("tls_unavailable", 6, "HTTPS hedefinde TLS doğrulaması tamamlanamadı.", ssl_info.get("error","")[:160])
        if not self.results["dns"].get("resolved"):
            sig("dns_failure", 5, "DNS çözümlemesi başarısız.")

        # Birden çok bağımsız pasif sinyal birlikteyse korelasyon bonusu.
        independent=sum(1 for x in signals if x["points"] >= 7)
        if independent >= 3: score += 8
        score=min(score,100)
        classification = "low"
        if score >= 55: classification="high"
        elif score >= 30: classification="elevated"
        elif score >= 15: classification="guarded"
        pa={"score":score,"signals":signals,"classification":classification}
        self.results["defender"]["passive_analysis"]=pa

        if score >= 55:
            self.add_finding("Pasif altyapı/URL riski yüksek", "high",
                "İçerikten bağımsız birden fazla URL, DNS, TLS veya ağ sinyali birlikte görüldü. Bu bulgu malware/phishing kanıtı değildir.",
                "passive", json.dumps(signals[:8], ensure_ascii=False), 0.72)
        elif score >= 30:
            self.add_finding("Pasif risk sinyalleri", "medium",
                "URL ve ağ metadatasında dikkat gerektiren birden fazla sinyal görüldü.",
                "passive", json.dumps(signals[:8], ensure_ascii=False), 0.65)

    def build_multi_evidence_fusion(self):
        """V16 Multi-Evidence Fusion Engine.
        Tek bulguya hüküm vermez. Aynı saldırı hipotezini destekleyen farklı uzman
        ailelerinden gelen kanıtları korele eder. Puanlar olasılık değildir.
        """
        findings=self.results.get("findings",[])
        sev={"critical":32,"high":20,"medium":10,"low":3,"info":1}

        def expert_for(f):
            cat=(f.get("category") or "").lower(); title=(f.get("title") or "").lower()
            if "phishtank" in title or "openphish" in title or "urlhaus" in title or "threatfox" in title: return "threat_intel"
            if cat in {"credential_theft","forms"}: return "credential"
            if cat in {"malware"}: return "malware"
            if cat in {"javascript","behavior"}: return "javascript_runtime"
            if cat in {"privacy"}: return "network_exfil"
            if cat in {"redirect"}: return "redirect"
            if cat in {"phishing","social_engineering"}: return "brand_social"
            if cat in {"url","passive"}: return "url_domain"
            if cat in {"network","tls","transport_security"}: return "infrastructure"
            return "other"

        hypotheses={
            "Phishing / Marka Taklidi":{"cats":{"phishing","social_engineering"},"experts":{"brand_social","url_domain","redirect","credential","threat_intel"}},
            "Kimlik Bilgisi Hırsızlığı":{"cats":{"credential_theft","forms","phishing"},"experts":{"credential","brand_social","redirect","network_exfil","threat_intel"}},
            "Malware / Zararlı İndirme":{"cats":{"malware","javascript","behavior"},"experts":{"malware","javascript_runtime","redirect","threat_intel","network_exfil"}},
            "Şüpheli JavaScript / Davranış":{"cats":{"javascript","behavior"},"experts":{"javascript_runtime","network_exfil","redirect"}},
            "Gizlilik / Veri Sızdırma Riski":{"cats":{"privacy","credential_theft"},"experts":{"network_exfil","credential","javascript_runtime"}},
            "Yönlendirme Kötüye Kullanımı":{"cats":{"redirect","phishing","malware"},"experts":{"redirect","brand_social","javascript_runtime","malware"}},
        }
        expert_rows={}
        for f in findings:
            if f.get("score_eligible_v322") is False: continue
            e=expert_for(f)
            if e in {"other","infrastructure"}: continue
            # Header/TLS/configuration bulguları threat fusion'a girmez.
            if (f.get("category") or "").lower() in {"headers","cookies","cors","csp","tls","transport_security","network"}: continue
            val=sev.get(f.get("severity"),0)*float(f.get("confidence",1))
            expert_rows.setdefault(e,[]).append((val,f))

        expert_summary=[]
        for e,rows in expert_rows.items():
            rows=sorted(rows,key=lambda x:x[0],reverse=True)
            # Aynı uzmandan gelen tekrarları azalan ağırlıkla say.
            score=min(100, round(sum(v*w for (v,_),w in zip(rows,[1,.45,.25,.15,.1]))))
            expert_summary.append({"expert":e,"score":score,"evidence":[r[1] for r in rows[:4]]})
        expert_summary.sort(key=lambda x:x["score"],reverse=True)

        category_rows=[]; chains=[]
        for name,h in hypotheses.items():
            relevant=[]; experts=set()
            for f in findings:
                if f.get("score_eligible_v322") is False: continue
                cat=(f.get("category") or "").lower(); e=expert_for(f)
                if cat in h["cats"] and e in h["experts"]:
                    relevant.append(f); experts.add(e)
            vals=sorted([sev.get(f.get("severity"),0)*float(f.get("confidence",1)) for f in relevant], reverse=True)
            base=sum(v*w for v,w in zip(vals,[1,.55,.30,.20,.12,.08]))
            # Gerçek fusion bonusu sadece farklı uzmanlar aynı hipotezi doğrularsa gelir.
            independent=len(experts)
            bonus={0:0,1:0,2:14,3:28,4:40}.get(independent,48)
            score=min(100,round(base+bonus))
            if independent>=2:
                chains.append({"type":name,"experts":sorted(experts),"evidence_count":len(relevant),"score":score})
            category_rows.append({"name":name,"score":score,"independent_experts":independent,"experts":sorted(experts),"evidence":sorted(relevant,key=lambda f:{"critical":0,"high":1,"medium":2,"low":3}.get(f.get("severity"),9))[:6]})
        category_rows.sort(key=lambda x:x["score"],reverse=True)
        primary=category_rows[0] if category_rows else {"name":"","score":0,"independent_experts":0}

        # Tek uzman critical IOC ise yüksek olabilir; davranışsal iddiada iki bağımsız uzman tercih edilir.
        verified_ioc=any(f.get("score_eligible_v322") is not False and expert_for(f)=="threat_intel" and f.get("severity")=="critical" for f in findings)
        score=primary.get("score",0)
        if primary.get("independent_experts",0)<2 and not verified_ioc:
            score=min(score,39)
        verdict="critical" if score>=75 else "high" if score>=50 else "guarded" if score>=20 else "low" if score>0 else "no_evidence"
        fusion={"score":score,"verdict":verdict,"primary":primary.get("name","") if score else "","categories":category_rows,"experts":expert_summary,"chains":chains,"independent_experts":primary.get("independent_experts",0),"verified_ioc":verified_ioc}
        self.results["defender"]["fusion"]=fusion
        self.results["defender"]["correlations"]=[f"{c['type']}: {' + '.join(c['experts'])}" for c in chains]
        types=[c["name"] for c in category_rows if c["score"]>=20]
        self.results["defender"]["threat_types"]=types

    def source_level_behavior_guard_v322(self):
        """
        Remove/demote generic modern-web behavior at the source-of-truth finding layer.
        Hard IOC / explicit cross-origin credential exfil / malware-hash evidence is preserved.
        """
        causal=self._v322_sensitive_external_causal_chain()
        findings=list(self.results.get("findings") or [])
        kept=[]; suppressed=[]

        generic_titles=(
            "token/cookie veri sızdırma korelasyonu",
            "girdi yakalama ve aktarım korelasyonu",
            "çoklu tehdit davranışı korelasyonu",
            "çoklu davranış korelasyonu"
        )
        for f0 in findings:
            f=dict(f0)
            text=self._v322_blob(f)
            hard=False
            if hasattr(self,"_v321_is_hard_evidence"):
                try: hard=self._v321_is_hard_evidence(f)
                except Exception: hard=False
            hard = hard or any(x in text for x in (
                "urlhaus","threatfox","openphish","phishtank","sha256 ioc","sha-256 ioc",
                "malware hash","known malicious","cross-origin credential","credential exfil"))

            generic_title=any(t in text for t in generic_titles)
            generic_pattern=(
                (("storage" in text or "cookie" in text or "input event" in text or "girdi yakalama" in text)
                 and "network" in text)
                or ("dynamic script loader" in text)
            )

            if (generic_title or generic_pattern) and not hard and not causal:
                # Keep only as contextual telemetry; it must not enter threat-category/fusion scoring.
                f["severity"]="info"
                f["confidence"]=min(float(f.get("confidence") or .5),.20)
                f["score_eligible_v322"]=False
                f["source_guard_v322"]="generic_web_behavior_without_causal_exfil"
                suppressed.append(f)
                continue

            f["score_eligible_v322"]=True
            kept.append(f)

        # Score/fusion source of truth contains only eligible evidence.
        self.results["contextual_findings_v322"]=suppressed
        self.results["findings"]=kept
        report={"causal_sensitive_external_chain":causal,
                "score_eligible_findings":len(kept),
                "context_only_findings":len(suppressed)}
        self.results["source_level_behavior_guard_v322"]=report
        return report

    def phishing_sensor_observatory_v3231(self):
        """Explain what the phishing engine could actually observe.
        This is diagnostic only and never manufactures threat evidence.
        """
        b=self.results.get("browser") or {}
        h=self.results.get("http") or {}
        ip=self.results.get("independent_phishing_v323") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        sem=b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        hooks=b.get("runtime_hooks") or {}
        reqs=b.get("requests") or []

        def state(observed, available=True, detail=None):
            return {
                "state":"observed" if observed else ("not_observed" if available else "unavailable"),
                "detail":detail
            }

        inputs=sem.get("inputs") or []
        forms=b.get("forms") or self.results.get("forms") or []
        iframes=sem.get("iframes") or b.get("frames") or self.results.get("iframes") or []
        frame_surfaces=b.get("frame_surfaces") or []
        shadow_inputs=int(sem.get("shadow_input_count") or 0)
        shadow_forms=int(b.get("shadow_form_count") or 0)
        frame_sensitive=0
        for fs in frame_surfaces:
            for inp in (fs.get("inputs") or []):
                blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete")).lower()
                if str(inp.get("type","")).lower()=="password" or re.search(r"password|passwd|otp|one.?time|verification|pin|cvv|cvc|cc-number|card|iban|wallet",blob,re.I):
                    frame_sensitive+=1
        mutations=b.get("dom_mutations") or {}
        runtime_writes=(hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or [])
        browser_ok=bool(b.get("success"))
        http_ok=bool(h.get("body_analyzed") or h.get("success"))
        visible=sem.get("visible_text") or ""
        title=sem.get("title") or b.get("title") or h.get("title") or ""

        sensors={
          "http_body":state(http_ok, True, f"status={h.get('status') or h.get('status_code')}; content_type={h.get('content_type')}"),
          "browser_navigation":state(browser_ok, True, f"final_url={final}"),
          "rendered_dom":state(bool(visible or title or inputs or forms), browser_ok,
                               f"inputs={len(inputs)}; forms={len(forms)}; visible_chars={len(str(visible))}"),
          "iframes":state(bool(iframes or frame_surfaces), browser_ok, f"declared={len(iframes)}; inspected={len(frame_surfaces)}"),
          "shadow_dom":state(bool(shadow_inputs or shadow_forms), browser_ok, f"shadow_inputs={shadow_inputs}; shadow_forms={shadow_forms}"),
          "frame_credential_surface":state(bool(frame_sensitive), browser_ok, f"sensitive_controls={frame_sensitive}; diagnostic_only=true"),
          "credential_surface":state(bool(ip.get("credential_intent")), browser_ok,
                                     f"sensitive_count={ip.get('sensitive_count',0)}"),
          "dom_mutation":state(bool(mutations), browser_ok, str(mutations)[:1000]),
          "runtime_network":state(bool(reqs or runtime_writes), browser_ok,
                                  f"requests={len(reqs)}; runtime_writes={len(runtime_writes)}"),
          "cross_origin_sink":state(bool(ip.get("cross_form_count") or ip.get("cross_write_count")), browser_ok,
                                    f"cross_forms={ip.get('cross_form_count',0)}; cross_writes={ip.get('cross_write_count',0)}"),
          "identity":state(bool(ip.get("brand_claims")), browser_ok,
                           f"claims={ip.get('brand_claims',[])[:5]}"),
          "visual":state(bool(ip.get("visual_score")), browser_ok,
                         f"score={ip.get('visual_score',0)}; mismatch={ip.get('visual_mismatch',False)}")
        }

        unavailable=[k for k,v in sensors.items() if v["state"]=="unavailable"]
        not_observed=[k for k,v in sensors.items() if v["state"]=="not_observed"]
        observed=[k for k,v in sensors.items() if v["state"]=="observed"]

        # Diagnostic reason for low engine score. Absence is not safety.
        reasons=[]
        if not browser_ok:
            reasons.append("browser_navigation_unavailable")
            if b.get("decision")=="browser_timeout" or b.get("failure_kind") in ("browser_timeout","parent_worker_deadline"):
                reasons.append("browser_worker_timeout")
        if sensors["rendered_dom"]["state"]!="observed": reasons.append("rendered_dom_not_observed")
        if sensors["credential_surface"]["state"]!="observed": reasons.append("credential_surface_not_observed")
        if sensors["cross_origin_sink"]["state"]!="observed": reasons.append("cross_origin_sink_not_observed")
        if len(ip.get("decisive_experts") or [])<2: reasons.append("fewer_than_two_decisive_experts")

        report={
          "mode":"diagnostic_only",
          "final_url":final,
          "engine_only_score":int(ip.get("score") or 0),
          "engine_only_verdict":ip.get("verdict") or "not_run",
          "decisive_experts":ip.get("decisive_experts") or [],
          "sensors":sensors,
          "observed":observed,
          "not_observed":not_observed,
          "unavailable":unavailable,
          "diagnostic_reasons":reasons,
          "browser_decision":b.get("decision"),
          "browser_failure_kind":b.get("failure_kind"),
          "browser_timings_ms":b.get("timings_ms") or {},
          "tls_observation_mode":b.get("tls_observation_mode") or "strict_or_not_run",
          "static_http_dom_length":int((self.results.get("static_semantic_v3232") or {}).get("dom_length") or 0),
          "warning":"not_observed/unavailable never means safe"
        }
        self.results["phishing_observatory_v3231"]=report
        return report

    def credential_flow_deep_observatory_v32328(self):
        """V32.3.28 diagnostic lens for credential-flow misses.

        Never submits a form, clicks a live control, executes extracted source, or adds threat score.
        It compares verified static HTML with the rendered browser surface and reports exactly
        which credential-flow stage was observed or missed.
        """
        static=self.results.get("static_source_intelligence_v32317") or {}
        sem=self.results.get("static_semantic_v3232") or {}
        b=self.results.get("browser") or {}
        bsem=b.get("semantic_dom") or {}
        hooks=b.get("runtime_hooks") or {}
        page_url=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        page_root=get_root_domain(urlparse(page_url).hostname or "")

        def inp_rows(src):
            out=[]
            for x in (src or [])[:120]:
                if not isinstance(x,dict): continue
                blob=" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label","label","role")).lower()
                out.append({"type":x.get("type"),"name":x.get("name"),"id":x.get("id"),"descriptor":blob[:500],
                            "secret":bool(re.search(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|card|iban|seed|recovery",blob,re.I)),
                            "identity":bool(re.search(r"email|e-mail|username|user.?name|login|phone|mobile|account|müşteri|kullanıcı|telefon|eposta",blob,re.I))})
            return out

        static_inputs=inp_rows(sem.get("inputs") or [])
        rendered_inputs=inp_rows(bsem.get("inputs") or [])
        static_forms=static.get("forms") or []
        rendered_forms=b.get("forms") or []
        frame_surfaces=b.get("frame_surfaces") or []
        frame_inputs=[]
        for fr in frame_surfaces[:40]:
            for x in inp_rows(fr.get("inputs") or []):
                y=dict(x); y["frame_url"]=fr.get("url"); frame_inputs.append(y)

        flow=static.get("credential_flow_v32327") or {}
        sinks=[]
        for x in (flow.get("js_sink_literals") or []):
            if isinstance(x,dict): sinks.append(dict(x))
        runtime=[]
        for kind in ("fetches","xhr","beacons","form_submits"):
            for x in (hooks.get(kind) or [])[:80]:
                if isinstance(x,dict):
                    u=x.get("url") or x.get("action") or x.get("target") or ""
                    rr=get_root_domain(urlparse(urljoin(page_url,str(u))).hostname or "") if u else ""
                    runtime.append({"kind":kind,"url":str(u)[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root),
                                    "method":x.get("method")})

        script_text=""
        try:
            # bounded verified static source only; diagnostic extraction, never execution
            raw=(self.results.get("http") or {}).get("body") or self.results.get("raw_html") or ""
            if raw:
                sp=BeautifulSoup(str(raw)[:1500000],"html.parser")
                script_text="\n".join((z.string or z.get_text() or "")[:200000] for z in sp.find_all("script")[:160] if not z.get("src"))[:800000]
        except Exception:
            script_text=""
        # Fall back to already extracted static report if raw body is intentionally not retained.
        handler_patterns={
          "submit_listener":r"addEventListener\s*\(\s*['\"]submit|onsubmit\s*=",
          "click_listener":r"addEventListener\s*\(\s*['\"]click|onclick\s*=",
          "prevent_default":r"preventDefault\s*\(",
          "formdata":r"new\s+FormData\s*\(|FormData\s*\(",
          "password_value_read":r"password[^\n]{0,160}\.value|querySelector\s*\([^)]*password[^)]*\)[^\n]{0,120}\.value",
          "identity_value_read":r"(?:email|username|login)[^\n]{0,160}\.value",
          "network_write":r"fetch\s*\(|XMLHttpRequest|axios\.(?:post|put|patch)|sendBeacon\s*\(",
          "dynamic_dom":r"createElement\s*\(|innerHTML\s*=|insertAdjacentHTML\s*\("
        }
        handlers={k:bool(re.search(v,script_text,re.I)) if script_text else bool(flow.get("js_submit_handlers")) if k in ("submit_listener","click_listener","prevent_default") else False for k,v in handler_patterns.items()}

        static_secret=sum(1 for x in static_inputs if x["secret"]); static_ident=sum(1 for x in static_inputs if x["identity"])
        render_secret=sum(1 for x in rendered_inputs if x["secret"]); render_ident=sum(1 for x in rendered_inputs if x["identity"])
        frame_secret=sum(1 for x in frame_inputs if x["secret"]); frame_ident=sum(1 for x in frame_inputs if x["identity"])
        cross_runtime=[x for x in runtime if x.get("cross_root")]
        cross_static=[x for x in sinks if x.get("external")]
        source_seen=bool(static_secret or static_ident or static.get("credential_source") or flow.get("js_dynamic_credential"))
        rendered_seen=bool(render_secret or render_ident or frame_secret or frame_ident)
        handler_seen=bool(any(handlers.values()) or flow.get("js_submit_handlers"))
        sink_seen=bool(cross_runtime or cross_static or static.get("external_sensitive_forms"))

        if not ((self.results.get("http") or {}).get("body_analyzed") or (b.get("success"))): stage="observation_unavailable"
        elif not source_seen and not rendered_seen and bool((b.get("stateful_surface") or {}).get("interaction_gate_suspected")): stage="interaction_gated_surface_not_reached"
        elif not source_seen and not rendered_seen: stage="credential_surface_not_observed"
        elif source_seen and not rendered_seen: stage="static_surface_not_rendered_or_interaction_gated"
        elif rendered_seen and not handler_seen: stage="credential_surface_seen_handler_not_observed"
        elif handler_seen and not sink_seen: stage="handler_seen_destination_not_observed"
        elif sink_seen: stage="credential_flow_components_observed_check_causality_fusion"
        else: stage="inconclusive"

        report={
          "mode":"diagnostic_only_no_score", "version":APP_VERSION, "page_root":page_root, "miss_stage":stage,
          "static":{"inputs":len(static_inputs),"identity":static_ident,"secret":static_secret,"forms":len(static_forms),
                    "credential_source":bool(static.get("credential_source")),"auth_intent":bool(static.get("auth_intent")),
                    "js_dynamic_credential":bool(flow.get("js_dynamic_credential")),"js_submit_handlers":bool(flow.get("js_submit_handlers"))},
          "rendered":{"inputs":len(rendered_inputs),"identity":render_ident,"secret":render_secret,"forms":len(rendered_forms),
                      "shadow_inputs":int(bsem.get("shadow_input_count") or 0),"shadow_forms":int(b.get("shadow_form_count") or 0),
                      "frames_inspected":len(frame_surfaces),"frame_identity":frame_ident,"frame_secret":frame_secret},
          "handlers":handlers,
          "destinations":{"static_literals":sinks[:30],"static_cross_root":cross_static[:20],"runtime":runtime[:50],
                          "runtime_cross_root":cross_runtime[:20],"external_sensitive_forms":(static.get("external_sensitive_forms") or [])[:20]},
          "comparison":{"static_surface_seen":source_seen,"rendered_surface_seen":rendered_seen,"handler_seen":handler_seen,"sink_seen":sink_seen,
                        "dom_delta_inputs":len(rendered_inputs)-len(static_inputs),"dom_delta_forms":len(rendered_forms)-len(static_forms)},
          "stateful_surface": b.get("stateful_surface") or {},
          "surface_samples":{
              "static_inputs":static_inputs[:40], "rendered_inputs":rendered_inputs[:40], "frame_inputs":frame_inputs[:40],
              "static_forms":static_forms[:30], "rendered_forms":rendered_forms[:30],
              "frame_surfaces":[{"url":x.get("url"),"title":x.get("title"),"input_count":len(x.get("inputs") or []),"form_count":len(x.get("forms") or [])} for x in frame_surfaces[:30] if isinstance(x,dict)],
          },
          "pipeline_handoff":{
              "static_credential_source":bool(static.get("credential_source")),
              "static_external_sensitive_forms":len(static.get("external_sensitive_forms") or []),
              "static_proven_edges":len(((static.get("js_dataflow") or {}).get("proven_edges") or [])),
              "independent_phishing_score":int((self.results.get("independent_phishing_v323") or {}).get("score") or 0),
              "canonical_credential_score":int(((self.results.get("canonical_category_scores_v3222") or {}).get("credential_theft") or 0)),
              "canonical_phishing_score":int(((self.results.get("canonical_category_scores_v3222") or {}).get("phishing") or 0)),
          },
          "safety":"Live controls are not clicked and forms are never submitted. Extracted JavaScript is not executed by this diagnostic.",
          "interpretation":"A missing stage is an observation/sensor gap, not evidence that the target is safe."
        }
        self.results["credential_deep_observatory_v32328"]=report
        return report

    def independent_phishing_engine_v323(self):
        """
        Feed-independent phishing engine.
        OpenPhish/PhishTank/reputation are deliberately excluded from this decision.
        Independent experts: identity, credential intent, submission/exfil, visual,
        runtime/interaction, URL/infrastructure and social-engineering semantics.
        """
        b=self.results.get("browser") or {}
        h=self.results.get("http") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        host=(urlparse(final).hostname or "").lower()
        root=get_root_domain(host)
        static_sem=self.results.get("static_semantic_v3232") or {}
        sem=b.get("semantic_dom") or static_sem or {}
        forms=b.get("forms") or self.results.get("forms") or []
        reqs=b.get("requests") or []
        hooks=b.get("runtime_hooks") or {}
        static_src=self.results.get("static_source_intelligence_v32317") or {}

        title=str(sem.get("title") or b.get("title") or h.get("title") or "")
        headings=" ".join(map(str,sem.get("headings") or []))
        buttons=" ".join(map(str,sem.get("buttons") or []))
        visible=str(sem.get("visible_text") or "")[:120000]
        identity_surfaces=sem.get("identity_surfaces") or {}

        # V32.3.11 Strong Identity Claim Gate.
        # A brand mention in body/footer/help/partner text is NOT an identity claim.
        # Only first-party identity surfaces may activate the identity expert.
        identity_parts=[title]
        identity_parts.extend(list(map(str,(sem.get("headings") or [])[:8])))
        for k in ("og_title","app_name","header_text","logo_text"):
            if identity_surfaces.get(k): identity_parts.append(str(identity_surfaces.get(k)))
        identity_blob=" ".join(identity_parts).lower()[:20000]
        context_blob=(" ".join((title,headings,buttons,visible))).lower()

        claims=[]; contextual_brand_mentions=[]
        ambiguous_identity_tokens={"live"}
        for brand in BRAND_KEYWORDS:
            if brand in ambiguous_identity_tokens:
                continue
            strong_claim=brand_present(brand,identity_blob)
            context_mention=brand_present(brand,context_blob)
            if strong_claim:
                claims.append({"brand":brand,"related":self._v323_identity_relation(brand,root),
                               "claim_strength":"strong_first_party_surface"})
            elif context_mention:
                contextual_brand_mentions.append(brand)
        # V32.3.18 source-to-fusion bridge: verified 2xx static source is a real sensor.
        # It can restore identity evidence when Chromium/DOM observation is unavailable.
        for brand in (static_src.get("brand_claims") or []):
            if not any(x.get("brand")==brand for x in claims):
                claims.append({"brand":brand,"related":self._v323_identity_relation(brand,root),
                               "claim_strength":"verified_static_first_party_surface","sensor":"static_source"})
        mismatches=[x for x in claims if not x["related"]]

        # Expert 2: credential/payment/identity intent.
        sensitive=[]
        for inp in sem.get("inputs") or []:
            blob=" ".join(str(inp.get(k,"")) for k in
                          ("type","name","id","placeholder","autocomplete","label")).lower()
            if str(inp.get("type","")).lower()=="password" or re.search(
                r"password|passwd|parola|şifre|otp|one.?time|verification|verify|pin|cvv|cvc|cc-number|card|kart|iban|seed|recovery|wallet|ssn|identity",
                blob,re.I):
                sensitive.append(inp)
        for f in forms:
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive.append({"form":True,"action":f.get("action")})
        intent_terms=re.findall(
            r"\b(sign\s?in|log\s?in|verify|verification|confirm|account|password|payment|billing|wallet|otp|security alert|suspended|blocked|limited)\b",
            context_blob,re.I)
        intent_term_count=len(set(x.lower() for x in intent_terms))
        # V32.3.11 Credential Intent Gate.
        # Semantic words alone are contextual. A decisive credential vote requires
        # an observed sensitive control/form. This prevents normal account/help copy
        # from becoming a credential-theft expert.
        static_sensitive_count=int(static_src.get("sensitive_controls") or 0)
        static_credential=bool(static_src.get("credential_source"))
        if static_credential and not sensitive:
            sensitive.append({"static_source":True,"count":static_sensitive_count})
        credential_intent=bool(sensitive or static_credential)
        credential_context=bool(intent_term_count)

        # Expert 3: concrete submission/exfil destination.
        cross_forms=[]; writes=[]; cross_writes=[]
        for f in forms:
            try:
                u=urljoin(final,str(f.get("action") or ""))
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root and (f.get("has_password") or f.get("has_otp") or f.get("has_card")):
                    cross_forms.append({"url":u,"root":rr})
            except Exception: pass
        for q in reqs:
            if str(q.get("method") or "").upper() not in ("POST","PUT","PATCH"): continue
            u=str(q.get("url") or "")
            writes.append(u)
            try:
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root: cross_writes.append({"url":u,"root":rr})
            except Exception: pass
        for q in (hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or []):
            u=urljoin(final,str(q.get("url") or q.get("action") or ""))
            method=str(q.get("method") or "POST").upper()
            if method not in ("POST","PUT","PATCH") and q not in (hooks.get("beacons") or []): continue
            try:
                rr=get_root_domain(urlparse(u).hostname or "")
                if rr and rr!=root: cross_writes.append({"url":u,"root":rr})
            except Exception: pass
        static_external=list(static_src.get("external_sensitive_forms") or [])
        if static_external:
            cross_forms.extend({"url":x.get("action"),"root":x.get("action_root"),"sensor":"static_source"} for x in static_external)
        flow327=static_src.get("credential_flow_v32327") or {}
        if flow327.get("js_credential_sink"):
            cross_forms.extend({"url":x.get("url"),"root":x.get("root"),"sensor":"credential_flow_v32327"}
                               for x in (flow327.get("js_external_sinks") or [])[:12])
        exfil=bool(cross_forms or (credential_intent and cross_writes))

        # Expert 4: verified visual baseline mismatch.
        vs=self.results.get("visual_similarity_v27") or {}
        best=vs.get("best") or {}
        visual_score=float(best.get("score") or 0)
        visual_mismatch=False
        if best and visual_score>=82:
            try: visual_mismatch=get_root_domain(best.get("baseline_domain") or "")!=root
            except Exception: pass

        # Expert 5: staged/runtime interaction.
        dm=b.get("dom_mutations") or {}
        js_added=int(dm.get("password_fields_added",0) or 0)>0
        final_path=(urlparse(final).path or "/").lower()
        staged_auth=js_added or any(x in final_path for x in ("login","signin","verify","verification","auth","wallet","payment","checkout","otp"))
        staged_auth=bool(staged_auth and credential_intent)

        # V32.3.9: once the destination ownership graph exists, it is authoritative
        # for credential/exfil causality. Cross-origin telemetry by itself is not exfiltration.
        graph_v3238=self.results.get("causal_destination_graph_v3238") or {}
        if graph_v3238:
            graph_exfil=bool(graph_v3238.get("concrete_exfil"))
            strong_edges=list(graph_v3238.get("strong_causal_edges") or [])
            # A verified static <form action> edge is concrete causality too. Runtime graph
            # may be empty when Chromium times out, so it must not erase static evidence.
            static_exfil=bool(static_external)
            exfil=bool(graph_exfil or static_exfil)
            if graph_exfil:
                cross_writes=[{"url":e.get("sink"),"root":e.get("sink_root"),"edge_id":e.get("edge_id")} for e in strong_edges]
            elif not static_exfil:
                cross_forms=[]
                cross_writes=[]

        # Expert 6: URL/infrastructure context. Never sufficient alone.
        shared=next((x for x in ("vercel.app","netlify.app","pages.dev","github.io","firebaseapp.com","web.app","workers.dev")
                     if host==x or host.endswith("."+x)),None)
        url_blob=(host+" "+(urlparse(final).path or "")).lower()
        lexical=bool(re.search(r"(login|signin|verify|account|secure|wallet|payment|support|auth|recover|unlock)",url_blob))
        raw_ip=host_is_raw_ip(host)
        infrastructure_context=bool(shared or lexical or raw_ip)

        # Expert 7: social-engineering semantics. Context unless corroborated.
        urgency=bool(re.search(
            r"(account.{0,35}(suspended|blocked|limited|locked)|verify.{0,30}(identity|account)|"
            r"confirm.{0,30}account|update.{0,30}(payment|billing|information)|unusual.{0,30}activity|"
            r"security.{0,30}alert|hesab.{0,35}(askıya|bloke|kapat)|kimli.{0,30}doğrula)",
            context_blob,re.I))

        experts={}
        if mismatches:
            experts["identity"]={"weight":34,"detail":"strong brand claim on unrelated registrable domain",
                                 "brands":[x["brand"] for x in mismatches[:6]]}
        if credential_intent:
            experts["credential_intent"]={"weight":26,"detail":f"sensitive_fields={len(sensitive)}; intent_terms={intent_term_count}",
                                          "gate":"observed_sensitive_control"}
        elif credential_context:
            experts["credential_context"]={"weight":0,"detail":f"intent_terms={intent_term_count}; no sensitive control observed",
                                           "gate":"context_only_no_vote"}
        if exfil:
            experts["submission_exfil"]={"weight":38,"detail":f"cross_forms={len(cross_forms)}; cross_writes={len(cross_writes)}"}
        if visual_mismatch:
            experts["visual"]={"weight":30,"detail":f"verified_baseline_similarity={visual_score}"}
        if staged_auth:
            experts["runtime_stage"]={"weight":18,"detail":f"js_added_password={js_added}; final_path={final_path[:180]}"}
        if infrastructure_context:
            experts["infrastructure"]={"weight":10,"detail":f"shared={shared}; lexical={lexical}; raw_ip={raw_ip}"}
        if urgency:
            experts["social_engineering"]={"weight":12,"detail":"urgency/account-pressure language"}
        if contextual_brand_mentions:
            experts["brand_context"]={"weight":0,"detail":"passive/contextual brand mentions",
                                      "brands":contextual_brand_mentions[:12],"gate":"context_only_no_vote"}

        # Causal/corroboration rules. Feed evidence is intentionally absent.
        score=0; reasons=[]
        if mismatches and credential_intent:
            score+=48; reasons.append("identity_mismatch+credential_intent")
        if mismatches and exfil:
            score+=34; reasons.append("identity_mismatch+submission_exfil")
        if credential_intent and exfil:
            score+=52; reasons.append("credential_intent+submission_exfil")
        if visual_mismatch and credential_intent:
            score+=35; reasons.append("visual_impersonation+credential_intent")
        if staged_auth and (mismatches or exfil):
            score+=18; reasons.append("runtime_stage+independent_risk")
        if infrastructure_context and mismatches and credential_intent:
            score+=10; reasons.append("infrastructure+identity+credential")
        if urgency and mismatches and credential_intent:
            score+=10; reasons.append("social_engineering+identity+credential")

        # Structural phishing without a recognized brand: sensitive collection plus external sink.
        if not mismatches and credential_intent and exfil:
            score=max(score,72)
        # Brand impersonation with sensitive collection should be high even before a submit is observed.
        if mismatches and credential_intent:
            score=max(score,68)
        if visual_mismatch and credential_intent and mismatches:
            score=max(score,82)

        independent=set()
        for name in experts:
            if name in ("identity","credential_intent","submission_exfil","visual","runtime_stage","infrastructure","social_engineering"):
                independent.add(name)
        # Context-only experts cannot manufacture a verdict.
        decisive={x for x in independent if x in ("identity","credential_intent","submission_exfil","visual","runtime_stage")}
        if len(decisive)<2:
            score=min(score,39)
        score=min(100,int(round(score)))

        verdict=("high_confidence_phishing" if score>=75 else
                 "probable_phishing" if score>=55 else
                 "suspicious" if score>=25 else "insufficient_independent_evidence")

        report={"feed_independent":True,"host":host,"root":root,"score":score,"verdict":verdict,
                "experts":experts,"decisive_experts":sorted(decisive),"reasons":reasons,
                "brand_claims":claims[:12],"brand_mismatches":mismatches[:12],
                "contextual_brand_mentions":contextual_brand_mentions[:20],
                "credential_intent":credential_intent,"credential_context":credential_context,
                "static_source_bridge":{"active":bool(static_src),"credential_source":static_credential,"sensitive_controls":static_sensitive_count,"external_sensitive_forms":len(static_external)},
                "intent_term_count":intent_term_count,"sensitive_count":len(sensitive),
                "cross_form_count":len(cross_forms),"cross_write_count":len(cross_writes),
                "visual_mismatch":visual_mismatch,"visual_score":visual_score,
                "post_guard":bool(graph_v3238),
                "expert_status":{
                    "identity":{"active":bool(mismatches),"reason":"unrelated_brand_claim" if mismatches else "no_unrelated_brand_claim"},
                    "credential_intent":{"active":bool(credential_intent),"reason":f"sensitive_count={len(sensitive)}; intent_terms={intent_term_count}",
                                         "guard":"observed_sensitive_control_required" if credential_intent else "context_only_no_sensitive_control"},
                    "submission_exfil":{"active":bool(exfil),"reason":"concrete_sensitive_source_to_unrelated_sink" if exfil else ("rejected_by_destination_ownership_graph" if graph_v3238 else "not_observed")},
                    "visual":{"active":bool(visual_mismatch),"reason":"verified_visual_mismatch" if visual_mismatch else "not_observed"},
                    "runtime_stage":{"active":bool(staged_auth),"reason":"staged_auth_behavior" if staged_auth else "not_observed"},
                    "social_engineering":{"active":bool(urgency),"reason":"corroborated_only" if urgency else "not_observed"}
                },
                "policy":"feed/reputation is an independent sensor, never a prerequisite; identity requires a first-party claim surface; credential intent requires an observed sensitive control; post-guard fusion reads only causal destination ownership; derived fusion summaries never vote"}
        self.results["independent_phishing_v323"]=report

        if score>=55 and len(decisive)>=2:
            sev="critical" if score>=85 and ("submission_exfil" in decisive or "visual" in decisive) else "high"
            self._v323_add("Bağımsız phishing motoru: çoklu kanıt korelasyonu",sev,
                "Feed/reputation kullanılmadan birden fazla bağımsız phishing uzmanı aynı saldırı hipotezini destekledi.",
                "phishing",json.dumps({"score":score,"reasons":reasons,"experts":experts},ensure_ascii=False)[:5000],
                min(.98,.72+.06*len(decisive)),"independent_phishing")
        if exfil and credential_intent:
            self._v323_add("Hassas veri kaynağı → harici gönderim zinciri","critical",
                "Hassas giriş yüzeyi ile farklı registrable domaine giden yazma/gönderim hedefi aynı taramada gözlendi.",
                "credential_theft",json.dumps({"cross_forms":cross_forms[:8],"cross_writes":cross_writes[:8]},ensure_ascii=False)[:5000],
                .98,"submission_exfil")
        return report

    def behavioral_brain_v3234(self):
        """Fuse strong credential intent with concrete interaction/sink evidence.

        This module is deliberately causal: generic words, a password field alone,
        or generic network activity cannot create a high-confidence verdict.
        """
        b = self.results.get("browser") or {}
        sem = b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms = b.get("forms") or self.results.get("forms") or []
        hooks = b.get("runtime_hooks") or {}
        requests = b.get("requests") or []
        final_url = b.get("final_url") or (self.results.get("http") or {}).get("final_url") or self.results.get("analyzed_url") or ""
        root = get_root_domain(urlparse(final_url).hostname or "") if final_url else ""

        strong_text_parts = []
        for key in ("title", "headings", "buttons", "labels", "visible_text"):
            v = sem.get(key)
            if isinstance(v, list):
                strong_text_parts.extend(str(x) for x in v[:80])
            elif v:
                strong_text_parts.append(str(v))
        text = " ".join(strong_text_parts).lower()[:160000]

        # Credential intent is semantic, not tied to one HTML input type.
        cred_terms = re.compile(
            r"\b(login|log in|sign in|signin|password|passcode|username|user id|email address|"
            r"verification code|one[- ]?time|otp|pin|security code|cvv|cvc|card number|"
            r"giriş|oturum aç|parola|şifre|doğrulama kodu|tek kullanımlık|kart numarası)\b", re.I
        )
        cred_semantic = bool(cred_terms.search(text))

        sensitive_controls = []
        for f in forms:
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive_controls.append({
                    "source": f.get("source") or "form",
                    "action": str(f.get("action") or "")[:500],
                    "external_action": bool(f.get("external_action")),
                    "password": bool(f.get("has_password")),
                    "otp": bool(f.get("has_otp")),
                    "card": bool(f.get("has_card")),
                })

        # Browser semantic snapshots may expose custom controls without normal <form>.
        for inp in (sem.get("inputs") or [])[:120]:
            blob = " ".join(str(inp.get(k, "")) for k in ("type","name","id","placeholder","autocomplete","aria_label")).lower()
            if re.search(r"password|passcode|otp|one.?time|verification|pin|cvv|cvc|card|username|email", blob, re.I):
                sensitive_controls.append({"source":"semantic_dom","descriptor":blob[:500]})

        def _targets(items):
            out=[]
            for x in items or []:
                if isinstance(x, str):
                    u=x
                elif isinstance(x, dict):
                    u=x.get("url") or x.get("target") or x.get("action") or ""
                else:
                    continue
                if not u:
                    continue
                try:
                    h=urlparse(urljoin(final_url, u)).hostname or ""
                    rr=get_root_domain(h) if h else ""
                    out.append({"url":str(u)[:700],"root":rr,"external":bool(rr and root and rr != root)})
                except Exception:
                    pass
            return out

        runtime_targets=[]
        for k in ("fetches","xhr","beacons","form_submits"):
            runtime_targets += _targets(hooks.get(k) or [])
        # Request telemetry is context unless it is a write request.
        write_targets=[]
        for r in requests[:500]:
            if not isinstance(r, dict):
                continue
            method=str(r.get("method") or "").upper()
            if method not in ("POST","PUT","PATCH"):
                continue
            write_targets += _targets([r])

        form_targets=[]
        for f in forms:
            if f.get("action"):
                form_targets += _targets([{"url":f.get("action")}])

        external_runtime=[x for x in runtime_targets if x.get("external")]
        external_writes=[x for x in write_targets if x.get("external")]
        external_forms=[x for x in form_targets if x.get("external")]

        credential_surface = bool(sensitive_controls) or cred_semantic
        concrete_sink = bool(external_runtime or external_writes or external_forms)
        independent_experts=[]

        if credential_surface:
            independent_experts.append("credential_intent")
        if concrete_sink:
            independent_experts.append("external_sink")

        # Staged UI / mutation is independent context, but never sufficient alone.
        mutations = b.get("dom_mutations") or []
        staged = bool(mutations) and credential_surface
        if staged:
            independent_experts.append("runtime_stage")

        score = 0
        if cred_semantic:
            score += 14
        if sensitive_controls:
            score += 18
        if concrete_sink:
            score += 24
        if credential_surface and concrete_sink:
            score += 26
        if staged and concrete_sink:
            score += 8
        score = min(100, score)

        report = {
            "score": score,
            "credential_semantic": cred_semantic,
            "sensitive_controls": sensitive_controls[:30],
            "external_runtime_targets": external_runtime[:30],
            "external_write_targets": external_writes[:30],
            "external_form_targets": external_forms[:30],
            "staged_sensitive_ui": staged,
            "independent_experts": independent_experts,
            "causal_chain": bool(credential_surface and concrete_sink),
            "note": "Generic telemetry alone is not promoted to threat evidence."
        }
        self.results["behavioral_brain_v3234"] = report

        # Only a real source -> sink chain becomes strong threat evidence.
        if credential_surface and concrete_sink:
            self._v323_add(
                "Hassas veri arayüzü → harici veri hedefi",
                "high" if score < 75 else "critical",
                "Sayfa hassas kimlik/veri girişi istiyor ve bağımsız bir harici gönderim hedefi gözlendi.",
                "credential_theft",
                {"causal_source":"credential_surface","causal_sink":"external_network_target",
                 "score":score,"targets":(external_runtime+external_writes+external_forms)[:10]},
                .98,
                "credential_causality"
            )
            self.results["findings"][-1]["producer"]="behavioral_brain_v3234"
        elif credential_surface:
            # Keep useful but non-conclusive evidence below the hard-threat boundary.
            self._v323_add(
                "Hassas giriş / kimlik doğrulama yüzeyi",
                "medium",
                "Kimlik veya hassas veri girişi isteyen bir yüzey gözlendi; bağımsız harici veri hedefi doğrulanmadı.",
                "credential_theft",
                {"context_only":True,"score_hint":min(score,29)},
                .72,
                "credential_intent"
            )
            self.results["findings"][-1].update({"producer":"behavioral_brain_v3234","context_only":True})
        return report

    def causal_destination_ownership_graph_v3238(self):
        """V32.3.8: classify sensitive-data destinations before calling them exfiltration.

        A cross-origin request is not automatically malicious. The graph separates
        first-party, identity-related, unrelated and unknown destinations, and only
        promotes a credential/exfil chain when the sensitive source is causally tied
        to an unrelated sink. Unknown third-party telemetry remains context.
        """
        b=self.results.get("browser") or {}
        final=b.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        page_root=get_root_domain(urlparse(final).hostname or "")
        sem=b.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms=b.get("forms") or self.results.get("forms") or []
        hooks=b.get("runtime_hooks") or {}
        reqs=b.get("requests") or []
        ident=self.results.get("identity_semantic_v18") or {}
        ip=self.results.get("independent_phishing_v323") or {}

        brands=set()
        for x in (ident.get("detected_brands") or []) + (ip.get("brand_claims") or []):
            if isinstance(x,dict): v=x.get("brand") or x.get("name")
            else: v=x
            if v: brands.add(str(v).strip().lower())

        def abs_target(v):
            try:
                u=urljoin(final,str(v or "")); h=(urlparse(u).hostname or "").lower()
                return u,h,get_root_domain(h)
            except Exception: return "","",""

        def relation(root):
            if not root: return "invalid"
            if root==page_root: return "first_party"
            # Identity relationship is context, never a safety override.
            if any(self._v323_identity_relation(br,root) for br in brands): return "identity_related"
            return "unknown_external"

        sensitive_terms=re.compile(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification|pin|cvv|cvc|card.?number|cc-number|kart.?num|iban|seed|recovery.?phrase|ssn",re.I)
        sensitive_sources=[]
        for i,inp in enumerate(sem.get("inputs") or []):
            if not isinstance(inp,dict): continue
            blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label","aria_label"))
            if str(inp.get("type","")).lower()=="password" or sensitive_terms.search(blob):
                sensitive_sources.append({"source_id":f"input:{i}","kind":"input","descriptor":blob[:400]})
        for i,f in enumerate(forms):
            if not isinstance(f,dict): continue
            if f.get("has_password") or f.get("has_otp") or f.get("has_card"):
                sensitive_sources.append({"source_id":f"form:{i}","kind":"form","descriptor":"sensitive_form"})

        edges=[]
        strong_edges=[]
        # A sensitive form action is a direct structural source->sink edge even if the
        # worker never submits the form.
        for i,f in enumerate(forms):
            if not isinstance(f,dict) or not (f.get("has_password") or f.get("has_otp") or f.get("has_card")): continue
            u,h,rr=abs_target(f.get("action") or final); rel=relation(rr)
            e={"edge_id":f"form:{i}","source":"sensitive_form","sink":u[:800],"sink_root":rr,
               "relation":rel,"causality":"direct_form_action","observed_write":False}
            # Unknown external is suspicious context, but not automatically exfiltration.
            if rel=="unknown_external":
                e["decision"]="candidate_unrelated_sink"
                # A form explicitly posting credentials to a different registrable domain
                # is strong only when the page itself claims a different first-party identity.
                mismatch=bool(ip.get("brand_mismatches"))
                if mismatch:
                    e["relation"]="unrelated"; e["decision"]="strong_causal_exfil"; strong_edges.append(e)
            else: e["decision"]="benign_or_related_destination"
            edges.append(e)

        def runtime_items():
            for kind in ("fetches","xhr","beacons","form_submits"):
                vals=hooks.get(kind) or []
                if isinstance(vals,dict): vals=[vals]
                for x in vals:
                    yield kind,x
            for x in reqs[:700]:
                if isinstance(x,dict) and str(x.get("method") or "").upper() in ("POST","PUT","PATCH"):
                    yield "request_write",x

        for idx,(kind,x) in enumerate(runtime_items()):
            if isinstance(x,dict):
                target=x.get("url") or x.get("action") or x.get("target") or x.get("href")
                payload=x.get("body") or x.get("post_data") or x.get("data") or x.get("payload")
                source_ref=x.get("source") or x.get("source_id") or x.get("input") or x.get("form")
            else: target=x; payload=None; source_ref=None
            if not target: continue
            u,h,rr=abs_target(target); rel=relation(rr)
            payload_blob=json.dumps(payload,ensure_ascii=False,default=str) if payload is not None else ""
            # Source linkage must be concrete. Generic POST/fetch is not credential theft.
            source_linked=bool(source_ref or (payload_blob and sensitive_terms.search(payload_blob)))
            e={"edge_id":f"runtime:{idx}","source":"sensitive_source" if source_linked else "unbound_runtime",
               "sink":u[:800],"sink_root":rr,"relation":rel,"causality":"runtime_payload" if source_linked else "telemetry_only",
               "observed_write":True,"source_linked":source_linked}
            if rel=="unknown_external" and source_linked:
                e["relation"]="unrelated"; e["decision"]="strong_causal_exfil"; strong_edges.append(e)
            elif rel in ("first_party","identity_related"):
                e["decision"]="benign_or_related_destination"
            else: e["decision"]="unbound_external_write"
            edges.append(e)

        out={"page_root":page_root,"claimed_brands":sorted(brands),"sensitive_source_count":len(sensitive_sources),
             "edges":edges[:160],"strong_causal_edges":strong_edges[:40],"concrete_exfil":bool(strong_edges),
             "counts":{"first_party":sum(e.get("relation")=="first_party" for e in edges),
                       "identity_related":sum(e.get("relation")=="identity_related" for e in edges),
                       "unrelated":sum(e.get("relation")=="unrelated" for e in edges),
                       "unknown_external":sum(e.get("relation")=="unknown_external" for e in edges)},
             "principle":"Cross-origin is context; credential theft requires a concrete sensitive source -> unrelated sink edge."}
        self.results["causal_destination_graph_v3238"]=out

        # Remove/demote only causality-derived credential/exfil findings when the graph
        # cannot prove the edge. IOC/hash/C2/feed evidence is untouched.
        if not out["concrete_exfil"]:
            kept=[]; ctx=list(self.results.get("contextual_findings_v322") or [])
            for f0 in self.results.get("findings") or []:
                f=dict(f0); blob=self._v322_blob(f).lower(); prod=str(f.get("producer") or "").lower(); exp=str(f.get("source_expert") or "").lower()
                protected=any(k in blob for k in ("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","command and control"," c2 "))
                causal_cred=(exp in ("credential_theft","network_exfil","credential_causality","submission_exfil") or
                             "hassas veri" in blob or "credential_flow" in blob) and prod in ("evidence_bus_v3236","behavioral_brain_v3234","independent_phishing_v323","zero_day_behavior_v32")
                if causal_cred and not protected:
                    f["score_eligible_v322"]=False; f["v3238_causality_reject"]="no_sensitive_source_to_unrelated_sink_edge"
                    f["original_severity_v3238"]=f.get("severity"); f["severity"]="info"; ctx.append(f)
                else: kept.append(f)
            self.results["findings"]=kept; self.results["contextual_findings_v322"]=ctx
        return out

    def behavior_semantics_identity_causality_gate_v3237(self):
        """V32.3.7: observation != malicious intent.

        Validates producer findings against concrete DOM/runtime causality before they
        can reach canonical fusion. This is generic, domain-relationship aware and
        never suppresses known IOC, malicious file/hash, C2 or concrete exfil evidence.
        """
        browser=self.results.get("browser") or {}
        final=browser.get("final_url") or self.results.get("final_url") or self.results.get("url") or ""
        root=get_root_domain(urlparse(final).hostname or "")
        sem=browser.get("semantic_dom") or self.results.get("static_semantic_v3232") or {}
        forms=browser.get("forms") or self.results.get("forms") or []
        hooks=browser.get("runtime_hooks") or {}
        reqs=browser.get("requests") or []

        def target_root(v):
            try:
                u=urljoin(final,str(v or "")); return get_root_domain(urlparse(u).hostname or "")
            except Exception: return ""

        # Concrete sensitive sources. Text such as 'account/security/payment' is not a source.
        sensitive_inputs=[]
        for inp in sem.get("inputs") or []:
            if not isinstance(inp,dict): continue
            blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
            if str(inp.get("type","")).lower()=="password" or re.search(
                r"password|passwd|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|cc-number|card.?number|kart.?num|iban|seed|recovery.?phrase|ssn",blob,re.I):
                sensitive_inputs.append(inp)
        sensitive_forms=[]; cross_sensitive_forms=[]
        for f in forms:
            if not isinstance(f,dict): continue
            sens=bool(f.get("has_password") or f.get("has_otp") or f.get("has_card"))
            if sens:
                sensitive_forms.append(f)
                rr=target_root(f.get("action"))
                if rr and root and rr!=root: cross_sensitive_forms.append(f)
        concrete_sensitive=bool(sensitive_inputs or sensitive_forms)

        # Concrete runtime writes. Merely loading a third-party asset is not exfiltration.
        writes=[]
        for key in ("fetches","xhr","beacons","form_submits"):
            vals=hooks.get(key) or []
            if isinstance(vals,dict): vals=[vals]
            for x in vals:
                if isinstance(x,dict):
                    u=x.get("url") or x.get("action") or x.get("target") or x.get("href")
                    method=str(x.get("method") or "").upper()
                    body=x.get("body") or x.get("post_data") or x.get("data")
                else: u=x; method=""; body=None
                rr=target_root(u)
                if u and (method in ("POST","PUT","PATCH") or key in ("beacons","form_submits") or body):
                    writes.append({"url":str(u),"root":rr,"cross":bool(rr and root and rr!=root),"kind":key})
        cross_writes=[x for x in writes if x["cross"]]
        graph_v3238=self.results.get("causal_destination_graph_v3238") or {}
        concrete_exfil=bool(graph_v3238.get("concrete_exfil")) if graph_v3238 else bool(concrete_sensitive and (cross_sensitive_forms or cross_writes))

        # Cloaking requires observed content divergence plus an actual anti-analysis primitive.
        anti_blob=json.dumps(browser.get("script_signals") or {},ensure_ascii=False,default=str).lower()
        anti=bool(re.search(r"webdriver|devtools|navigator\.webdriver|headless|debugger",anti_blob,re.I))
        http=self.results.get("http") or {}
        obs=self.results.get("phishing_observatory_v3231") or {}
        discrepancy=bool(browser.get("content_discrepancy") or browser.get("http_browser_discrepancy") or
                         obs.get("content_discrepancy") or obs.get("cloaking_observed"))
        concrete_cloaking=bool(anti and discrepancy)

        # Redirect abuse needs a chain and a cross-root hop. Meta refresh alone is navigation telemetry.
        navs=browser.get("navigations") or browser.get("redirects") or http.get("redirect_history") or []
        if isinstance(navs,dict): navs=[navs]
        nav_roots=[]
        for n in navs:
            u=n.get("url") if isinstance(n,dict) else n
            rr=target_root(u)
            if rr: nav_roots.append(rr)
        cross_redirect=bool(len(navs)>=2 and any(rr!=root for rr in nav_roots if root))

        # Official identity relation invalidates impersonation only, never independent malicious evidence.
        official_claims=set()
        ident=self.results.get("identity_semantic_v18") or {}
        for x in ident.get("detected_brands") or []:
            if isinstance(x,dict):
                b=str(x.get("brand") or "").lower()
                if b and self._v323_identity_relation(b,root): official_claims.add(b)

        protected_terms=("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","c2","command and control")
        kept=[]; contextual=list(self.results.get("contextual_findings_v322") or []); demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f).lower(); title=str(f.get("title") or "").lower()
            if any(t in text for t in protected_terms): kept.append(f); continue
            reject=None
            if ("hassas veri + harici yazma" in title or "credential_flow" in text or
                (str(f.get("source_expert") or "").lower()=="credential_theft" and str(f.get("producer") or "").lower()=="evidence_bus_v3236")):
                if not concrete_exfil: reject="credential_event_without_concrete_sensitive_source_to_cross_origin_sink"
            elif ("anti-analysis + içerik ayrışması" in title or
                  (str(f.get("source_expert") or "").lower()=="cloaking" and str(f.get("producer") or "").lower()=="evidence_bus_v3236")):
                if not concrete_cloaking: reject="cloaking_event_without_observed_divergence_and_anti_analysis_primitive"
            elif "meta refresh yönlendirmesi" in title:
                if not cross_redirect: reject="meta_refresh_without_cross_root_redirect_chain"
            elif "sosyal mühendislik içeriği" in title:
                # Language is context until identity mismatch or a concrete credential/exfil chain corroborates it.
                ip=self.results.get("independent_phishing_v323") or {}
                if not concrete_exfil and not (ip.get("identity_mismatch") and concrete_sensitive):
                    reject="urgency_language_without_attack_causality"
            elif any(k in title for k in ("marka kimliği / domain uyuşmazlığı","marka taklidi + hassas işlem","sayfa başlığında marka taklidi")):
                if official_claims: reject="official_identity_relationship"
            if reject:
                f["score_eligible_v322"]=False; f["v3237_semantic_reject"]=reject
                f["original_severity_v3237"]=f.get("severity"); f["severity"]="info"
                contextual.append(f); demoted.append({"title":f.get("title"),"reason":reject})
            else: kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        out={"root":root,"concrete_sensitive_source":concrete_sensitive,
             "cross_origin_sensitive_form_count":len(cross_sensitive_forms),
             "cross_origin_runtime_write_count":len(cross_writes),"concrete_exfil":concrete_exfil,
             "destination_graph_v3238":graph_v3238,
             "anti_analysis_primitive":anti,"content_discrepancy":discrepancy,"concrete_cloaking":concrete_cloaking,
             "cross_root_redirect_chain":cross_redirect,"official_identity_claims":sorted(official_claims),
             "demoted":demoted,"principle":"Observation != attack intent; canonical threat evidence requires concrete causality."}
        self.results["behavior_semantics_gate_v3237"]=out
        return out

    def evidence_independence_ownership_guard_v32325(self):
        """V32.3.25 producer-level guard for evidence independence and ownership.

        Identity relationships can invalidate only impersonation hypotheses. They are
        never a safety allowlist and never suppress IOC/hash/C2/concrete exfil evidence.
        Redirect and source->sink claims require concrete cross-root causality. Derived
        summaries cannot become an independent corroborator of their own parents.
        """
        host=(urlparse(self.results.get("final_url") or self.results.get("analyzed_url") or "").hostname or "").lower()
        root=get_root_domain(host) if host else ""
        browser=self.results.get("browser") or {}
        http=self.results.get("http") or {}
        graph=self.results.get("causal_destination_graph_v3238") or {}

        # Organization/identity registry. This is relation data, not a trust override.
        org_groups={
          "meta":{"facebook.com","instagram.com","meta.com","whatsapp.com","fb.com"},
          "google":{"google.com","gmail.com","youtube.com"},
          "microsoft":{"microsoft.com","live.com","office.com","outlook.com"},
          "amazon":{"amazon.com","amazon.com.tr","amazon.co.uk","amazon.de","amazon.fr","amazon.it","amazon.es","amazon.co.jp","amazon.ca","amazon.com.au","amazon.in","amazon.com.br","amazon.com.mx"},
          "apple":{"apple.com","icloud.com"}
        }
        related_brands=set()
        brand_to_roots={
          "facebook":{"facebook.com","meta.com","fb.com"}, "instagram":{"instagram.com"},
          "meta":{"meta.com","facebook.com"}, "whatsapp":{"whatsapp.com"},
          "google":{"google.com","gmail.com"}, "youtube":{"youtube.com"},
          "microsoft":{"microsoft.com","live.com","office.com","outlook.com"},
          "amazon":org_groups["amazon"], "apple":{"apple.com","icloud.com"}
        }
        for brand,roots in brand_to_roots.items():
            if root in roots: related_brands.add(brand)
        for members in org_groups.values():
            if root in members:
                for brand,roots in brand_to_roots.items():
                    if roots & members: related_brands.add(brand)

        def target_root(u):
            try: return get_root_domain((urlparse(str(u)).hostname or "").lower())
            except Exception: return ""
        navs=browser.get("navigations") or browser.get("redirects") or http.get("redirect_history") or http.get("redirects") or []
        if isinstance(navs,dict): navs=[navs]
        nav_roots=[]
        for n in navs:
            u=n.get("url") if isinstance(n,dict) else n
            rr=target_root(u)
            if rr: nav_roots.append(rr)
        concrete_cross_root_redirect=bool(root and any(rr and rr!=root for rr in nav_roots))

        strong_edges=graph.get("strong_causal_edges") or []
        concrete_exfil=bool(graph.get("concrete_exfil") or strong_edges)

        protected=("openphish","phishtank","urlhaus","threatfox","malicious hash","sha256","c2","command and control")
        kept=[]; contextual=list(self.results.get("contextual_findings_v322") or []); demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0); text=self._v322_blob(f).lower(); title=str(f.get("title") or "").lower()
            if any(x in text for x in protected):
                kept.append(f); continue
            reason=None

            # Related first-party brand mentions cannot support impersonation.
            brand_hits={b for b in brand_to_roots if re.search(r"(?<![a-z0-9])"+re.escape(b)+r"(?![a-z0-9])",text)}
            if brand_hits and brand_hits.issubset(related_brands) and any(k in title for k in (
                "marka taklidi","marka kimliği","domain uyuşmaz","görsel marka kimliği","sahte host")):
                reason="related_first_party_identity_not_impersonation"

            # Navigation telemetry is contextual until a concrete cross-root chain exists.
            if not reason and ("meta refresh" in title or str(f.get("category") or "").lower() in ("redirect","redirect_abuse")):
                if not concrete_cross_root_redirect:
                    reason="redirect_without_concrete_cross_root_destination"

            # Static source+network vocabulary is not exfiltration without a causal edge.
            if not reason and any(k in title for k in ("hassas kaynak","ağ aktarım zinciri","veri gönderim akışı")):
                if not concrete_exfil:
                    reason="sensitive_source_network_without_causal_sink_edge"

            # A correlation/summary cannot vote as a new expert. Keep it diagnostic only.
            if not reason and any(k in title for k in ("çoklu tehdit davranışı korelasyonu","yüksek risk: phishing sitesi özellikleri","bağımsız davranış uzmanları aynı tehdidi destekliyor")):
                f["derived_evidence"]=True
                f["score_eligible_v322"]=False
                reason="derived_summary_cannot_be_independent_vote"

            if reason:
                f["score_eligible_v322"]=False; f["v32325_reject"]=reason
                f["original_severity_v32325"]=f.get("severity"); f["severity"]="info"
                contextual.append(f); demoted.append({"title":f.get("title"),"reason":reason})
            else:
                kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        out={"root":root,"related_brand_tokens":sorted(related_brands),
             "concrete_cross_root_redirect":concrete_cross_root_redirect,
             "concrete_exfil":concrete_exfil,"demoted":demoted,
             "invariant":"ownership invalidates impersonation only; redirect/exfil require causal destination evidence; derived summaries never vote"}
        self.results["evidence_independence_ownership_v32325"]=out
        return out

    def behavioral_intent_gate_v3226(self):
        """V32.2.6: generic JS/runtime primitives are telemetry until a causal malicious intent is proven.

        Important: the gate evaluates each finding's own provenance/evidence. It deliberately does not
        borrow unrelated page-wide signals, preventing normal large applications from manufacturing a
        source->sink chain by coincidence.
        """
        generic_js_terms=(
            "dynamic script loader", "dinamik harici script", "script oluşturuyor",
            "createelement('script')", 'createelement("script")', ".src =", ".src=",
            "eval_like", "decoder_like", "atob(", "fromcharcode", "decodeuricomponent",
            "storage access", "cookie access", "event listener", "input event"
        )
        malicious_sink_terms=(
            "cross-origin credential", "credential exfil", "cross-site credential",
            "external credential sink", "harici credential", "harici kimlik",
            "malware payload", "known malicious", "urlhaus", "threatfox", "openphish",
            "phishtank", "sha-256 ioc", "sha256 ioc", "malware hash", "command and control",
            " c2 ", "c2 endpoint"
        )
        explicit_flow_terms=(
            "source_to_sink", "source->sink", "source → sink", "source-to-sink",
            "credential_source", "sink_host", "destination_host", "external_sink"
        )
        kept=[]
        contextual=list(self.results.get("contextual_findings_v322") or [])
        demoted=[]
        for f0 in self.results.get("findings") or []:
            f=dict(f0)
            local=self._v322_blob({
                "title":f.get("title"), "description":f.get("description"),
                "evidence":f.get("evidence"), "category":f.get("category"),
                "source":f.get("source_expert") or f.get("source")
            })
            is_generic=any(t in local for t in generic_js_terms)
            has_hard=any(t in local for t in malicious_sink_terms)
            has_explicit_flow=any(t in local for t in explicit_flow_terms)
            # A generic primitive is not malicious intent. Only evidence local to this finding can promote it.
            if is_generic and not (has_hard or has_explicit_flow):
                f["original_severity_v3226"]=f.get("severity")
                f["severity"]="info"
                f["confidence"]=min(float(f.get("confidence") or .5), .20)
                f["score_eligible_v322"]=False
                f["behavioral_intent_v3226"]="generic_primitive_without_local_malicious_sink"
                contextual.append(f)
                demoted.append({"title":f.get("title"),"category":f.get("category")})
                continue
            kept.append(f)
        self.results["findings"]=kept
        self.results["contextual_findings_v322"]=contextual
        report={
            "policy":"generic_runtime_primitive_requires_finding_local_causal_malicious_sink",
            "score_eligible_findings":len(kept), "demoted_count":len(demoted), "demoted":demoted
        }
        self.results["behavioral_intent_gate_v3226"]=report
        return report

    def run_identity_semantic_v18(self):
        """Brand identity + semantic intent + shared-hosting context. Passive only."""
        url=self.results.get("final_url") or self.results.get("url") or ""
        host=(urlparse(url).hostname or "").lower()
        root=get_root_domain(host) if host else ""
        browser=self.results.get("browser",{}) or {}
        http=self.results.get("http",{}) or {}

        # Curated high-signal brands. Domain ownership is checked independently.
        brands={
          "airbnb":["airbnb.com"],"paypal":["paypal.com"],"microsoft":["microsoft.com","live.com","office.com","outlook.com"],
          "google":["google.com","gmail.com"],"apple":["apple.com","icloud.com"],"facebook":["facebook.com","meta.com"],
          "instagram":["instagram.com"],"amazon":["amazon.com","amazon.com.tr","amazon.co.uk","amazon.de","amazon.fr","amazon.it","amazon.es","amazon.co.jp","amazon.ca","amazon.com.au","amazon.in","amazon.com.br","amazon.com.mx"],"netflix":["netflix.com"],"github":["github.com"],
          "discord":["discord.com"],"telegram":["telegram.org"],"binance":["binance.com"],"coinbase":["coinbase.com"],
          "shopee":["shopee.com"],"trendyol":["trendyol.com"],"hepsiburada":["hepsiburada.com"]
        }
        shared_suffixes=("vercel.app","netlify.app","pages.dev","github.io","firebaseapp.com","web.app","workers.dev")

        # V32.3.2: only strong first-party surfaces can assert identity.
        static_sem=self.results.get("static_semantic_v3232") or {}
        semdom=browser.get("semantic_dom") or {}
        pieces=[]
        for source in (semdom, static_sem):
            for key in ("title","headings","buttons","labels","visible_text"):
                val=source.get(key)
                if val:
                    if isinstance(val,list): pieces.extend(str(x)[:1000] for x in val[:50])
                    else: pieces.append(str(val)[:120000])
        semantic=" ".join(pieces).lower()

        detected=[]
        ambiguous_identity_tokens={"live"}
        for brand,domains in brands.items():
            if brand in ambiguous_identity_tokens:
                continue
            if re.search(r"(?<![a-z0-9])"+re.escape(brand)+r"(?![a-z0-9])",semantic,re.I):
                official=any(root==d or root.endswith("."+d) for d in domains)
                detected.append({"brand":brand,"official_domain":official,"expected_domains":domains})

        sensitive_terms={
          "login":["login","log in","sign in","oturum aç","giriş yap"],
          "password":["password","parola","şifre"],
          "otp":["otp","one-time","verification code","doğrulama kod"],
          "payment":["payment","card number","credit card","cvv","cvc","ödeme","kart numarası"],
          "booking":["book now","reservation","booking","rezervasyon"],
          "identity":["verify identity","identity verification","kimlik doğrul"]
        }
        intents=[k for k,terms in sensitive_terms.items() if any(t in semantic for t in terms)]

        shared=next((x for x in shared_suffixes if host==x or host.endswith("."+x)),None)
        mismatches=[x for x in detected if not x["official_domain"]]
        score=0; evidence=[]
        if mismatches:
            score+=34
            evidence.append("Sayfa içeriğinde marka kimliği var ancak kök domain markanın resmi domaini değil")
        if mismatches and shared:
            score+=12
            evidence.append("Marka içeriği üçüncü taraf/shared-hosting subdomaininde")
        sensitive=set(intents)&{"login","password","otp","payment","identity"}
        if mismatches and sensitive:
            score+=24
            evidence.append("Marka-domain uyuşmazlığı hassas işlem niyetiyle birlikte gözlendi")
        if len(sensitive)>=2:
            score+=10
            evidence.append("Birden fazla hassas kullanıcı akışı sinyali")
        score=min(100,score)

        self.results["identity_semantic_v18"]={
          "host":host,"root_domain":root,"shared_hosting":shared,
          "detected_brands":detected,"brand_mismatches":mismatches,
          "semantic_intents":intents,"score":score,"evidence":evidence,
          "note":"Shared hosting tek başına tehdit kanıtı değildir."
        }

        # Feed explicit findings into existing UI/fusion.
        if mismatches:
            names=", ".join(x["brand"].title() for x in mismatches[:4])
            sev="high" if sensitive else "medium"
            self.add_finding("Marka kimliği / domain uyuşmazlığı", sev,
                f"Sayfa {names} marka göstergeleri taşıyor ancak kök domain resmi marka domaini değil."
                + (f" Shared hosting: {shared}." if shared else ""),
                "phishing", confidence=.88 if sensitive else .72)
        if mismatches and sensitive:
            self.add_finding("Marka taklidi + hassas işlem korelasyonu", "high",
                "Marka-domain uyuşmazlığı ile "+", ".join(sorted(sensitive))+" sinyalleri birlikte gözlendi.",
                "credential_theft", confidence=.92)

        # Coverage is decomposed; 100% module completion is not 100% behavioral certainty.
        browser_ok=bool(browser.get("success"))
        body_ok=bool(http.get("body_analyzed"))
        intel_checked=bool((self.results.get("threat_intelligence") or {}).get("checked"))
        self.results["coverage_v18"]={
          "technical_module_completion":100,
          "static_content_observation":100 if body_ok else 0,
          "browser_behavior_observation":100 if browser_ok else 0,
          "threat_intel_observation":100 if intel_checked else 0,
          "interpretation":"Modüllerin tamamlanması, tüm saldırı davranışlarının gözlemlendiği anlamına gelmez."
        }

    def run_behavioral_fusion_v17(self):
        """Passive multi-evidence correlation; missing observation is not clean evidence."""
        findings=self.results.get("findings",[]) or []
        browser=self.results.get("browser",{}) or {}
        http=self.results.get("http",{}) or {}
        scan=self.results.get("scan",{}) or {}
        blob=" ".join(str(x.get("title",""))+" "+str(x.get("description",""))+" "+str(x.get("evidence",""))+" "+str(x.get("category","")) for x in findings).lower()
        fam={k:{"score":0,"experts":set(),"evidence":[]} for k in
             ("phishing","credential_theft","malware","suspicious_script","redirect_abuse","data_exfiltration","cloaking")}
        def add(k,e,w,label):
            d=fam[k]; d["score"]+=w; d["experts"].add(e)
            if label not in d["evidence"]: d["evidence"].append(label)
        rules=[
          ("phishing","brand",34,("marka/domain","brand imperson","marka taklidi","marka kimliği / domain uyuşmazlığı")),
          ("phishing","url",12,("typosquat","punycode","homoglyph","şüpheli tld")),
          ("credential_theft","credential",32,("password","parola","şifre","otp","cvv","pin","hassas alan","marka taklidi + hassas işlem")),
          ("credential_theft","network",30,("harici runtime veri hedefi","cross-domain credential","external credential")),
          ("malware","download",40,("sha-256 ioc","urlhaus malware","malware payload","zararlı indirme")),
          ("suspicious_script","javascript",20,("obfuscat","eval","dynamic script","js-added password")),
          ("redirect_abuse","redirect",20,("redirect","yönlendirme","location")),
          ("data_exfiltration","network",30,("beacon","external runtime","harici runtime","veri hedefi"))]
        for k,e,w,keys in rules:
            if any(x in blob for x in keys): add(k,e,w," / ".join(keys[:2]))
        if browser.get("success"):
            hooks=browser.get("runtime_hooks") or {}; sem=browser.get("semantic_dom") or {}
            forms=sem.get("forms") or []
            sensitive=any(any(k in json.dumps(f,ensure_ascii=False).lower() for k in
                ("password","otp","one-time","cvv","cvc","cc-number","pin","iban")) for f in forms)
            if sensitive:
                add("credential_theft","dom",24,"Runtime DOM hassas alan")
                add("phishing","dom",12,"Runtime hassas form")
            if hooks.get("form_submits"): add("credential_theft","runtime",12,"Runtime form submit")
            if hooks.get("beacons"): add("data_exfiltration","runtime",16,"sendBeacon")
            if hooks.get("fetches") or hooks.get("xhr"): add("data_exfiltration","runtime",6,"fetch/XHR")
            if browser.get("downloads"): add("malware","download",14,"Browser download")
            hf=str(http.get("final_url") or scan.get("final_url") or ""); bf=str(browser.get("final_url") or "")
            if hf and bf:
                try:
                    if get_root_domain(urlparse(hf).hostname or "") != get_root_domain(urlparse(bf).hostname or ""):
                        add("cloaking","http_vs_browser",34,"HTTP/browser farklı kök domain")
                except Exception: pass
            if http.get("status") and browser.get("status") and http.get("status")!=browser.get("status"):
                add("cloaking","http_vs_browser",12,"HTTP/browser status farkı")
        redirects=http.get("redirects") or []; navs=browser.get("navigations") or []
        if redirects or len(navs)>1:
            add("redirect_abuse","navigation",min(20,8+3*(len(redirects)+max(0,len(navs)-1))),"Çok katmanlı navigasyon")
        blind=[]
        if browser.get("attempted") and not browser.get("success"): blind+=["runtime DOM","runtime network","client-side navigation"]
        if not http.get("body_analyzed"): blind.append("static response body")
        scan["v17_blind_spots"]=blind
        out=[]
        for k,d in fam.items():
            n=len(d["experts"]); score=d["score"]+(12 if n>=2 else 0)+(14 if n>=3 else 0)+(10 if n>=4 else 0)
            score=max(0,min(100,score))
            strength="none" if score==0 else "low" if score<30 else "medium" if score<60 else "high" if score<85 else "critical"
            out.append({"family":k,"evidence_strength":score,"strength":strength,"independent_experts":n,
                        "experts":sorted(d["experts"]),"evidence":d["evidence"][:12]})
        out.sort(key=lambda x:x["evidence_strength"],reverse=True)
        self.results["behavioral_fusion_v17"]={"engine":"Multi-Evidence Behavioral Fusion V17",
            "families":out,"primary":out[0] if out and out[0]["evidence_strength"] else None,
            "blind_spots":blind,"principle":"Independent evidence correlation; missing observation is not negative evidence."}

    def domain_impersonation_guard_v32313(self, original_url):
        """Site-agnostic passive identity detector that survives missing content.

        It never needs DOM access and therefore must remain eligible when a WAF,
        bot challenge, timeout or other target access restriction hides content.
        """
        final = self.results.get("final_url") or original_url
        host = (urlparse(final).hostname or "").lower()
        root = get_root_domain(host)
        labels = [x for x in host.split('.') if x and x not in {"www","com","net","org","app","site","online","co","tr"}]
        hits=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand, root):
                continue
            bs = self._leet_skeleton_v32313(brand)
            if len(bs) < 4: continue
            for label in labels:
                ls = self._leet_skeleton_v32313(label)
                if not ls: continue
                ratio = difflib.SequenceMatcher(None, bs, ls).ratio()
                # Exact skeleton catches leetspeak (f4c3b00k -> facebook).
                # High similarity catches ordinary typo variants without making
                # a single short substring decisive.
                if ls == bs or (len(bs) >= 5 and ratio >= .86):
                    hits.append({"brand":brand,"label":label,"skeleton":ls,"similarity":round(ratio,3)})
                    break
        # V32.3.14: hosted/tenant subdomain identity claim.
        # A phishing page can live below an otherwise legitimate hosting root
        # (tenant.example-host.tld). The hosting root must never inherit safety
        # to the tenant name. This is site/provider agnostic and does not require DOM.
        tenant_labels=[]
        if host and root and host != root and host.endswith("." + root):
            prefix=host[:-(len(root)+1)]
            tenant_labels=[x for x in prefix.split('.') if x and x != "www"]
        hosted_claims=[]
        for brand in BRAND_KEYWORDS:
            if legitimate_brand_root(brand, root):
                continue
            bs=self._leet_skeleton_v32313(brand)
            if len(bs) < 4:
                continue
            for label in tenant_labels:
                ls=self._leet_skeleton_v32313(label)
                # Exact token, leetspeak token, or a brand embedded in a longer
                # tenant slug (e.g. brand-support-login). This is an identity
                # warning, not by itself a phishing conviction.
                if ls == bs or (len(bs) >= 5 and (bs in ls or difflib.SequenceMatcher(None, bs, ls).ratio() >= .86)):
                    hosted_claims.append({"brand":brand,"tenant_label":label,"skeleton":ls,"root":root})
                    break

        detected=bool(hits or hosted_claims)
        if hits:
            detail = f"host={host}; root={root}; matches={hits[:8]}"
            self.add_finding(
                "Pasif alan adı marka taklidi / typosquatting sinyali", "high",
                "Alan adı, bilinen bir marka adının yazım/leetspeak benzerini kullanıyor ancak registrable domain o markanın resmi domain ilişkisiyle eşleşmiyor. İçerik alınamasa da bu pasif kimlik kanıtı geçerlidir.",
                "phishing", detail, .94)
        # Do not add a second scoring finding for hosted_claims here. Existing URL
        # intelligence may already score the brand-like hostname. This signal is
        # primarily an identity/observation guard so access failure cannot hide it.
        self.results["domain_impersonation_v32313"]={
            "detected":detected,"host":host,"root":root,"matches":hits[:8],
            "hosted_tenant_claims":hosted_claims[:8],
            "identity_context":"hosted_tenant_brand_claim" if hosted_claims else ("typosquat" if hits else "none"),
            "content_independent":True,
            "rule":"A legitimate hosting/root domain never makes an unverified tenant/subdomain identity claim safe."
        }
        return self.results["domain_impersonation_v32313"]

