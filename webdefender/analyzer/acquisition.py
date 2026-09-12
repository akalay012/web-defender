"""Acquisition and static-analysis sensor mixin.

These methods observe HTTP/browser/content/script surfaces. They do not own the
final verdict. The mixin is intentionally free of Flask route concerns.
"""
from ..metadata import RUNNING_ON_PYTHONANYWHERE
import requests, re, ssl, socket, ipaddress, time, os, json, hashlib, math, uuid, subprocess, sys, tempfile, shutil, difflib, csv, threading, zipfile, io, base64
from bs4 import BeautifulSoup
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin, parse_qsl, unquote_plus, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

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

REQUEST_TIMEOUT=15
MAX_CONTENT_SIZE=5*1024*1024
MAX_REDIRECTS=8
USER_AGENT=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36")

class AcquisitionSensorsMixin:
    def run_browser_worker(self, url, timeout=42):
        """Chromium/Playwright'i ayrı bir Python prosesinde çalıştırır.
        Ana Flask prosesi şüpheli sayfanın JavaScript'ini çalıştırmaz.
        Worker ephemeral context kullanır, indirmeleri reddeder ve private/special
        hedeflere giden istekleri route seviyesinde engeller.
        """
        defender = self.results.setdefault("defender", {})
        b = self.results.setdefault("browser", {
            "attempted": False, "available": None, "success": False,
            "status_code": None, "final_url": "", "title": "",
            "dom_length": 0, "requests": [], "blocked_requests": [],
            "console_errors": [], "error": "", "duration_ms": None
        })
        defender["browser"] = b
        b["attempted"] = True
        started = time.perf_counter()
        try:
            python_bin = self.resolve_worker_python()
            b["python_interpreter"] = python_bin or ""
            if not python_bin:
                b["available"] = False
                b["decision"] = "python_interpreter_unavailable"
                b["error"] = "Browser Worker için gerçek Python interpreter bulunamadı."
                return

            import tempfile
            checkpoint_path = os.path.join(tempfile.gettempdir(), f"wd-browser-{os.getpid()}-{threading.get_ident()}-{int(time.time()*1000)}.json")
            try:
                proc = subprocess.run(
                    [python_bin, "-m", "webdefender.browser_worker.runtime", url, checkpoint_path],
                    capture_output=True, text=True, timeout=timeout,
                    env={**os.environ, "WEB_DEFENDER_WORKER": "1", "WEB_DEFENDER_PYTHONANYWHERE": "1" if RUNNING_ON_PYTHONANYWHERE else "0"}
                )
                raw = (proc.stdout or "").strip()
            except subprocess.TimeoutExpired as exc:
                payload = {}
                try:
                    if os.path.isfile(checkpoint_path):
                        with open(checkpoint_path, "r", encoding="utf-8") as fh:
                            payload = json.load(fh)
                except Exception:
                    payload = {}
                payload.update({"success": False, "decision": "browser_timeout", "failure_kind": "parent_worker_deadline",
                                "error": f"Browser worker {timeout}s ana proses zaman sınırına ulaştı; son checkpoint korundu.",
                                "partial_observation": bool(payload)})
                b.update(payload)
                b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
                self.results["errors"].append({"module":"browser_worker","error":payload["error"]})
                return None
            finally:
                try:
                    if os.path.isfile(checkpoint_path): os.unlink(checkpoint_path)
                except Exception:
                    pass
            if not raw:
                raise RuntimeError((proc.stderr or "Browser worker çıktı üretmedi.")[-800:])
            payload = json.loads(raw.splitlines()[-1])
            b.update(payload)
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            if not payload.get("success"):
                self.results["errors"].append({
                    "module": "browser_worker",
                    "error": payload.get("error") or "Browser analizi başarısız."
                })
                return None

            html = payload.get("html", "")
            final_url = payload.get("final_url") or url
            if html:
                # Render edilmiş DOM'u mevcut motorlara besle.
                self.results["final_url"] = final_url
                self.results["http"]["body_analyzed"] = True
                self.results["http"]["content_trusted_for_analysis"] = True
                self.results["http"]["access_restricted"] = False
                self.results["http"]["decision"] = "content_analyzable_via_browser"
                self.results["http"]["reachable"] = True
                self.results["http"]["status_code"] = payload.get("status_code")
                self.results["http"]["reason"] = "BROWSER"
                self.results["http"]["content_length"] = len(html.encode("utf-8", errors="ignore"))
                self.results["http"]["network_mode"] = (
                    "pythonanywhere-browser-worker" if RUNNING_ON_PYTHONANYWHERE
                    else "isolated-browser-worker"
                )
                self.results["defender"]["content_status"] = "browser_analyzed"
                self.results["defender"]["passive_only"] = False

                # Browser sonunda login/auth/verify/payment yüzeyine geçiş ayrıca gözlemlenir.
                initial_path=(urlparse(url).path or "/").lower()
                final_path=(urlparse(final_url).path or "/").lower()
                auth_words=("login","signin","sign-in","auth","verify","verification","account","wallet","payment","checkout","otp")
                if final_url != url and any(w in final_path for w in auth_words) and not any(w in initial_path for w in auth_words):
                    self.add_finding(
                        "Tarayıcı giriş/doğrulama sayfasına yönlendirildi", "medium",
                        "Başlangıç adresi tarayıcı çalıştıktan sonra giriş, doğrulama veya ödeme bağlamlı bir yola geçti. Bu tek başına saldırı kanıtı değildir; diğer kimlik bilgisi ve marka sinyalleriyle birlikte değerlendirilir.",
                        "redirect", f"Başlangıç: {url}\nFinal: {final_url}", 0.86)

                self.run_check("browser_html", self.check_html, html, final_url)
                self.run_check("browser_patterns", self.check_suspicious_patterns, html)
                self.run_check("browser_mixed", self.check_mixed_content, html, final_url)
                self.run_check("browser_phishing", self.check_page_phishing_signals, html, final_url)
                self.run_check("browser_defender", self.check_advanced_defender, html, final_url)

                reqs = payload.get("requests") or []
                external = []
                base_root = get_root_domain(urlparse(final_url).hostname or "")
                for q in reqs:
                    try:
                        qh = urlparse(q.get("url","")).hostname or ""
                        if qh and get_root_domain(qh) != base_root:
                            external.append(q)
                    except Exception:
                        pass
                if external:
                    self.add_finding(
                        "Browser: harici ağ istekleri gözlendi", "low",
                        f"Render sırasında {len(external)} farklı-origin ağ isteği gözlendi.",
                        "behavior",
                        "\n".join(x.get("url","")[:220] for x in external[:12]),
                        0.65
                    )

                # V13.7 Runtime korelasyon: form hedefi, gerçek POST trafiği, iframe, DOM ve JS gizleme.
                forms = payload.get("forms") or []
                runtime_writes = [q for q in reqs if str(q.get("method","")).upper() in ("POST","PUT","PATCH")]
                cred_forms = [f for f in forms if f.get("has_password") or f.get("has_otp") or f.get("has_card")]
                cross_forms=[]
                for f in cred_forms:
                    try:
                        ar=get_root_domain(urlparse(str(f.get("action", ""))).hostname or "")
                        if ar and ar != base_root: cross_forms.append(f)
                    except Exception: pass
                if cross_forms:
                    self.add_finding("Runtime credential formu harici domaine gidiyor", "critical",
                        "Render edilmiş DOM'daki parola/OTP/kart formunun action hedefi farklı kök domainde.",
                        "credential_theft", "\n".join(str(x.get("action",""))[:300] for x in cross_forms[:8]), .99)

                matches=[]
                for f in cross_forms:
                    try:
                        fa=urlparse(str(f.get("action",""))); fh=(fa.hostname or "").lower(); fp=(fa.path or "/").rstrip("/")
                    except Exception: continue
                    for q in runtime_writes:
                        try:
                            qu=urlparse(str(q.get("url",""))); qh=(qu.hostname or "").lower(); qp=(qu.path or "/").rstrip("/")
                        except Exception: continue
                        if fh and fh==qh and (not fp or qp==fp or qp.startswith(fp)):
                            matches.append(q); break
                if matches:
                    self.add_finding("Credential form hedefi runtime trafikte doğrulandı", "critical",
                        "Hassas formun harici action hedefi ile tarayıcıda gözlenen veri gönderme isteği eşleşti.",
                        "credential_theft", "\n".join(f'{x.get("method")} {x.get("url","")[:300]}' for x in matches[:8]), .995)

                frames=payload.get("frames") or []; ext_frames=[]
                for fr in frames:
                    try:
                        rr=get_root_domain(urlparse(str(fr.get("src",""))).hostname or "")
                        if rr and rr != base_root: ext_frames.append(fr)
                    except Exception: pass
                if any(any(w in str(x.get("src","")).lower() for w in ("login","signin","auth","verify","otp","payment","wallet")) for x in ext_frames):
                    self.add_finding("Harici credential iframe zinciri", "high",
                        "Farklı kök domainden giriş/doğrulama/ödeme bağlamlı iframe yüklendi.", "phishing",
                        "\n".join(str(x.get("src",""))[:300] for x in ext_frames[:8]), .90)

                dm=payload.get("dom_mutations") or {}
                if int(dm.get("password_fields_added",0) or 0)>0:
                    self.add_finding("JavaScript sonrası parola alanı oluşturuldu", "high",
                        "Sayfa yüklenirken JavaScript DOM'a yeni parola alanı ekledi.", "javascript", str(dm), .90)
                ss=payload.get("script_signals") or {}
                obf_pts=min(int(ss.get("long_encoded_blobs",0) or 0),3)*2 + min(int(ss.get("hex_escape_blobs",0) or 0),3)*2 + min(int(ss.get("eval_like",0) or 0),3)*2 + min(int(ss.get("decoder_like",0) or 0),3)
                if obf_pts >= 6:
                    self.add_finding("Yoğun obfuscated JavaScript", "high",
                        "Birden fazla kod gizleme/çözme göstergesi runtime DOM içinde birlikte bulundu.", "javascript", str(ss), .90)

                # V14 runtime semantic phishing: görünür marka + hassas alan + domain uyumsuzluğu.
                sem=payload.get("semantic_dom") or {}
                sem_blob=" ".join([str(sem.get("title", "")), " ".join(sem.get("headings") or []),
                                   " ".join(sem.get("buttons") or []), str(sem.get("visible_text", ""))]).lower()
                claimed_runtime=[]
                for brand in BRAND_KEYWORDS:
                    if brand_present(brand, sem_blob) and not legitimate_brand_root(brand, base_root):
                        claimed_runtime.append(brand)
                sensitive_inputs=[]
                for inp in sem.get("inputs") or []:
                    blob=" ".join(str(inp.get(k,"")) for k in ("type","name","id","placeholder","autocomplete","label")).lower()
                    if inp.get("type")=="password" or re.search(r"otp|one.?time|verification|pin|cvv|cvc|cc-number|card|kart|iban|password|parola|şifre", blob, re.I):
                        sensitive_inputs.append(inp)
                if claimed_runtime:
                    self.add_finding("Runtime DOM'da marka/domain uyumsuzluğu", "high",
                        "Tarayıcıda render edilen görünür içerik tanınan bir marka adı kullanıyor ancak registrable domain markanın bilinen domaini değil.",
                        "phishing", f"host={base_root}; brands={', '.join(sorted(set(claimed_runtime))[:8])}", .92)
                if claimed_runtime and sensitive_inputs:
                    self.add_finding("Runtime marka taklidi + hassas bilgi isteme", "critical",
                        "Render edilmiş sayfa marka/domain uyumsuzluğu ile parola/OTP/kart benzeri hassas alanları birlikte içeriyor.",
                        "credential_theft", f"brands={claimed_runtime[:8]}; sensitive_fields={len(sensitive_inputs)}", .98)
                hooks=payload.get("runtime_hooks") or {}
                runtime_dest=(hooks.get("fetches") or [])+(hooks.get("xhr") or [])+(hooks.get("beacons") or [])+(hooks.get("form_submits") or [])
                ext_runtime=[]
                for rq in runtime_dest:
                    try:
                        rr=get_root_domain(urlparse(urljoin(final_url,str(rq.get("url") or rq.get("action") or ""))).hostname or "")
                        if rr and rr != base_root: ext_runtime.append(rq)
                    except Exception: pass
                if sensitive_inputs and ext_runtime:
                    self.add_finding("Hassas alan + harici runtime veri hedefi", "critical",
                        "Sayfada hassas giriş alanları bulunurken JavaScript/runtime trafiğinde farklı kök domaine giden veri hedefleri gözlendi.",
                        "credential_theft", str(ext_runtime[:8])[:1800], .97)

                for dl in payload.get("downloads") or []:
                    sh=str(dl.get("sha256") or "").lower()
                    if not re.fullmatch(r"[0-9a-f]{64}",sh): continue
                    hm=THREAT_INTEL_STORE.lookup_hash(sh)
                    if hm:
                        self.add_finding("İndirilen dosya SHA-256 IOC eşleşmesi","critical",
                            "İndirmenin SHA-256 özeti aktif malware IOC hafızasıyla eşleşti.","malware",
                            json.dumps({"sha256":sh,"filename":dl.get("suggested_filename"),"sources":[x.get("source") for x in hm]},ensure_ascii=False),.999)
                    else:
                        self.add_finding("İndirilen dosya SHA-256 hesaplandı","low",
                            "Dosya çalıştırılmadan SHA-256 özeti çıkarıldı; aktif yerel IOC eşleşmesi yok.","behavior",
                            json.dumps({"sha256":sh,"filename":dl.get("suggested_filename"),"size":dl.get("size")},ensure_ascii=False),.55)

                if len(payload.get("popups") or []) >= 2:
                    self.add_finding("Yoğun popup davranışı", "medium", "Sayfa yüklenirken birden fazla popup açma girişimi gözlendi.", "behavior", str(payload.get("popups")[:8]), .75)

                return html
        except subprocess.TimeoutExpired:
            b["available"] = True
            b["success"] = False
            b["decision"] = "browser_timeout"
            b["failure_kind"] = "parent_worker_deadline"
            b["timeout_seconds"] = timeout
            b["error"] = f"Browser worker {timeout}s zaman aşımına uğradı; HTTP/statik analiz korunuyor."
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self.results["errors"].append({"module": "browser_worker", "error": b["error"]})
        except Exception as exc:
            b["error"] = str(exc)
            b["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            self.results["errors"].append({"module": "browser_worker", "error": str(exc)})
        return None

    def finalize_content_acquisition_v32316(self, original_url):
        """Unifies what the engine actually managed to observe.

        This is an observation authority, not a WAF bypasser. It never solves
        CAPTCHAs, submits forms, changes identity, or treats a protected host as
        safe. It simply records which independent acquisition surface produced
        a real 2xx target body and which analyzers therefore had evidence.
        """
        http=self.results.get("http") or {}
        browser=self.results.get("browser") or {}
        recovery=self.results.get("observation_recovery_v32315") or {"attempted":False}
        hs=http.get("status_code"); bs=browser.get("status_code")
        try: hs=int(hs) if hs is not None else None
        except Exception: hs=None
        try: bs=int(bs) if bs is not None else None
        except Exception: bs=None
        http_body=bool(http.get("content_trusted_for_analysis") and hs is not None and 200 <= hs < 300)
        browser_body=bool(browser.get("success") and bs is not None and 200 <= bs < 300 and int(browser.get("dom_length") or 0)>0)
        body_observed=bool(http_body or browser_body)
        bdec=str(browser.get("decision") or browser.get("failure_kind") or "").lower()
        hdec=str(http.get("decision") or http.get("failure_kind") or "").lower()
        status=hs if hs is not None else bs
        challenge_status=status in {401,403,406,409,418,423,425,429,451}
        browser_blocked=any(x in bdec for x in ("timeout","challenge","blocked","access_restricted","deadline"))
        if body_observed:
            state="content_observed"
            display="Gerçek hedef içeriği gözlemlendi"
        elif challenge_status and browser_blocked:
            state="access_protection_or_challenge"
            display="Hedef erişim koruması / bot-WAF benzeri erişim kısıtı"
        elif challenge_status:
            state="http_access_restricted"
            display="HTTP erişim kısıtı"
        elif "timeout" in bdec:
            state="browser_timeout"
            display="Tarayıcı gözlemi zaman aşımına uğradı"
        elif status is not None and 400 <= status < 500:
            state="target_4xx_unavailable"
            display="Hedef içerik 4xx yanıtı nedeniyle alınamadı"
        elif status is not None and status >= 500:
            state="upstream_error"
            display="Hedef/upstream sunucu hatası"
        elif "network" in bdec or hdec in ("connection","proxy","tls"):
            state="network_observation_failure"
            display="Ağ/transport gözlemi tamamlanamadı"
        else:
            state="content_unverified"
            display="Hedef içerik doğrulanamadı"

        sem=browser.get("semantic_dom") or {}
        hooks=browser.get("runtime_hooks") or {}
        forms=browser.get("forms") or self.results.get("forms") or []
        scripts=(browser.get("script_signals") or {})
        analyzers={
            "url_domain": True,
            "dns_tls": True,
            "threat_intel": True,
            "static_html": bool(body_observed and self.results.get("static_semantic_v3232") is not None),
            "static_javascript": bool(body_observed and self.results.get("static_source_intelligence_v32317") is not None),
            "dom_semantics": browser_body,
            "forms_inputs": browser_body,
            "runtime_network": browser_body,
            "visual_runtime": browser_body,
        }
        out={
            "state":state,"display_name":display,"body_observed":body_observed,
            "http_body_observed":http_body,"browser_body_observed":browser_body,
            "http_status":hs,"browser_status":bs,
            "http_decision":http.get("decision") or "","browser_decision":browser.get("decision") or "",
            "bytes_observed":int(http.get("content_length") or 0) if http_body else 0,
            "dom_bytes_observed":int(browser.get("dom_length") or 0) if browser_body else 0,
            "final_url":browser.get("final_url") or self.results.get("final_url") or original_url,
            "recovery":recovery,
            "surface_inventory":{
                "forms":len(forms),"inputs":len(sem.get("inputs") or []),
                "frames":len(browser.get("frames") or []),"network_requests":len(browser.get("requests") or []),
                "runtime_hooks":sum(len(x) for x in hooks.values() if isinstance(x,list)),
                "script_signal_groups":len([k for k,v in scripts.items() if v]),
                "dom_mutations":sum(int(v or 0) for v in (browser.get("dom_mutations") or {}).values() if isinstance(v,(int,float))),
            },
            "analyzers":analyzers,
            "blind_spots":[k for k,v in analyzers.items() if not v],
            "rules":[
                "A 4xx/WAF/challenge body is never analyzed as if it were the target application.",
                "Access protection never suppresses independent URL/domain/IOC/DNS/TLS evidence.",
                "No CAPTCHA bypass, form submission, credential entry, or exploit is performed.",
                "Feed evidence is a sensor; content acquisition and behavioral analysis remain independent engine surfaces."
            ]
        }
        self.results["content_acquisition_v32316"]=out
        # Upgrade the older source report so diagnostics have one coherent view.
        self.results["source_analysis_v32315"]={
            "body_observed":body_observed,
            "bytes_observed":out["bytes_observed"]+out["dom_bytes_observed"],
            "static_code_analysis_available":body_observed,
            "reason":state,"recovery":recovery,
            "rule":"Source/DOM/JS claims require a real observed 2xx target body."
        }
        return out

    def check_dns(self, host):
        try:
            infos = socket.getaddrinfo(host, None)
            ips   = list(dict.fromkeys(i[4][0] for i in infos))
            self.results["dns"].update({"resolved": bool(ips), "addresses": ips})
            self.results["domain_info"]["ips"] = ips
        except Exception as exc:
            self.results["dns"]["error"] = str(exc)
            self.add_finding(
                "DNS çözümlemesi başarısız", "medium",
                "Domain için DNS kaydı bulunamadı veya çözümleme hatası oluştu.",
                "dns", str(exc)[:200], 0.9,
            )

    def check_html(self, html, base_url):
        soup      = BeautifulSoup(html, "html.parser")
        base_host = urlparse(base_url).hostname

        # V32.3.2: keep bounded strong semantic surfaces from a valid HTTP body.
        title_tag = soup.find("title")
        _static_inputs=[]
        for x in soup.find_all(["input","textarea","select"])[:200]:
            _static_inputs.append({
                "type": str(x.get("type") or ("textarea" if x.name=="textarea" else "text"))[:80],
                "name": str(x.get("name") or "")[:200], "id": str(x.get("id") or "")[:200],
                "placeholder": str(x.get("placeholder") or "")[:300],
                "autocomplete": str(x.get("autocomplete") or "")[:120],
                "label": ""
            })
        _og=soup.find("meta", attrs={"property":"og:title"}) or soup.find("meta", attrs={"name":"og:title"})
        _app=soup.find("meta", attrs={"name":re.compile(r"application-name",re.I)})
        _header=" ".join(x.get_text(" ",strip=True) for x in soup.find_all(["header","nav"])[:4])[:2500]
        _logo=" ".join((str(x.get("alt") or "")+" "+str(x.get("title") or "")) for x in soup.find_all("img")[:40] if re.search(r"logo|brand",str(x.get("class") or "")+" "+str(x.get("id") or "")+" "+str(x.get("src") or ""),re.I))[:1500]
        self.results["static_semantic_v3232"] = {
            "source": "http_body",
            "title": title_tag.get_text(" ", strip=True)[:1000] if title_tag else "",
            "headings": [x.get_text(" ", strip=True)[:500] for x in soup.find_all(["h1","h2"])[:20]],
            "buttons": [x.get_text(" ", strip=True)[:300] for x in soup.find_all("button")[:30]],
            "labels": [x.get_text(" ", strip=True)[:300] for x in soup.find_all("label")[:40]],
            "visible_text": " ".join(soup.stripped_strings)[:120000],
            "inputs": _static_inputs,
            "identity_surfaces": {
                "og_title": str((_og or {}).get("content") or "")[:1000] if _og else "",
                "app_name": str((_app or {}).get("content") or "")[:1000] if _app else "",
                "header_text": _header, "logo_text": _logo,
            },
            "dom_length": len(html),
        }

        for s in soup.find_all("script", src=True)[:100]:
            src = s.get("src", "")
            abs_url = urljoin(base_url, src)
            self.results["scripts"].append({
                "src": src[:500], "absolute_url": abs_url[:500],
                "type": "external",
                "same_origin": urlparse(abs_url).hostname == base_host,
            })
        for s in soup.find_all("script", src=False)[:100]:
            content = s.string or s.get_text() or ""
            self.results["scripts"].append({
                "src": "", "type": "inline", "length": len(content),
                "has_eval": bool(re.search(r"\beval\s*\(", content)),
            })

        for form in soup.find_all("form")[:100]:
            action   = urljoin(base_url, form.get("action", ""))
            method   = form.get("method", "GET").upper()
            inputs   = [
                {"name": x.get("name", ""), "type": x.get("type", "text")}
                for x in form.find_all(["input", "textarea", "select"])[:100]
            ]
            external = urlparse(action).hostname not in {base_host, None}
            _blob = " ".join((str(x.get("name",""))+" "+str(x.get("type",""))) for x in inputs).lower()
            _types = {str(x.get("type","")).lower() for x in inputs}
            self.results["forms"].append({
                "action": action[:1000], "method": method,
                "inputs": inputs, "input_count": len(inputs),
                "external_action": external,
                "has_password": "password" in _types,
                "has_otp": bool(re.search(r"otp|one.?time|verification|code|pin", _blob, re.I)),
                "has_card": bool(re.search(r"cvv|cvc|card|cc-number|kart", _blob, re.I)),
                "source": "http_static",
            })
            if external:
                self.add_finding(
                    "Form harici origin'e gönderiliyor", "medium",
                    "Form action adresi sayfanın origin'inden farklı bir hosta gidiyor.",
                    "forms", action[:300], 0.9,
                )

        for frame in soup.find_all("iframe")[:100]:
            src      = urljoin(base_url, frame.get("src", ""))
            external = urlparse(src).hostname not in {base_host, None}
            self.results["iframes"].append({
                "src": src[:1000], "sandbox": frame.get("sandbox", ""),
                "title": frame.get("title", ""), "external": external,
            })

        for a in soup.find_all("a", href=True)[:300]:
            href = urljoin(base_url, a["href"])
            self.results["links"].append({
                "url": href[:1000],
                "text": a.get_text(" ", strip=True)[:200],
                "external": urlparse(href).hostname not in {base_host, None},
            })

    def _v32326_static_js_dataflow(self, js, base_url):
        """Conservative static source->sink proof for inline JavaScript.

        This is deliberately *not* a full JavaScript taint engine. It only promotes a
        chain when the source and write sink are structurally close and the destination
        can be resolved to a different registrable domain. Mere API co-occurrence is
        telemetry and cannot vote in threat scoring.
        """
        page_root=get_root_domain((urlparse(base_url).hostname or "").lower())
        text=str(js or "")[:900000]
        source_rx=re.compile(
            r"document\.cookie|localStorage(?:\.[A-Za-z_$][\w$]*|\s*\[)|sessionStorage(?:\.[A-Za-z_$][\w$]*|\s*\[)|"
            r"\.value\b|getAttribute\s*\(\s*['\"]value['\"]|FormData\s*\(|"
            r"querySelector\s*\([^)]*(?:password|otp|passcode|cvv|cvc|card|iban)", re.I)
        sink_rx=re.compile(r"\bfetch\s*\(\s*(['\"])(?P<fetch>[^'\"]+)\1|"
                           r"\.open\s*\(\s*(['\"])(?:POST|PUT|PATCH)\2\s*,\s*(['\"])(?P<xhr>[^'\"]+)\3|"
                           r"sendBeacon\s*\(\s*(['\"])(?P<beacon>[^'\"]+)\4", re.I)
        sources=list(source_rx.finditer(text))[:120]
        sinks=[]
        for m in sink_rx.finditer(text):
            raw=m.groupdict().get("fetch") or m.groupdict().get("xhr") or m.groupdict().get("beacon") or ""
            try:
                u=urljoin(base_url,raw); rr=get_root_domain((urlparse(u).hostname or "").lower())
            except Exception:
                u=raw; rr=""
            relation="same_root" if rr and rr==page_root else ("cross_root" if rr else "unresolved")
            sinks.append({"start":m.start(),"raw":raw[:500],"url":u[:700],"root":rr,"relation":relation})
            if len(sinks)>=120: break

        # Bounded structural proof: source and explicit cross-root write target must be
        # in the same small JS region. We intentionally do not infer through arbitrary
        # variables/functions, because that recreates the old false-positive problem.
        edges=[]
        for sm in sources:
            for sk in sinks:
                distance=abs(sm.start()-sk["start"])
                if sk["relation"]!="cross_root" or distance>1800: continue
                lo=max(0,min(sm.start(),sk["start"])-250); hi=min(len(text),max(sm.end(),sk["start"])+900)
                region=text[lo:hi]
                # Require a write/body/data cue, not a GET-like resource request.
                write_cue=bool(re.search(r"\b(?:body|data|payload|credentials|password|passwd|otp|token)\b\s*[:=]|JSON\.stringify\s*\(|FormData\s*\(",region,re.I))
                if not write_cue: continue
                edges.append({"source":sm.group(0)[:180],"sink":sk["url"],"sink_root":sk["root"],"distance":distance,"proof":"bounded_source_to_explicit_cross_root_write"})
                if len(edges)>=12: break
            if len(edges)>=12: break
        return {"page_root":page_root,"source_count":len(sources),"literal_sink_count":len(sinks),
                "cross_root_literal_sinks":sum(1 for x in sinks if x["relation"]=="cross_root"),
                "proven_edges":edges,"proven_sensitive_to_unrelated_sink":bool(edges),
                "policy":"API co-occurrence is telemetry; scoring requires bounded source -> explicit cross-root write proof."}

    def _v324_static_interaction_graph(self, js, soup, base_url):
        """Bounded, non-executing reconstruction of interaction-triggered data flow.

        It never clicks, types, submits, or executes extracted JavaScript. It only inspects
        explicit handler source and HTML attributes. Strong proof requires a sensitive read
        and an explicit unrelated write sink inside the same bounded handler region.
        """
        js=(js or "")[:1000000]
        page_root=get_root_domain(urlparse(base_url).hostname or "")
        sensitive_read_re=re.compile(r"(?:\.value\b|getElementById\s*\([^)]*(?:pass|otp|cvv|card|pin|email|user)|querySelector\s*\([^)]*(?:password|otp|cvv|card|pin|email|user)|FormData\s*\()",re.I)
        write_re=re.compile(r"(?:fetch\s*\(\s*['\"]([^'\"]+)|\.open\s*\(\s*['\"](?:POST|PUT|PATCH)['\"]\s*,\s*['\"]([^'\"]+)|sendBeacon\s*\(\s*['\"]([^'\"]+)|(?:axios\.(?:post|put|patch)|\$\.post)\s*\(\s*['\"]([^'\"]+))",re.I)
        handlers=[]
        # Bounded extraction. This is intentionally conservative, not a JavaScript interpreter.
        patterns=[
          ("listener",re.compile(r"addEventListener\s*\(\s*['\"](submit|click|change|input)['\"]\s*,\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*\{(.{0,7000}?)\}\s*\)",re.I|re.S)),
          ("property",re.compile(r"on(submit|click|change|input)\s*=\s*(?:async\s*)?(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{(.{0,7000}?)\}",re.I|re.S)),
        ]
        for kind,pat in patterns:
            for m in pat.finditer(js):
                event=(m.group(1) or "").lower(); body=m.group(2) or ""
                sens=bool(sensitive_read_re.search(body))
                sinks=[]
                for wm in write_re.finditer(body):
                    raw=next((g for g in wm.groups() if g),"")
                    u=urljoin(base_url,raw); rr=get_root_domain(urlparse(u).hostname or "")
                    sinks.append({"url":u[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root)})
                cross=[x for x in sinks if x["cross_root"]]
                handlers.append({"kind":kind,"event":event,"sensitive_read":sens,"write_sinks":sinks[:12],"cross_root_sinks":cross[:12],"proven_sensitive_to_cross_root":bool(sens and cross)})
                if len(handlers)>=80: break
            if len(handlers)>=80: break
        html_handlers=[]
        for el in soup.find_all(True)[:1200]:
            for attr,event in (("onsubmit","submit"),("onclick","click"),("onchange","change"),("oninput","input")):
                code=str(el.get(attr) or "")
                if not code: continue
                sens=bool(sensitive_read_re.search(code)); sinks=[]
                for wm in write_re.finditer(code):
                    raw=next((g for g in wm.groups() if g),""); u=urljoin(base_url,raw); rr=get_root_domain(urlparse(u).hostname or "")
                    sinks.append({"url":u[:700],"root":rr,"cross_root":bool(rr and page_root and rr!=page_root)})
                html_handlers.append({"event":event,"tag":el.name,"sensitive_read":sens,"write_sinks":sinks[:8],"proven_sensitive_to_cross_root":bool(sens and any(x["cross_root"] for x in sinks))})
        proven=[x for x in handlers+html_handlers if x.get("proven_sensitive_to_cross_root")]
        return {"mode":"non_executing_static_reconstruction","handler_count":len(handlers)+len(html_handlers),"script_handlers":handlers[:80],"html_handlers":html_handlers[:40],"proven_paths":proven[:20],"proven_count":len(proven),"policy":"No live control is activated. Strong proof requires sensitive source and explicit unrelated write sink in the same bounded handler."}

    def static_source_intelligence_v32317(self, html, base_url):
        """Feed-independent static source expert over a verified 2xx target body.

        It does not execute source code. It extracts bounded HTML/JS evidence and
        only emits strong threat findings when independent source facts correlate.
        """
        soup=BeautifulSoup((html or "")[:1500000], "html.parser")
        host=(urlparse(base_url).hostname or "").lower(); root=get_root_domain(host)
        sem=self.results.get("static_semantic_v3232") or {}
        title=str(sem.get("title") or "")
        headings=" ".join(map(str,(sem.get("headings") or [])[:20]))
        ids=sem.get("identity_surfaces") or {}
        identity_blob=" ".join([title,headings,str(ids.get("og_title") or ""),str(ids.get("app_name") or ""),str(ids.get("header_text") or ""),str(ids.get("logo_text") or "")]).lower()[:30000]
        claims=[]
        for brand in BRAND_KEYWORDS:
            if brand_present(brand,identity_blob) and not legitimate_brand_root(brand,root): claims.append(brand)
        claims=list(dict.fromkeys(claims))[:12]

        # V32.3.27 Credential Flow Sensor: distinguish secret controls from identity/auth controls.
        # Email/username alone is not malicious. It becomes credential intent only when the
        # same first-party surface also expresses an authentication/account-verification intent.
        auth_surface_blob=(identity_blob+" "+" ".join(str(x.get_text(" ",strip=True)) for x in soup.find_all(["label","button"] )[:120])).lower()[:80000]
        auth_intent=bool(re.search(r"\b(login|log in|sign in|signin|verify|verification|account|continue|next|authenticate|"
                                   r"giriş|oturum aç|doğrula|doğrulama|hesap|devam|kimlik)\b",auth_surface_blob,re.I))
        sensitive=[]; identity_inputs=[]
        secret_re=re.compile(r"password|passwd|passcode|parola|şifre|otp|one.?time|verification.?code|pin|cvv|cvc|card.?number|cc-number|iban|seed|recovery.?phrase|wallet",re.I)
        identity_re=re.compile(r"email|e-mail|username|user.?name|user.?id|login|phone|telephone|mobile|account.?id|müşteri|kullanıcı|telefon|eposta|e-posta",re.I)
        for x in soup.find_all(["input","textarea","select"])[:250]:
            blob=" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label")).lower()
            typ=str(x.get("type") or "").lower()
            row={"type":typ,"name":str(x.get("name") or "")[:120],"id":str(x.get("id") or "")[:120],"descriptor":blob[:400]}
            if typ=="password" or secret_re.search(blob): sensitive.append(row)
            elif typ in ("email","tel") or identity_re.search(blob): identity_inputs.append(row)

        forms=[]; external_sensitive=[]; credential_forms=[]
        for f in soup.find_all("form")[:120]:
            action=urljoin(base_url,str(f.get("action") or "")); ar=get_root_domain(urlparse(action).hostname or "")
            fields=f.find_all(["input","textarea","select"])[:150]
            fb=" ".join(" ".join(str(x.get(k) or "") for k in ("type","name","id","placeholder","autocomplete","aria-label")) for x in fields).lower()
            has_secret=bool(secret_re.search(fb))
            has_identity=bool(identity_re.search(fb) or any(str(x.get("type") or "").lower() in ("email","tel") for x in fields))
            fs=bool(has_secret or (has_identity and auth_intent))
            row={"action":action[:600],"action_root":ar,"method":str(f.get("method") or "GET").upper(),"sensitive":fs,
                 "has_secret":has_secret,"has_identity":has_identity,"auth_intent":auth_intent}
            forms.append(row)
            if fs: credential_forms.append(row)
            if fs and ar and ar!=root: external_sensitive.append(row)

        scripts=[]; js_blob=[]; external_candidates=[]
        for sc in soup.find_all("script")[:180]:
            if sc.get("src"):
                u=urljoin(base_url,str(sc.get("src"))); row={"type":"external","url":u[:600],"root":get_root_domain(urlparse(u).hostname or "")}
                scripts.append(row); external_candidates.append((u,row))
            else:
                code=(sc.string or sc.get_text() or "")[:250000]; js_blob.append(code); scripts.append({"type":"inline","bytes":len(code)})
        # V32.4.1 Deep Script Inspection: inspect a bounded set of referenced JS files too.
        # This is passive source retrieval only: no extracted code is executed. safe_get keeps
        # public-IP and redirect guards active. Large/binary/non-script responses are rejected.
        fetched_external=0; fetched_external_bytes=0
        if external_candidates:
            _ses=requests.Session(); _ses.trust_env=bool(RUNNING_ON_PYTHONANYWHERE)
            _ses.headers.update({"User-Agent":USER_AGENT,"Accept":"application/javascript,text/javascript,*/*;q=0.2","Connection":"close"})
            for _u,_row in external_candidates[:10]:
                try:
                    _r,_hist,_fu=self.safe_get(_ses,_u,timeout=5,max_redirects=3)
                    _ct=str(_r.headers.get("Content-Type") or "").lower(); _cl=int(_r.headers.get("Content-Length") or 0)
                    if int(_r.status_code) != 200 or (_cl and _cl>350000):
                        _row.update({"fetched":False,"status":int(_r.status_code)}); _r.close(); continue
                    _raw=_r.raw.read(350001,decode_content=True); _r.close()
                    if len(_raw)>350000:
                        _row.update({"fetched":False,"reason":"size_limit"}); continue
                    if not ("javascript" in _ct or "ecmascript" in _ct or _u.lower().split("?",1)[0].endswith((".js",".mjs"))):
                        _row.update({"fetched":False,"reason":"non_script_content_type","content_type":_ct[:120]}); continue
                    _code=_raw.decode("utf-8","replace")
                    js_blob.append("\n/* external: "+_fu[:300]+" */\n"+_code)
                    fetched_external+=1; fetched_external_bytes+=len(_raw)
                    _row.update({"fetched":True,"status":200,"bytes":len(_raw),"final_url":_fu[:600]})
                except Exception as _e:
                    _row.update({"fetched":False,"error":str(_e)[:180]})
        js="\n".join(js_blob)[:1800000]
        self.results["_javascript_sources"]={"inline_and_external":[{"origin":"combined","url":base_url,"body":js}],"bytes":len(js),"execution":"never"}

        # Bounded static reconstruction of JS-created credential UI and submission sinks.
        # No JavaScript is executed. We only recognize explicit literals/API calls.
        js_auth=bool(re.search(r"login|sign.?in|password|passcode|verify|verification|otp|account|giriş|oturum|parola|şifre|doğrula|hesap",js,re.I))
        js_identity_control=bool(re.search(r"(?:type|name|id|placeholder|autocomplete)\s*[=:]\s*['\"](?:email|tel|username|user.?id|login)|"
                                           r"setAttribute\s*\(\s*['\"](?:type|name|autocomplete)['\"]\s*,\s*['\"](?:email|tel|username)",js,re.I))
        js_secret_control=bool(re.search(r"type\s*[=:]\s*['\"]password|setAttribute\s*\(\s*['\"]type['\"]\s*,\s*['\"]password|"
                                         r"otp|one.?time|verification.?code|cvv|cvc|card.?number|recovery.?phrase",js,re.I))
        js_submit_handlers=bool(re.search(r"addEventListener\s*\(\s*['\"]submit|onsubmit\s*=|preventDefault\s*\(|"
                                          r"addEventListener\s*\(\s*['\"]click",js,re.I))
        js_sink_literals=[]
        sink_patterns=[
            r"fetch\s*\(\s*['\"]([^'\"]+)",
            r"\.open\s*\(\s*['\"](?:POST|PUT|PATCH)['\"]\s*,\s*['\"]([^'\"]+)",
            r"(?:axios\.(?:post|put|patch)|\$\.post)\s*\(\s*['\"]([^'\"]+)",
            r"sendBeacon\s*\(\s*['\"]([^'\"]+)"
        ]
        for pat in sink_patterns:
            for m in re.finditer(pat,js,re.I):
                u=urljoin(base_url,m.group(1)); rr=get_root_domain(urlparse(u).hostname or "")
                js_sink_literals.append({"url":u[:600],"root":rr,"external":bool(rr and root and rr!=root),"offset":m.start()})
                if len(js_sink_literals)>=40: break
            if len(js_sink_literals)>=40: break
        js_external_sinks=[x for x in js_sink_literals if x.get("external")]
        js_dynamic_credential=bool(js_secret_control or (js_identity_control and js_auth))

        js_features={
            "dynamic_eval":bool(re.search(r"\beval\s*\(|new\s+Function\s*\(",js,re.I)),
            "decode_obfuscation":bool(re.search(r"\batob\s*\(|String\.fromCharCode|unescape\s*\(",js,re.I)),
            "cookie_access":bool(re.search(r"document\.cookie",js,re.I)),
            "storage_access":bool(re.search(r"localStorage|sessionStorage",js,re.I)),
            "key_capture":bool(re.search(r"keydown|keypress|keyup|beforeinput|input",js,re.I)),
            "network_sink":bool(re.search(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon\s*\(",js,re.I)),
            "location_redirect":bool(re.search(r"(?:window\.)?location(?:\.href)?\s*=|location\.replace\s*\(",js,re.I)),
            "password_dom":bool(re.search(r"type\s*[=:]\s*['\"]password|setAttribute\s*\(\s*['\"]type['\"]\s*,\s*['\"]password",js,re.I)),
        }
        # V32.3.26: lexical co-occurrence is NOT a causal data-flow proof.
        # A page may legitimately contain cookie/storage/input APIs and fetch/XHR in unrelated
        # modules (large first-party applications do this constantly).  Static JS contributes
        # attack evidence only when a bounded source -> sink chain is visible in the same code
        # region, and the sink is demonstrably cross-root/unrelated.
        dataflow=self._v32326_static_js_dataflow(js, base_url)
        js_causal=bool(dataflow.get("proven_sensitive_to_unrelated_sink"))
        credential_source=bool(sensitive or (identity_inputs and auth_intent) or any(x["sensitive"] for x in forms) or js_features["password_dom"] or js_dynamic_credential)
        # JS sink is only a submission/exfil candidate when credential UI + submit semantics are
        # present. A random analytics fetch on the same page is never promoted by this sensor.
        js_credential_sink=bool(js_dynamic_credential and js_submit_handlers and js_external_sinks)

        interaction_v324=self._v324_static_interaction_graph(js,soup,base_url)

        report={"body_bytes":len(html or ""),"host":host,"root":root,"brand_claims":claims,"sensitive_controls":len(sensitive),
                "identity_inputs":identity_inputs[:30],"auth_intent":auth_intent,"credential_forms":credential_forms[:30],
                "forms":forms[:30],"external_sensitive_forms":external_sensitive[:12],"scripts":scripts[:60],"inline_js_bytes":len(js),
                "js_features":js_features,"causal_dataflow_v32326":dataflow,
                "credential_flow_v32327":{"js_auth":js_auth,"js_identity_control":js_identity_control,"js_secret_control":js_secret_control,
                    "js_dynamic_credential":js_dynamic_credential,"js_submit_handlers":js_submit_handlers,
                    "js_sink_literals":js_sink_literals[:20],"js_external_sinks":js_external_sinks[:20],"js_credential_sink":js_credential_sink},
                "credential_source":credential_source,"non_executing_interaction_v324":interaction_v324,
                "external_script_inspection_v3241":{"fetched":fetched_external,"bytes":fetched_external_bytes,"candidate_count":len(external_candidates),"limit":10,"execution":"never"},
                "feed_independent":True,
                "rule":"Static source is evidence only when the verified 2xx target body was observed; source code is never executed."}
        self.results["static_source_intelligence_v32317"]=report

        # Strong, source-level correlations. No brand-only conviction.
        if claims and credential_source:
            self.add_finding("Statik kaynakta marka taklidi + hassas bilgi talebi","high",
                "Gerçek hedef HTML kaynağında güçlü marka kimliği yüzeyi ile parola/OTP/ödeme benzeri hassas bilgi talebi birlikte gözlendi.",
                "credential_theft",json.dumps({"brands":claims,"sensitive_controls":len(sensitive)},ensure_ascii=False),.95)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_credential_intent","independent_group":"static_source","evidence_lineage_id":"static-source-identity-credential"})
        if js_credential_sink:
            self.add_finding("JavaScript ile oluşturulan kimlik yüzeyi → harici gönderim hedefi","high",
                "Statik kaynakta JavaScript ile oluşturulan kimlik/hassas giriş yüzeyi, submit etkileşimi ve farklı registrable domaine giden açık ağ hedefi aynı kaynakta gözlendi. Kod çalıştırılmadı.",
                "credential_theft",json.dumps({"external_sinks":js_external_sinks[:8],"submit_handler":js_submit_handlers},ensure_ascii=False),.96)
            self.results["findings"][-1].update({"producer":"credential_flow_sensor_v32327","source_expert":"static_submission_exfil","independent_group":"static_source","evidence_lineage_id":"v32327-js-credential-sink"})
        elif js_dynamic_credential:
            self.add_finding("JavaScript ile oluşturulan kimlik doğrulama yüzeyi","medium",
                "Statik JavaScript kaynağında dinamik kimlik/hassas giriş kontrolü gözlendi; harici gönderim hedefi doğrulanmadığı için bu bulgu tek başına veri sızdırma kanıtı değildir.",
                "credential_theft",json.dumps({"auth":js_auth,"identity_control":js_identity_control,"secret_control":js_secret_control},ensure_ascii=False),.78)
            self.results["findings"][-1].update({"producer":"credential_flow_sensor_v32327","source_expert":"static_credential_intent","independent_group":"static_source","context_only":True,"score_hint_v32327":24,"evidence_lineage_id":"v32327-js-credential-surface"})

        if external_sensitive:
            self.add_finding("Statik kaynakta hassas form harici domaine gönderiliyor","critical",
                "Gerçek hedef HTML kaynağındaki hassas veri formunun action hedefi farklı bir registrable domaine gidiyor.",
                "credential_theft",json.dumps(external_sensitive[:6],ensure_ascii=False),.99)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_submission_exfil","independent_group":"static_source","evidence_lineage_id":"static-source-sensitive-form-sink"})
        if js_causal and credential_source:
            self.add_finding("Statik JavaScript'te hassas kaynak + ağ aktarım zinciri","high",
                "Gerçek hedef kaynağında hassas giriş bağlamı ile giriş/cookie erişimi, ağ API'si ve kod gizleme/dinamik çalıştırma göstergeleri birlikte bulundu. Kod çalıştırılmadı.",
                "javascript",json.dumps(js_features,ensure_ascii=False),.93)
            self.results["findings"][-1].update({"producer":"static_source_intelligence_v32318","source_expert":"static_javascript","independent_group":"static_source","evidence_lineage_id":"static-source-js-causal"})
        return report

    def check_mixed_content(self, html, base_url):
        if urlparse(base_url).scheme != "https":
            return
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["img", "script", "iframe", "link",
                                   "audio", "video", "source"]):
            attr  = "href" if tag.name == "link" else "src"
            value = tag.get(attr)
            if value and value.lower().startswith("http://"):
                self.results["mixed_content"].append({"tag": tag.name, "url": value[:1000]})
        if self.results["mixed_content"]:
            self.add_finding(
                "Mixed Content", "medium",
                f"HTTPS sayfada {len(self.results['mixed_content'])} HTTP kaynak bulundu.",
                "mixed_content",
                "; ".join(x["url"] for x in self.results["mixed_content"][:5]),
                1.0,
            )

    def check_ssl_certificate(self, host, port):
        self.results["ssl_info"]["checked"] = True
        proto = self.results["domain_info"]["protocol"]

        if proto != "https":
            self.results["ssl_info"]["error"] = "Hedef HTTP; TLS kontrolü atlandı."
            self.add_finding(
                "HTTPS kullanılmıyor", "high",
                "Site HTTP üzerinden çalışıyor. Tüm veri iletimi şifresizdir.",
                "tls", f"Protocol: {proto}", 1.0,
            )
            return

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert      = ssock.getpeercert()
                    expiry_raw= cert.get("notAfter", "")
                    days      = None
                    if expiry_raw:
                        expiry = datetime.strptime(
                            expiry_raw, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        days = (expiry - datetime.now(timezone.utc)).days

                    issuer  = dict(x[0] for x in cert.get("issuer",  []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    self.results["ssl_info"].update({
                        "valid": True, "version": ssock.version() or "",
                        "issuer": issuer, "subject": subject,
                        "not_before": cert.get("notBefore", ""),
                        "not_after":  expiry_raw, "days_remaining": days,
                        "subject_alt_names": cert.get("subjectAltName", []),
                    })

                    if days is not None and days < 30:
                        self.add_finding(
                            "TLS sertifikası yakında sona eriyor",
                            "medium" if days >= 0 else "high",
                            f"Sertifikanın kalan süresi: {days} gün.",
                            "tls", expiry_raw, 1.0,
                        )
                    if issuer == subject:
                        self.add_finding(
                            "Self-signed TLS sertifikası", "high",
                            "Sertifika güvenilir bir CA tarafından imzalanmamış (self-signed). "
                            "Phishing altyapısının göstergesi olabilir.",
                            "tls", f"Issuer: {issuer}", 0.90,
                        )
        except ssl.SSLCertVerificationError as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS sertifika doğrulaması başarısız", "high",
                "TLS bağlantısı kuruldu ancak sertifika doğrulanamadı.",
                "tls", str(exc)[:500], 0.98,
            )
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS bağlantısı doğrulanamadı",
                "info" if RUNNING_ON_PYTHONANYWHERE else "low",
                "Raw TLS bağlantısı kurulamadı. Bu sonuç tek başına geçersiz/sahte sertifika kanıtı değildir.",
                "network", str(exc)[:500],
                0.55 if RUNNING_ON_PYTHONANYWHERE else 0.70,
            )
        except Exception as exc:
            self.results["ssl_info"].update({"valid": False, "error": str(exc)})
            self.add_finding(
                "TLS kontrolü tamamlanamadı", "low",
                "TLS modülü kesin sertifika hükmü üretemedi.",
                "network", str(exc)[:500], 0.60,
            )

    def trace_javascript_dataflow(self):
        # Conservative non-executing lexical source-to-sink tracker.
        base=self.results.get("final_url") or self.results.get("analyzed_url") or ""
        page_root=get_canonical_root(urlparse(base).hostname or "")
        st=self.results.get("static_source_intelligence_v32317") or {}
        credential_context=bool(st.get("credential_source"))
        blobs=[]; source_bus=self.results.get("_javascript_sources") or {}
        for row in (source_bus.get("inline_and_external") or [])[:8]:
            if not isinstance(row,dict): continue
            code=str(row.get("body") or "")[:1800000]
            if code: blobs.append((str(row.get("origin") or "source"),str(row.get("url") or base),code))

        source_rx=re.compile(r"(?i)(?:[A-Za-z_$][\w$]*\s*\.\s*value\b|document\s*\.\s*cookie\b|(?:localStorage|sessionStorage)\s*\.\s*(?:getItem\s*\([^)]*\)|[A-Za-z_$][\w$]*)|new\s+FormData\s*\([^)]*\))")
        assign_rx=re.compile(r"(?m)\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,700})")
        alias_rx=re.compile(r"\b([A-Za-z_$][\w$]*)\b")
        sink_rx=re.compile(r"(?is)(?:fetch\s*\(\s*([^,\n\)]{1,700})(?:,\s*(\{.{0,1800}?\}))?|sendBeacon\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200})|axios\s*\.\s*(?:post|put|patch)\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200})|\$\s*\.\s*post\s*\(\s*([^,\n\)]{1,700})\s*,\s*([^\)]{1,1200}))")
        literal_url_rx=re.compile(r"['\"]((?:https?:)?//[^'\"]+|/[^'\"]*)['\"]",re.I)

        reports=[]; proven=[]
        for origin,script_url,code in blobs:
            tainted=set(); sources=[]
            for m in assign_rx.finditer(code):
                name,rhs=m.group(1),m.group(2)
                if source_rx.search(rhs):
                    tainted.add(name); sources.append({"var":name,"offset":m.start()})
            for _ in range(6):
                changed=False
                for m in assign_rx.finditer(code):
                    name,rhs=m.group(1),m.group(2)
                    if set(alias_rx.findall(rhs)) & tainted and name not in tainted:
                        tainted.add(name); changed=True
                if not changed: break

            sinks=[]
            for m in sink_rx.finditer(code):
                parts=[x for x in m.groups() if x]
                joined=" ".join(parts)
                refs=set(alias_rx.findall(joined))
                carries=bool(refs & tainted or source_rx.search(joined))
                dest=""
                for part in parts[:2]:
                    lm=literal_url_rx.search(part)
                    if lm:
                        dest=urljoin(script_url or base,lm.group(1)); break
                root=get_canonical_root(urlparse(dest).hostname or "") if dest else ""
                cross=bool(dest and root and page_root and root!=page_root)
                row={"offset":m.start(),"destination":dest[:700],"destination_root":root,
                     "cross_root":cross,"carries_sensitive":carries,
                     "tainted_variables":sorted(refs & tainted)[:20]}
                sinks.append(row)
                if carries and cross and credential_context:
                    proven.append({"origin":origin,"script_url":script_url[:700],**row})
            reports.append({"origin":origin,"script_url":script_url[:700],
                            "tainted_variables":sorted(tainted)[:80],
                            "sources":sources[:80],"sinks":sinks[:80]})

        rep={"mode":"bounded_nonexecuting_lexical_dataflow","scripts_analyzed":len(blobs),
             "credential_context":credential_context,"reports":reports[:50],"proven_sensitive_crossroot_paths":proven[:40],
             "proven_count":len(proven),"score_eligible":bool(proven),
             "limitations":["dynamic destination expressions","eval/new Function","deep interprocedural calls","computed object properties"],
             "policy":"No JavaScript is executed and no form is submitted. Only explicit sensitive-data propagation into an explicit unrelated network destination is score-eligible."}
        self.results["javascript_dataflow"]=rep
        self.results["js_dataflow_v3244"]=rep
        if proven:
            self.add_finding("JavaScript hassas veri akışı harici hedefe bağlandı","critical",
                "Statik JavaScript veri akışında hassas bir kaynaktan açıkça farklı kök domaine yazılan ağ hedefi doğrulandı.",
                "credential_theft",json.dumps({"paths":proven[:8]},ensure_ascii=False),.97)
            self.results["findings"][-1].update({
                "producer":"javascript_dataflow","source_expert":"static_submission_exfil",
                "independent_group":"static_source","evidence_lineage_id":"v3244-js-sensitive-crossroot",
                "causal_proof":True,"score_eligible":True})
        return rep

    def js_dataflow_engine_v3244(self):
        return self.trace_javascript_dataflow()

    def differential_observation_engine_v32331(self):
        """Compare bounded browser observation profiles without interacting with live controls.

        This is a sensor, not a verdict. A profile difference only becomes scoring evidence
        when the same target exposes a materially different application surface and at least
        one profile contains an authentication/credential surface.
        """
        b=self.results.get("browser") or {}
        d=b.get("differential_observation") or {}
        profiles=d.get("profiles") or []
        base=d.get("baseline") or {}
        report={
            "mode":"bounded_observation_no_interaction",
            "profiles":profiles,
            "baseline":base,
            "material_divergence":False,
            "credential_surface_in_variant":False,
            "conditional_delivery_signal":False,
            "score_eligible":False,
            "reason":"not_observed",
            "policy":"Viewport/locale/JavaScript differences are sensors only. No click, typing, form submission or challenge bypass is performed."
        }
        if not profiles:
            report["reason"]="no_differential_profiles"
            self.results["differential_observation_v32331"]=report
            return report

        def sig(x):
            return (str(x.get("title") or "").strip().lower(), int(x.get("inputs") or 0),
                    int(x.get("forms") or 0), int(x.get("iframes") or 0),
                    bool(x.get("auth_intent")), str(x.get("final_url") or ""))
        bs=sig(base)
        divergent=[]; credential=[]
        for x in profiles:
            xs=sig(x)
            # Material means application-surface change, not a few bytes of analytics noise.
            surface_delta=(xs[1:5] != bs[1:5]) or (xs[5] and bs[5] and xs[5] != bs[5])
            title_delta=bool(xs[0] and bs[0] and xs[0] != bs[0])
            html_ratio=0.0
            try:
                a=max(1,int(base.get("html_length") or 0)); c=int(x.get("html_length") or 0)
                html_ratio=abs(c-a)/a
            except Exception: pass
            material=surface_delta or (title_delta and html_ratio >= .20) or html_ratio >= .45
            if material: divergent.append(x)
            if int(x.get("inputs") or 0)>0 or int(x.get("forms") or 0)>0 or bool(x.get("auth_intent")):
                credential.append(x)
        conditional=bool(divergent and credential)
        report.update({
            "material_divergence":bool(divergent),
            "credential_surface_in_variant":bool(credential),
            "conditional_delivery_signal":conditional,
            "divergent_profiles":[x.get("profile") for x in divergent],
            "credential_profiles":[x.get("profile") for x in credential],
            "reason":"conditional_application_surface" if conditional else ("profile_divergence_context_only" if divergent else "profiles_consistent")
        })
        # Stronger than generic headless telemetry, but still cannot declare phishing alone.
        if conditional:
            self._v323_add(
                "Koşullu içerik / farklı uygulama yüzeyi",
                "medium",
                "Aynı hedef, sınırlı tarayıcı profilleri arasında maddi olarak farklı içerik gösterdi ve en az bir profilde kimlik doğrulama/girdi yüzeyi gözlendi. Bu bulgu tek başına phishing hükmü değildir.",
                "cloaking",
                {"profiles":report["divergent_profiles"],"credential_profiles":report["credential_profiles"],"context_only":True},
                .86,
                "differential_observation"
            )
            self.results["findings"][-1].update({"producer":"differential_observation_v32331","context_only":True,"score_eligible_v322":False})
        self.results["differential_observation_v32331"]=report
        return report

