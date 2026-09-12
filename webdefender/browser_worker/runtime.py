"""Isolated browser-worker runtime."""
from ..metadata import RUNNING_ON_PYTHONANYWHERE
import hashlib, io, threading
import os, sys, re, json, time, socket, ipaddress
from urllib.parse import urlparse, urljoin
from ..analyzer.url_domain import host_is_private, resolve_public_ips, get_canonical_root

def browser_worker_main(target_url, checkpoint_path=""):
    out = {
        "available": False, "success": False, "status_code": None,
        "final_url": "", "title": "", "dom_length": 0, "html": "",
        "requests": [], "responses": [], "downloads": [], "popups": [], "dialogs": [],
        "forms": [], "frames": [], "dom_mutations": {}, "runtime_hooks": {}, "script_signals": {}, "navigations": [], "semantic_dom": {}, "websockets": [], "screenshot_sha256": None, "screenshot_dhash": None,
        "blocked_requests": [], "console_errors": [], "error": "", "decision": "not_run", "failure_kind": "", "proxy_mode": "", "proxy_server": "",
        "stateful_surface": {"snapshots": [], "application_surface_verified": False, "interaction_gate_suspected": False, "reason": "not_observed"},
        "differential_observation": {"baseline": {}, "profiles": [], "policy": "bounded_no_interaction"}
    }
    def _checkpoint(stage):
        out["checkpoint_stage"] = stage
        out["checkpoint_at"] = time.time()
        if not checkpoint_path:
            return
        try:
            tmp = checkpoint_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(out, fh, ensure_ascii=False)
            os.replace(tmp, checkpoint_path)
        except Exception:
            pass

    _checkpoint("worker_started")
    try:
        from playwright.sync_api import sync_playwright
        out["available"] = True
    except Exception as exc:
        out["error"] = (
            "Playwright kurulu değil. Kurulum: pip install playwright && "
            "python -m playwright install chromium | " + str(exc)
        )
        print(json.dumps(out, ensure_ascii=False))
        return

    try:
        p = urlparse(normalize_url(target_url))
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Geçersiz browser hedefi.")
        resolve_public_ips(p.hostname)

        with sync_playwright() as pw:
            launch_kwargs = {
                "headless": True,
                "args": [
                    "--disable-dev-shm-usage",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-component-extensions-with-background-pages",
                    "--disable-features=Translate,BackForwardCache,MediaRouter,OptimizationHints",
                    "--renderer-process-limit=2",
                    "--no-sandbox",
                    "--headless",
                ]
            }
            if RUNNING_ON_PYTHONANYWHERE and os.path.exists("/usr/bin/chromium"):
                launch_kwargs["executable_path"] = "/usr/bin/chromium"

            # Chromium does not reliably consume PythonAnywhere's proxy environment
            # in the same way requests does. Pass the proxy explicitly to Playwright.
            proxy_url = (
                os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or ""
            ).strip()
            if proxy_url:
                pp = urlparse(proxy_url)
                if pp.scheme and pp.hostname:
                    proxy_server = f"{pp.scheme}://{pp.hostname}"
                    if pp.port:
                        proxy_server += f":{pp.port}"
                    proxy_cfg = {"server": proxy_server}
                    if pp.username:
                        proxy_cfg["username"] = unquote(pp.username)
                    if pp.password:
                        proxy_cfg["password"] = unquote(pp.password)
                    launch_kwargs["proxy"] = proxy_cfg
                    out["proxy_mode"] = "explicit-playwright-proxy"
                    out["proxy_server"] = proxy_server
                else:
                    out["proxy_mode"] = "invalid-env-proxy"
            else:
                out["proxy_mode"] = "direct-browser"

            _t_launch=time.perf_counter()
            _checkpoint("before_chromium_launch")
            browser = pw.chromium.launch(**launch_kwargs)
            _checkpoint("chromium_launched")
            out.setdefault("timings_ms", {})["chromium_launch"] = round((time.perf_counter()-_t_launch)*1000,2)
            context = browser.new_context(
                accept_downloads=True,
                ignore_https_errors=True,
                java_script_enabled=True,
                service_workers="block",
                user_agent=USER_AGENT,
                locale=os.getenv("WEB_DEFENDER_BROWSER_LOCALE", "en-US"),
                extra_http_headers={"Accept-Language": os.getenv("WEB_DEFENDER_BROWSER_ACCEPT_LANGUAGE", "en-US,en;q=0.9")},
            )
            page = context.new_page()
            page.set_default_timeout(5000)
            page.set_default_navigation_timeout(8500)
            _checkpoint("page_created")

            # V32.3.3: cache host safety decisions. A modern page can request hundreds
            # of resources from the same hosts; repeating DNS validation for every
            # request can exhaust the browser-worker deadline.
            _route_host_cache = {}
            _target_host=(p.hostname or "").lower().rstrip(".")
            _route_host_cache[_target_host]=(True,"")  # already validated before Chromium launch
            def _resolve_bounded(key, seconds=1.25):
                box={}
                def work():
                    try: box["ips"]=resolve_public_ips(key)
                    except Exception as exc: box["error"]=str(exc)
                t=threading.Thread(target=work, daemon=True); t.start(); t.join(seconds)
                if t.is_alive(): raise TimeoutError("bounded_dns_timeout")
                if box.get("error"): raise ValueError(box["error"])
                return box.get("ips") or []
            def _public_host_once(host):
                key=(host or "").strip().lower().rstrip(".")
                if key in _route_host_cache:
                    ok,err=_route_host_cache[key]
                    if not ok: raise ValueError(err)
                    return True
                try:
                    _resolve_bounded(key)
                    _route_host_cache[key]=(True,"")
                    return True
                except Exception as exc:
                    _route_host_cache[key]=(False,str(exc)[:180])
                    raise

            def route_guard(route):
                u = route.request.url
                try:
                    if route.request.resource_type in ("font", "media"):
                        out["blocked_requests"].append({"url": u[:300], "reason": "resource_budget"})
                        return route.abort()
                    q = urlparse(u)
                    if q.scheme not in ("http", "https") or not q.hostname:
                        out["blocked_requests"].append({"url": u[:300], "reason": "scheme"})
                        return route.abort()
                    _public_host_once(q.hostname)
                    return route.continue_()
                except Exception as exc:
                    out["blocked_requests"].append({"url": u[:300], "reason": str(exc)[:180]})
                    return route.abort()

            page.route("**/*", route_guard)
            page.on("request", lambda req: out["requests"].append({
                "url": req.url[:500], "method": req.method, "resource_type": req.resource_type,
                "has_post_data": bool(req.post_data)
            }) if len(out["requests"]) < 300 else None)
            page.on("websocket", lambda ws: out["websockets"].append({"url":ws.url[:700]}) if len(out["websockets"]) < 80 else None)
            page.on("response", lambda rr: out["responses"].append({
                "url": rr.url[:500], "status": rr.status,
                "content_type": rr.headers.get("content-type", "")[:200],
                "content_disposition": rr.headers.get("content-disposition", "")[:300]
            }) if len(out["responses"]) < 300 else None)
            page.on("framenavigated", lambda fr: out["navigations"].append({"url": fr.url[:500], "main": fr == page.main_frame}) if len(out["navigations"]) < 80 else None)
            page.on("popup", lambda pg: out["popups"].append({"url": pg.url[:500]}) if len(out["popups"]) < 30 else None)
            page.on("dialog", lambda d: (out["dialogs"].append({"type": d.type, "message": d.message[:300]}) if len(out["dialogs"]) < 30 else None, d.dismiss()))
            page.on("console", lambda msg: out["console_errors"].append(msg.text[:500])
                    if msg.type == "error" and len(out["console_errors"]) < 50 else None)
            def inspect_download(dl):
                item={"url":dl.url[:500],"suggested_filename":dl.suggested_filename[:250],"sha256":None,"size":None,"hash_status":"metadata_only"}
                try:
                    fp=dl.path()
                    if fp and os.path.isfile(fp):
                        item["size"]=os.path.getsize(fp)
                        if item["size"] <= int(os.getenv("MAX_DOWNLOAD_HASH_BYTES",str(25*1024*1024))):
                            hh=hashlib.sha256()
                            with open(fp,"rb") as fh:
                                for ch in iter(lambda:fh.read(1024*1024),b""): hh.update(ch)
                            item["sha256"]=hh.hexdigest(); item["hash_status"]="hashed"
                        else: item["hash_status"]="too_large"
                except Exception as e:
                    item["hash_status"]="error"; item["hash_error"]=str(e)[:180]
                if len(out["downloads"])<30: out["downloads"].append(item)
            page.on("download",inspect_download)

            page.add_init_script("""() => {
              window.__wdMut = {forms_added:0,password_fields_added:0,nodes_added:0};
              window.__wdRuntime = {fetches:[], xhr:[], beacons:[], nav:[], form_submits:[], sensitive_events:0};
              window.__wdListeners = [];
              const oadd=EventTarget.prototype.addEventListener;
              EventTarget.prototype.addEventListener=function(type,listener,opts){ try{ if(['submit','click','change','input'].includes(String(type).toLowerCase())){ let src=''; try{src=String(listener).slice(0,5000)}catch(e){} window.__wdListeners.push({type:String(type).toLowerCase(),target:(this?.tagName||this?.constructor?.name||'').toString().slice(0,80),handler_source:src}); if(window.__wdListeners.length>200) window.__wdListeners.shift(); }}catch(e){} return oadd.call(this,type,listener,opts); };
              const clip=(x,n=700)=>String(x||'').slice(0,n);
              const ofetch=window.fetch; if(ofetch) window.fetch=function(input,init){ try{window.__wdRuntime.fetches.push({url:clip(input?.url||input),method:clip(init?.method||'GET',20),has_body:!!init?.body});}catch(e){} return ofetch.apply(this,arguments); };
              const oopen=XMLHttpRequest.prototype.open, osend=XMLHttpRequest.prototype.send;
              XMLHttpRequest.prototype.open=function(m,u){this.__wd={method:clip(m,20),url:clip(u)}; return oopen.apply(this,arguments)};
              XMLHttpRequest.prototype.send=function(body){try{window.__wdRuntime.xhr.push({...this.__wd,has_body:!!body})}catch(e){} return osend.apply(this,arguments)};
              const obeacon=navigator.sendBeacon?.bind(navigator); if(obeacon) navigator.sendBeacon=function(u,d){try{window.__wdRuntime.beacons.push({url:clip(u),has_body:!!d})}catch(e){} return obeacon(u,d)};
              document.addEventListener('submit',e=>{try{const f=e.target;window.__wdRuntime.form_submits.push({action:clip(f.action||location.href),method:clip(f.method||'GET',20)})}catch(x){}},true);
              document.addEventListener('input',e=>{try{if(e.target?.matches?.('input[type=password],input[autocomplete*=one-time],input[autocomplete*=cc-]'))window.__wdRuntime.sensitive_events++}catch(x){}},true);
              new MutationObserver(ms => { for (const m of ms) for (const n of m.addedNodes || []) {
                if (!n || n.nodeType !== 1) continue; window.__wdMut.nodes_added++;
                if (n.matches?.('form')) window.__wdMut.forms_added++;
                if (n.matches?.('input[type=password]')) window.__wdMut.password_fields_added++;
                window.__wdMut.forms_added += n.querySelectorAll?.('form').length || 0;
                window.__wdMut.password_fields_added += n.querySelectorAll?.('input[type=password]').length || 0;
              }}).observe(document, {subtree:true, childList:true});
            }""")
            _t_nav=time.perf_counter()
            out["tls_observation_mode"] = "browser_ignore_https_errors_for_observation_only"
            _checkpoint("before_navigation")
            resp = None
            try:
                resp = page.goto(target_url, wait_until="domcontentloaded", timeout=8500)
                out["navigation_state"]="domcontentloaded"
            except Exception as nav_exc:
                out["navigation_error"]=str(nav_exc)[:700]
                # A navigation timeout must not discard an already committed/rendered document.
                try:
                    if page.url and page.url not in ("about:blank", ""):
                        out["navigation_state"]="partial_committed"
                    else:
                        raise nav_exc
                except Exception:
                    raise nav_exc
            out.setdefault("timings_ms", {})["domcontentloaded"] = round((time.perf_counter()-_t_nav)*1000,2)
            _checkpoint("navigation_returned")
            # V32.3.23: bounded staged observation. We do not click, type or submit.
            # A short second window catches delayed phishing UI without turning the worker into a crawler.
            # V32.3.30 Stateful Surface Discovery. Observation only: no click, type or submit.
            # Multiple bounded snapshots catch delayed/SPAs/JS-created credential surfaces.
            def _surface_snapshot(label):
                try:
                    z=page.evaluate("""() => {
                      const vis=e=>{try{const s=getComputedStyle(e),r=e.getBoundingClientRect();return s.display!=='none'&&s.visibility!=='hidden'&&r.width>0&&r.height>0}catch(x){return false}};
                      const inputs=[...document.querySelectorAll('input,textarea')];
                      const forms=[...document.forms];
                      const controls=[...document.querySelectorAll('button,a,[role=button],input[type=submit]')].filter(vis).slice(0,100).map(x=>(x.innerText||x.value||x.getAttribute('aria-label')||x.getAttribute('title')||'').trim()).filter(Boolean);
                      const blob=(document.body?.innerText||'').slice(0,160000);
                      const low=(controls.join(' ')+' '+blob.slice(0,40000)).toLowerCase();
                      const auth=/log[ -]?in|sign[ -]?in|verify|verification|account|password|passcode|otp|one[ -]?time|email|e-mail|username|continue|next|giriş|oturum|doğrula|şifre|parola|hesap|kullanıcı/.test(low);
                      const meta=(document.querySelector('meta[http-equiv="refresh" i]')||{}).content||'';
                      return {url:location.href,title:document.title||'',html_length:document.documentElement?.outerHTML?.length||0,text_length:blob.length,inputs:inputs.length,forms:forms.length,iframes:document.querySelectorAll('iframe').length,buttons:document.querySelectorAll('button,input[type=submit],[role=button]').length,links:document.links.length,visible_controls:controls.slice(0,40),auth_intent:auth,meta_refresh:meta,ready_state:document.readyState};
                    }""")
                    z["label"]=label; z["at_ms"]=round((time.perf_counter()-_t_nav)*1000,2)
                    out["stateful_surface"]["snapshots"].append(z)
                except Exception as se:
                    out["stateful_surface"]["snapshots"].append({"label":label,"error":str(se)[:300]})
            page.wait_for_timeout(700); _surface_snapshot("t+0.7s")
            page.wait_for_timeout(1400); _surface_snapshot("t+2.1s")
            # Extra bounded quiet window for delayed UI. Still no interaction.
            page.wait_for_timeout(2400); _surface_snapshot("t+4.5s")
            snaps=[x for x in out["stateful_surface"]["snapshots"] if isinstance(x,dict) and not x.get("error")]
            if snaps:
                first,last=snaps[0],snaps[-1]
                changed=any((x.get("inputs"),x.get("forms"),x.get("iframes"),x.get("url"),x.get("html_length")) != (first.get("inputs"),first.get("forms"),first.get("iframes"),first.get("url"),first.get("html_length")) for x in snaps[1:])
                has_surface=any((x.get("inputs",0)>0 or x.get("forms",0)>0) for x in snaps)
                auth_gate=any(bool(x.get("auth_intent")) and not (x.get("inputs",0)>0 or x.get("forms",0)>0) for x in snaps)
                out["stateful_surface"].update({"application_surface_verified":bool(has_surface),"interaction_gate_suspected":bool(auth_gate),"changed_across_snapshots":bool(changed),"reason":"interactive_surface_observed" if has_surface else ("auth_or_continue_language_without_form" if auth_gate else "no_form_or_input_observed")})

            # Runtime DOM snapshot: forms, iframes, sensitive inputs and script-obfuscation indicators.
            try:
                snap = page.evaluate("""() => {
                  const txt = (document.body?.innerText || '').slice(0, 120000);
                  const inputs = [...document.querySelectorAll('input,textarea')].slice(0,120).map(i => ({
                    type:(i.type||'').toLowerCase(), name:i.name||'', id:i.id||'', placeholder:i.placeholder||'',
                    autocomplete:i.autocomplete||'', label:(i.labels && i.labels[0] ? i.labels[0].innerText : ''),
                    hidden: !!(i.hidden || i.type==='hidden' || getComputedStyle(i).display==='none' || getComputedStyle(i).visibility==='hidden')
                  }));
                  const forms = [...document.forms].slice(0,60).map(f => {
                    const ins=[...f.querySelectorAll('input,textarea')];
                    const blob=ins.map(i => `${i.type} ${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`).join(' ').toLowerCase();
                    return {action:f.action||location.href, method:(f.method||'get').toUpperCase(),
                      has_password:ins.some(i=>i.type==='password'), has_otp:/otp|one-time|verification|sms.?code|doğrulama.?kod/.test(blob),
                      has_card:/card|cc-number|cvv|cvc|iban|kart/.test(blob), input_count:ins.length};
                  });
                  const scripts=[...document.scripts].map(s=>s.textContent||'').join('\n').slice(0,500000);
                  const count = r => (scripts.match(r)||[]).length;
                  const shadowInputs=[]; const shadowForms=[];
                  const walkShadow=(root,depth=0)=>{ if(!root || depth>5) return;
                    for(const el of [...(root.querySelectorAll?.('*')||[])].slice(0,2500)){
                      if(el.shadowRoot){
                        for(const i of [...el.shadowRoot.querySelectorAll('input,textarea')].slice(0,80)) shadowInputs.push({type:(i.type||'').toLowerCase(),name:i.name||'',id:i.id||'',placeholder:i.placeholder||'',autocomplete:i.autocomplete||'',hidden:false,source:'shadow_dom'});
                        for(const f of [...el.shadowRoot.querySelectorAll('form')].slice(0,30)){ const ins=[...f.querySelectorAll('input,textarea')]; shadowForms.push({action:f.action||location.href,method:(f.method||'get').toUpperCase(),has_password:ins.some(i=>i.type==='password'),has_otp:ins.some(i=>/otp|one-time|verification|code/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`)),has_card:ins.some(i=>/card|cc-number|cvv|cvc|iban/i.test(`${i.name} ${i.id} ${i.placeholder} ${i.autocomplete}`)),input_count:ins.length,source:'shadow_dom'}); }
                        walkShadow(el.shadowRoot,depth+1);
                      }
                    }
                  };
                  try{walkShadow(document)}catch(e){}
                  return {
                    semantic_dom:{title:document.title||'', headings:[...document.querySelectorAll('h1,h2,h3')].slice(0,40).map(x=>x.innerText.trim()),
                      buttons:[...document.querySelectorAll('button,input[type=submit]')].slice(0,60).map(x=>(x.innerText||x.value||'').trim()), visible_text:txt, inputs:[...inputs,...shadowInputs].slice(0,200), shadow_input_count:shadowInputs.length,
                      identity_surfaces:{
                        og_title:(document.querySelector('meta[property="og:title"]')||{}).content||'',
                        app_name:(document.querySelector('meta[name="application-name"]')||{}).content||'',
                        header_text:[...document.querySelectorAll('header,[role=banner],nav')].slice(0,12).map(x=>(x.innerText||'').trim()).join(' ').slice(0,5000),
                        logo_text:[...document.querySelectorAll('header img,[role=banner] img,img[alt*="logo" i],svg[aria-label],a[aria-label]')].slice(0,40).map(x=>[x.alt||'',x.getAttribute('aria-label')||'',x.getAttribute('title')||''].join(' ')).join(' ').slice(0,5000)
                      }},
                    forms:[...forms,...shadowForms].slice(0,100), shadow_form_count:shadowForms.length,
                    frames:[...document.querySelectorAll('iframe')].slice(0,60).map(x=>({src:x.src||'', title:x.title||''})),
                    script_signals:{eval_like:count(/\\beval\\s*\\(/gi), decoder_like:count(/\\batob\\s*\\(|decodeURIComponent\\s*\\(|unescape\\s*\\(/gi),
                      from_char_code:count(/String[.]fromCharCode/gi), long_encoded_blobs:count(/[A-Za-z0-9+/]{180,}={0,2}/g),
                      hex_escape_blobs:count(/(?:\\x[0-9a-fA-F]{2}){8,}/g), unicode_escape_blobs:count(/(?:\\u[0-9a-fA-F]{4}){6,}/g)}
                  };
                }""")
                out["semantic_dom"] = snap.get("semantic_dom", {})
                out["forms"] = snap.get("forms", [])
                out["frames"] = snap.get("frames", [])
                out["script_signals"] = snap.get("script_signals", {})
                # V32.3.22: inspect frame DOMs without interacting with them. Playwright can
                # observe attached frames; failures are isolated per frame.
                frame_surfaces=[]
                for fr in page.frames[:20]:
                    if fr == page.main_frame:
                        continue
                    try:
                        fs=fr.evaluate("""() => ({url:location.href,title:document.title||'',visible:(document.body?.innerText||'').slice(0,12000),inputs:[...document.querySelectorAll('input,textarea')].slice(0,60).map(i=>({type:(i.type||'').toLowerCase(),name:i.name||'',id:i.id||'',placeholder:i.placeholder||'',autocomplete:i.autocomplete||''})),forms:[...document.forms].slice(0,30).map(f=>({action:f.action||location.href,method:(f.method||'get').toUpperCase(),has_password:!!f.querySelector('input[type=password]')}))})""")
                        frame_surfaces.append(fs)
                    except Exception as fe:
                        frame_surfaces.append({"url":fr.url[:500],"error":str(fe)[:180]})
                out["frame_surfaces"]=frame_surfaces
                try:
                    out["runtime_hooks"] = page.evaluate("() => window.__wdRuntime || {}") or {}
                    out["registered_listeners"] = page.evaluate("() => window.__wdListeners || []") or []
                except Exception:
                    out["runtime_hooks"] = {}
                    out["registered_listeners"] = []
                try:
                    out["dom_mutations"] = page.evaluate("() => window.__wdMut || {}") or {}
                except Exception:
                    out["dom_mutations"] = {}
            except Exception as exc:
                out["console_errors"].append(("DOM snapshot: " + str(exc))[:500])

            out["route_host_cache_size"] = len(_route_host_cache)
            out["status_code"] = resp.status if resp else None
            out["final_url"] = page.url
            out["title"] = page.title()[:500]
            try:
                shot=page.screenshot(full_page=False,type="png")
                out["screenshot_sha256"]=hashlib.sha256(shot).hexdigest()
                try:
                    from PIL import Image
                    im=Image.open(io.BytesIO(shot)).convert("L").resize((9,8))
                    px=list(im.getdata()); bits=[]
                    for yy in range(8):
                        row=px[yy*9:(yy+1)*9]
                        bits.extend(1 if row[x]>row[x+1] else 0 for x in range(8))
                    out["screenshot_dhash"]=f"{sum(bit << (63-i) for i,bit in enumerate(bits)):016x}"
                except Exception:
                    out["screenshot_dhash"]=None
            except Exception:
                out["screenshot_sha256"]=None; out["screenshot_dhash"]=None
            html = page.content()
            if len(html) > MAX_CONTENT_SIZE:
                html = html[:MAX_CONTENT_SIZE]
            out["dom_length"] = len(html)
            _checkpoint("dom_snapshot_complete")
            bs = out["status_code"]
            browser_2xx = bs is not None and 200 <= int(bs) < 300
            committed_observable = bool(html and len(html) > 200 and page.url not in ("", "about:blank"))
            out["committed_observable"] = committed_observable
            out["access_restricted"] = bs in (401, 403, 429)
            out["decision"] = ("content_analyzable" if browser_2xx else
                               "access_restricted" if out["access_restricted"] else
                               "target_content_unavailable" if bs is not None and 400 <= int(bs) < 500 else
                               "upstream_error" if bs is not None and 500 <= int(bs) < 600 else
                               "http_non_success")
            out["html"] = html if browser_2xx else ""
            out["success"] = bool(html) and browser_2xx
            if not browser_2xx:
                out["error"] = (f"Browser HTTP {bs}: hedef uygulamanın gerçek içeriği doğrulanamadı."
                                if bs is not None else
                                "Browser geçerli hedef yanıtı alamadı.")
            # V32.3.31 Differential Observation Engine.
            # Bounded passive reloads only. No click, type, submit, CAPTCHA/challenge bypass or payload execution.
            try:
                base_snap=(out.get("stateful_surface") or {}).get("snapshots") or []
                last_base=next((x for x in reversed(base_snap) if isinstance(x,dict) and not x.get("error")), {})
                out["differential_observation"]["baseline"]={
                    "profile":"baseline_en_desktop","status":out.get("status_code"),"final_url":out.get("final_url"),
                    "title":out.get("title"),"html_length":out.get("dom_length"),"inputs":last_base.get("inputs",0),
                    "forms":last_base.get("forms",0),"iframes":last_base.get("iframes",0),"auth_intent":last_base.get("auth_intent",False)
                }
                profs=[
                    {"profile":"tr_desktop","locale":"tr-TR","accept":"tr-TR,tr;q=0.9,en;q=0.6","viewport":{"width":1365,"height":768},"js":True},
                    {"profile":"mobile_en","locale":"en-US","accept":"en-US,en;q=0.9","viewport":{"width":390,"height":844},"js":True},
                    {"profile":"nojs_en","locale":"en-US","accept":"en-US,en;q=0.9","viewport":{"width":1365,"height":768},"js":False},
                ]
                for cfg in profs:
                    item={"profile":cfg["profile"],"success":False}
                    c2=None
                    try:
                        c2=browser.new_context(ignore_https_errors=True,java_script_enabled=cfg["js"],service_workers="block",user_agent=USER_AGENT,locale=cfg["locale"],viewport=cfg["viewport"],extra_http_headers={"Accept-Language":cfg["accept"]})
                        p2=c2.new_page(); p2.set_default_timeout(3500); p2.set_default_navigation_timeout(5500)
                        # Same SSRF/private-network guard as the primary context.
                        p2.route("**/*", route_guard)
                        r2=None
                        try: r2=p2.goto(target_url,wait_until="domcontentloaded",timeout=5500)
                        except Exception: pass
                        p2.wait_for_timeout(700 if cfg["js"] else 150)
                        z=p2.evaluate("""() => { const t=(document.body?.innerText||'').slice(0,50000); const low=t.toLowerCase(); return {title:document.title||'',html_length:document.documentElement?.outerHTML?.length||0,inputs:document.querySelectorAll('input,textarea').length,forms:document.forms.length,iframes:document.querySelectorAll('iframe').length,auth_intent:/log[ -]?in|sign[ -]?in|verify|verification|password|passcode|otp|email|username|continue|next|giriş|oturum|doğrula|şifre|parola|hesap|kullanıcı/.test(low)} }""")
                        item.update(z or {}); item.update({"status":r2.status if r2 else None,"final_url":p2.url,"success":bool(p2.url and p2.url!='about:blank'),"java_script":cfg["js"],"locale":cfg["locale"],"viewport":cfg["viewport"]})
                    except Exception as de:
                        item["error"]=str(de)[:300]
                    finally:
                        try:
                            if c2: c2.close()
                        except Exception: pass
                    out["differential_observation"]["profiles"].append(item)
            except Exception as de:
                out["differential_observation"]["error"]=str(de)[:500]
            context.close()
            browser.close()
    except Exception as exc:
        msg = str(exc)[:1200]
        out["error"] = msg
        low = msg.lower()
        if "err_tunnel_connection_failed" in low:
            out["decision"] = "hosting_access_restricted"
            out["failure_kind"] = "pythonanywhere_proxy_tunnel"
        elif "timeout" in low:
            out["decision"] = "browser_timeout"
            out["failure_kind"] = "browser_timeout"
        elif any(x in low for x in (
            "err_proxy_connection_failed", "err_connection_refused",
            "err_connection_reset", "err_name_not_resolved",
            "err_internet_disconnected"
        )):
            out["decision"] = "browser_network_error"
            out["failure_kind"] = "browser_network"
        else:
            out["decision"] = "browser_error"
            out["failure_kind"] = "browser_error"

    print(json.dumps(out, ensure_ascii=False))

def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m webdefender.browser_worker.runtime <url> [checkpoint-path]")
    browser_worker_main(sys.argv[1], sys.argv[2] if len(sys.argv) >= 3 else "")

if __name__ == "__main__":
    main()
