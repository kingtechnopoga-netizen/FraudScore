from dataclasses import asdict
import json
import os
from flask import Flask, request, render_template_string, jsonify
from proxy_intel import ProxyIntelligence, RotationTester

app = Flask(__name__)

HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0610">
<title>Proxy Intelligence • Nexus</title>
<style>
:root{--bg:#08050b;--panel:rgba(21,12,25,.82);--panel2:#130b18;--line:rgba(255,102,194,.16);--pink:#ff3da8;--pink2:#ff79c8;--text:#f9eef7;--muted:#a99cab;--green:#55e6a5;--red:#ff637f;--amber:#ffd166;--shadow:0 24px 80px rgba(0,0,0,.42)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);background:radial-gradient(circle at 15% 5%,rgba(255,61,168,.18),transparent 30%),radial-gradient(circle at 90% 15%,rgba(155,72,255,.13),transparent 28%),linear-gradient(135deg,#08050b,#0c0710 48%,#07050a);overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.28;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 85%)}
.blob{position:fixed;width:280px;height:280px;border-radius:50%;filter:blur(70px);opacity:.18;pointer-events:none;animation:float 11s ease-in-out infinite}.b1{background:#ff1493;top:8%;left:-120px}.b2{background:#8f42ff;right:-120px;top:38%;animation-delay:-5s}.b3{background:#ff4db8;left:35%;bottom:-180px;animation-delay:-2s}@keyframes float{50%{transform:translate3d(30px,-35px,0) scale(1.08)}}
.wrap{width:min(1180px,calc(100% - 28px));margin:auto;padding:28px 0 46px;position:relative}.topbar{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:12px}.logo{width:46px;height:46px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(135deg,#ff2c9c,#a03cff);box-shadow:0 0 35px rgba(255,61,168,.35);font-size:22px;font-weight:900}.brand h1{font-size:17px;letter-spacing:.4px;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:12px}.status{display:flex;align-items:center;gap:8px;border:1px solid var(--line);background:rgba(255,255,255,.035);padding:9px 12px;border-radius:999px;color:#d9cbd8;font-size:12px}.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green);animation:pulse 1.7s infinite}@keyframes pulse{50%{opacity:.4;transform:scale(.72)}}
.hero{padding:26px;border:1px solid var(--line);border-radius:26px;background:linear-gradient(135deg,rgba(255,61,168,.11),rgba(255,255,255,.025));box-shadow:var(--shadow);backdrop-filter:blur(18px);overflow:hidden;position:relative}.hero:after{content:"";position:absolute;width:280px;height:280px;right:-100px;top:-150px;border-radius:50%;border:1px solid rgba(255,121,200,.2);box-shadow:0 0 0 35px rgba(255,121,200,.025),0 0 0 70px rgba(255,121,200,.018)}.eyebrow{color:var(--pink2);font-size:11px;font-weight:800;letter-spacing:2px;text-transform:uppercase}.hero h2{font-size:clamp(29px,5vw,50px);line-height:1.02;margin:9px 0 10px;max-width:720px}.hero h2 span{background:linear-gradient(90deg,#fff,#ff62bb 55%,#b675ff);-webkit-background-clip:text;background-clip:text;color:transparent}.hero p{color:var(--muted);max-width:720px;line-height:1.65;margin:0}.hero-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}.pill{font-size:12px;border:1px solid var(--line);padding:8px 11px;border-radius:999px;color:#dbcddd;background:rgba(0,0,0,.16)}
.grid{display:grid;grid-template-columns:1.05fr .95fr;gap:16px;margin-top:16px}.card{border:1px solid var(--line);background:var(--panel);border-radius:22px;padding:20px;box-shadow:0 18px 55px rgba(0,0,0,.25);backdrop-filter:blur(15px)}.card-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}.card h3{margin:0;font-size:16px}.card-head small{color:var(--muted);font-size:11px}.icon{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:rgba(255,61,168,.1);border:1px solid var(--line);color:var(--pink2)}
label{display:block;color:#d8cbd8;font-size:11px;font-weight:700;margin:13px 0 7px}.input,textarea{width:100%;border:1px solid rgba(255,255,255,.08);outline:none;background:rgba(0,0,0,.27);color:#fff;border-radius:13px;padding:13px 14px;font:inherit;font-size:13px;transition:.2s;border-color:rgba(255,255,255,.09)}.input:focus,textarea:focus{border-color:rgba(255,61,168,.65);box-shadow:0 0 0 4px rgba(255,61,168,.08)}textarea{resize:vertical;min-height:150px}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.btn{width:100%;border:0;border-radius:13px;padding:13px 15px;margin-top:13px;color:#fff;font-weight:800;font-size:13px;cursor:pointer;background:linear-gradient(135deg,#ff2c9c,#b33cff);box-shadow:0 12px 28px rgba(255,61,168,.18);transition:transform .18s,box-shadow .18s,filter .18s}.btn:hover{transform:translateY(-2px);box-shadow:0 16px 35px rgba(255,61,168,.28);filter:saturate(1.12)}.btn:active{transform:translateY(0)}.btn.secondary{background:rgba(255,255,255,.05);border:1px solid var(--line);box-shadow:none;color:#eadfea}.hint{color:#8f8290;font-size:10px;line-height:1.5;margin-top:8px}
.results{margin-top:16px}.result-toolbar{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px}.result-toolbar .actions{display:flex;gap:7px}.mini{border:1px solid var(--line);background:rgba(255,255,255,.035);color:#e7dbe7;border-radius:10px;padding:8px 10px;font-size:11px;cursor:pointer}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:12px}.stat{padding:13px;border:1px solid rgba(255,255,255,.06);background:rgba(0,0,0,.18);border-radius:14px}.stat b{font-size:20px;display:block}.stat span{color:var(--muted);font-size:10px}.resultbox{min-height:150px;border-radius:15px;background:#080509;border:1px solid rgba(255,255,255,.07);padding:15px;overflow:auto}.empty{text-align:center;color:#796c78;padding:35px 10px;font-size:12px}.result-json{margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;color:#dfd2df}.loading{display:flex;align-items:center;gap:10px;color:#cdbdcc}.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,.15);border-top-color:var(--pink);border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.footer{padding:22px 4px 0;color:#6f6470;font-size:10px;display:flex;justify-content:space-between;gap:15px}.badge{padding:5px 8px;border:1px solid rgba(255,255,255,.06);border-radius:999px}.toast{position:fixed;right:16px;bottom:16px;max-width:330px;padding:12px 14px;border-radius:13px;background:#180d1c;border:1px solid rgba(255,61,168,.3);box-shadow:var(--shadow);font-size:12px;opacity:0;transform:translateY(15px);pointer-events:none;transition:.25s;z-index:20}.toast.show{opacity:1;transform:none}.danger{color:var(--red)}
@media(max-width:850px){.grid{grid-template-columns:1fr}.hero h2{max-width:100%}}@media(max-width:620px){.wrap{width:min(100% - 18px,1180px);padding-top:16px}.topbar{margin-bottom:18px}.status{display:none}.hero{padding:20px;border-radius:21px}.card{padding:16px;border-radius:18px}.two,.summary{grid-template-columns:1fr 1fr}.summary .stat b{font-size:17px}.footer{flex-direction:column}.hero-actions{gap:7px}.pill{font-size:10px}}
</style>
</head>
<body>
<div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div>
<main class="wrap">
<header class="topbar">
  <div class="brand"><div class="logo">PX</div><div><h1>Proxy Intelligence</h1><p>NEXUS CONTROL CENTER</p></div></div>
  <div class="status"><i class="dot"></i> Engine online</div>
</header>
<section class="hero">
  <div class="eyebrow">Fraud • Reputation • Rotation</div>
  <h2>Professional proxy intelligence in a <span>smooth dark-pink workspace.</span></h2>
  <p>Run single checks, batch analysis, and rotation tests from one responsive dashboard. Built around your existing Python intelligence engine.</p>
  <div class="hero-actions"><span class="pill">● Live analysis</span><span class="pill">JSON-ready results</span><span class="pill">Mobile optimized</span></div>
</section>
<section class="grid">
  <div class="card">
    <div class="card-head"><div><h3>Single Proxy Scan</h3><small>Full intelligence lookup</small></div><div class="icon">⌁</div></div>
    <label for="proxy">Proxy endpoint</label><input class="input" id="proxy" placeholder="host:port or user:pass@host:port" autocomplete="off">
    <div class="two"><div><label for="ipqs">IPQualityScore key</label><input class="input" id="ipqs" type="password" placeholder="Optional"></div><div><label for="abuse">AbuseIPDB key</label><input class="input" id="abuse" type="password" placeholder="Optional"></div></div>
    <button class="btn" onclick="checkProxy()">Run Intelligence Scan</button>
    <div class="hint">Keys entered here are sent only with the current request. For a deployed public app, server-side environment variables are recommended.</div>
  </div>
  <div class="card">
    <div class="card-head"><div><h3>Rotation Monitor</h3><small>Detect changing exit IPs</small></div><div class="icon">↻</div></div>
    <label for="rotate">Rotating proxy endpoint</label><input class="input" id="rotate" placeholder="rotating-proxy-host:port" autocomplete="off">
    <label for="hits">Number of hits</label><input class="input" id="hits" type="number" min="1" max="50" value="10">
    <button class="btn" onclick="rotateTest()">Start Rotation Test</button>
    <div class="hint">Use only endpoints you own or are authorized to test. Results depend on the upstream proxy and external IP services.</div>
  </div>
  <div class="card">
    <div class="card-head"><div><h3>Batch Analyzer</h3><small>Up to 50 proxies per request</small></div><div class="icon">▦</div></div>
    <label for="batch">Proxy list</label><textarea id="batch" placeholder="One proxy per line\nhost1:port\nhost2:port\nhost3:port"></textarea>
    <button class="btn" onclick="batchCheck()">Analyze Batch</button>
  </div>
  <div class="card">
    <div class="card-head"><div><h3>Workflow</h3><small>Fast keyboard-friendly controls</small></div><div class="icon">✦</div></div>
    <div class="stat" style="margin-bottom:10px"><b>1</b><span>Enter an authorized proxy</span></div>
    <div class="stat" style="margin-bottom:10px"><b>2</b><span>Choose scan, batch, or rotation</span></div>
    <div class="stat"><b>3</b><span>Inspect or copy the returned JSON</span></div>
  </div>
</section>
<section class="card results">
  <div class="result-toolbar"><div><h3 style="margin:0">Live Results</h3><small id="resultMeta">Waiting for a scan</small></div><div class="actions"><button class="mini" onclick="copyResult()">Copy</button><button class="mini" onclick="downloadResult()">Save JSON</button><button class="mini" onclick="clearResult()">Clear</button></div></div>
  <div class="summary"><div class="stat"><b id="sStatus">—</b><span>Status</span></div><div class="stat"><b id="sItems">0</b><span>Items</span></div><div class="stat"><b id="sScore">—</b><span>Fraud score</span></div><div class="stat"><b id="sTime">—</b><span>Response</span></div></div>
  <div class="resultbox" id="resultBox"><div class="empty">Your analysis output will appear here.</div></div>
</section>
<footer class="footer"><span>Proxy Intelligence Nexus • Flask interface</span><span class="badge">Authorized use only</span></footer>
</main><div class="toast" id="toast"></div>
<script>
let lastResult=null;
const $=id=>document.getElementById(id);
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove('show'),2600)}
function keys(){return {ipqs_key:$('ipqs').value.trim(),abuseipdb_key:$('abuse').value.trim()}}
function setLoading(label){$('resultBox').innerHTML='<div class="loading"><span class="spinner"></span>'+label+'</div>';$('resultMeta').textContent='Processing external intelligence sources…';$('sStatus').textContent='RUN';$('sTime').textContent='…'}
function summarize(data,ms){$('sTime').textContent=ms+'ms';$('sStatus').textContent='OK';if(Array.isArray(data)){$('sItems').textContent=data.length;$('sScore').textContent='—'}else{$('sItems').textContent='1';let score=data.fraud_score ?? data.score ?? data.fraudScore;$('sScore').textContent=score==null?'—':score}}
async function post(url,body,label){setLoading(label);const start=performance.now();try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const text=await r.text();let data;try{data=JSON.parse(text)}catch{data={error:text||'Invalid server response'}}if(!r.ok)throw new Error(data.error||('Request failed ('+r.status+')'));lastResult=data;summarize(data,Math.round(performance.now()-start));$('resultBox').innerHTML='<pre class="result-json">'+escapeHtml(JSON.stringify(data,null,2))+'</pre>';$('resultMeta').textContent='Completed just now';toast('Analysis complete');}catch(e){lastResult={error:e.message};$('sStatus').textContent='ERR';$('sItems').textContent='0';$('sScore').textContent='—';$('sTime').textContent='—';$('resultBox').innerHTML='<pre class="result-json danger">'+escapeHtml(e.message)+'</pre>';$('resultMeta').textContent='Request failed';toast('Request failed')}}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function checkProxy(){const proxy=$('proxy').value.trim();if(!proxy)return toast('Enter a proxy endpoint first');post('/api/check',{proxy,...keys()},'Running proxy intelligence scan…')}
function batchCheck(){const proxies=$('batch').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);if(!proxies.length)return toast('Add at least one proxy');if(proxies.length>50)return toast('Maximum 50 proxies per request');post('/api/batch',{proxies,...keys()},'Analyzing proxy batch…')}
function rotateTest(){const proxy=$('rotate').value.trim();const hits=Math.max(1,Math.min(50,Number($('hits').value)||10));if(!proxy)return toast('Enter a rotating proxy endpoint first');post('/api/rotate',{proxy,hits},'Testing rotation behavior…')}
function clearResult(){lastResult=null;$('resultBox').innerHTML='<div class="empty">Your analysis output will appear here.</div>';$('resultMeta').textContent='Waiting for a scan';$('sStatus').textContent='—';$('sItems').textContent='0';$('sScore').textContent='—';$('sTime').textContent='—'}
async function copyResult(){if(lastResult==null)return toast('Nothing to copy yet');try{await navigator.clipboard.writeText(JSON.stringify(lastResult,null,2));toast('JSON copied')}catch{toast('Copy is unavailable in this browser')}}
function downloadResult(){if(lastResult==null)return toast('Nothing to save yet');const blob=new Blob([JSON.stringify(lastResult,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='proxy-intelligence-result.json';a.click();URL.revokeObjectURL(a.href)}
document.addEventListener('keydown',e=>{if(e.ctrlKey&&e.key==='Enter'){e.preventDefault();checkProxy()}});
</script>
</body></html>'''


def engine(data):
    return ProxyIntelligence(
        timeout=15,
        ipqs_key=data.get("ipqs_key") or os.environ.get("IPQS_API_KEY"),
        abuseipdb_key=data.get("abuseipdb_key") or os.environ.get("ABUSEIPDB_API_KEY"),
    )

@app.get("/")
def index():
    return render_template_string(HTML)

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "proxy-intelligence"})

@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    proxy = (data.get("proxy") or "").strip()
    if not proxy:
        return jsonify({"error": "Proxy is required"}), 400
    try:
        result = engine(data).check(proxy, full=True)
        return jsonify(asdict(result))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

@app.post("/api/batch")
def api_batch():
    data = request.get_json(silent=True) or {}
    proxies = data.get("proxies") or []
    if not proxies:
        return jsonify({"error": "At least one proxy is required"}), 400
    if not isinstance(proxies, list):
        return jsonify({"error": "proxies must be a list"}), 400
    if len(proxies) > 50:
        return jsonify({"error": "Maximum 50 proxies per request"}), 400
    proxies = [str(x).strip() for x in proxies if str(x).strip()]
    try:
        results = engine(data).check_many(proxies, threads=min(10, len(proxies)), full=True)
        return jsonify([asdict(x) for x in results])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

@app.post("/api/rotate")
def api_rotate():
    data = request.get_json(silent=True) or {}
    proxy = (data.get("proxy") or "").strip()
    if not proxy:
        return jsonify({"error": "Proxy is required"}), 400
    try:
        hits = max(1, min(50, int(data.get("hits", 10))))
    except (TypeError, ValueError):
        return jsonify({"error": "hits must be a number"}), 400
    try:
        return jsonify(RotationTester(timeout=15).test(proxy, hits=hits))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
