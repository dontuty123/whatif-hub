// Password gate (copied from NOAH tools/lib/gate.js): every published page holds only AES-GCM ciphertext of the real page.
// Key = PBKDF2(password, site salt, 200000, SHA-256); one key for the whole site, so one unlock opens every page.
// The key is remembered on the device (localStorage, user 2026-10-01: type the password once, then go straight in);
// a wrong or outdated key (password changed) is dropped and the form shows again.
// The decrypted page is written only after the gate page has fully loaded: document.open() while the gate is still
// loading appends to the hidden gate instead of replacing it (blank white page on reload, found 2026-10-01).
// IV is derived from the plaintext, so builds are deterministic (site-publish --check works) and unique per content.
"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const CFG = path.join(__dirname, "..", "config", "site.json");
const ITER = 200000, STORE = "whatifHubKey";
function siteKey() {
  const cfg = JSON.parse(fs.readFileSync(CFG, "utf8"));
  const salt = crypto.createHash("sha256").update("whatif-hub-salt").digest().subarray(0, 16);
  return { salt, key: crypto.pbkdf2Sync(cfg.password, salt, ITER, 32, "sha256") };
}
let cached = null;
function gate(page) {
  const { salt, key } = cached || (cached = siteKey());
  const iv = crypto.createHash("sha256").update(page).digest().subarray(0, 12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(page, "utf8"), c.final(), c.getAuthTag()]);
  const b64 = b => Buffer.from(b).toString("base64");
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>What If Hub</title>
<meta name="robots" content="noindex,nofollow">
<link rel="icon" href="data:,">
<script>try{var t=localStorage.getItem("whatifHubTheme");if(t==="light"||t==="dark")document.documentElement.dataset.theme=t;if(localStorage.getItem("${STORE}"))document.documentElement.className="unlocking"}catch(e){}</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&family=Be+Vietnam+Pro:wght@400;500;600&display=swap">
<style>
:root{--bg:#EDEFF4;--panel:#FFFFFF;--ink:#172036;--muted:#5B6479;--line:#D5DAE5;--lamp:#B8700F;--on-lamp:#FFFFFF;--bad:#B4412F}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0E1322;--panel:#161D31;--ink:#E7EAF3;--muted:#9AA3B9;--line:#27304A;--lamp:#F2A93E;--on-lamp:#1B1206;--bad:#F08A77;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0E1322;--panel:#161D31;--ink:#E7EAF3;--muted:#9AA3B9;--line:#27304A;--lamp:#F2A93E;--on-lamp:#1B1206;--bad:#F08A77;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:radial-gradient(ellipse at 50% 35%,color-mix(in srgb,var(--lamp) 14%,var(--bg)),var(--bg) 60%);color:var(--ink);font-family:"Be Vietnam Pro","Segoe UI",system-ui,sans-serif}
.card{width:min(100%,380px);background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:28px 26px;box-shadow:0 18px 50px rgba(0,0,0,.12)}
.lamp{width:44px;height:44px;border-radius:50%;background:radial-gradient(circle at 50% 45%,#FFE3A3,var(--lamp) 60%,transparent 72%);margin:0 0 14px;box-shadow:0 0 30px color-mix(in srgb,var(--lamp) 55%,transparent)}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:600}
h1{font-family:"Bricolage Grotesque","Segoe UI",system-ui,sans-serif;font-weight:800;font-size:32px;letter-spacing:-.02em;margin:6px 0 4px}
h1 span{color:var(--lamp)}
p{margin:0 0 18px;color:var(--muted);font-size:14px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
input{width:100%;font-size:16px;font-family:inherit;padding:11px 13px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--ink)}
input:focus{outline:2px solid var(--lamp);outline-offset:1px;border-color:transparent}
button{margin-top:12px;width:100%;font-size:15px;font-weight:600;font-family:inherit;padding:11px;border:0;border-radius:10px;background:var(--lamp);color:var(--on-lamp);cursor:pointer}
button[disabled]{opacity:.6;cursor:progress}
.err{color:var(--bad);font-size:13px;min-height:18px;margin:8px 0 0}
.unlocking .card{visibility:hidden}
</style></head><body>
<form class="card" id="f" autocomplete="off">
  <div class="lamp" aria-hidden="true"></div>
  <div class="eyebrow">Quản lý kênh</div>
  <h1>What If <span>Hub</span></h1>
  <p>Trang nội bộ. Nhập mật khẩu để xem.</p>
  <label for="pw">Mật khẩu</label>
  <input id="pw" type="password" autocomplete="current-password" autofocus>
  <button id="go" type="submit">Mở</button>
  <div class="err" id="err" role="alert"></div>
</form>
<script>
(function(){
  var D={s:"${b64(salt)}",i:"${b64(iv)}",c:"${b64(ct)}"},K="${STORE}";
  function b(s){var r=atob(s),a=new Uint8Array(r.length);for(var i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a}
  function open(raw){return crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]).then(function(k){return crypto.subtle.decrypt({name:"AES-GCM",iv:b(D.i)},k,b(D.c))}).then(function(p){return new TextDecoder().decode(p)})}
  function paint(h){function go(){document.open();document.write(h);document.close()}if(document.readyState==="complete")setTimeout(go,0);else window.addEventListener("load",function(){setTimeout(go,0)})}
  function keep(raw){try{var s="";raw.forEach(function(x){s+=String.fromCharCode(x)});localStorage.setItem(K,btoa(s))}catch(e){}}
  function show(){document.documentElement.className="";try{document.getElementById("pw").focus()}catch(e){}}
  function derive(pw){return crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveBits"]).then(function(k){return crypto.subtle.deriveBits({name:"PBKDF2",salt:b(D.s),iterations:${ITER},hash:"SHA-256"},k,256)}).then(function(bits){return new Uint8Array(bits)})}
  var saved=null;try{saved=localStorage.getItem(K)}catch(e){}
  if(saved){try{open(b(saved)).then(paint).catch(function(){try{localStorage.removeItem(K)}catch(e){}show()})}catch(e){show()}}else show();
  document.getElementById("f").addEventListener("submit",function(ev){ev.preventDefault();var btn=document.getElementById("go"),err=document.getElementById("err");btn.disabled=true;err.textContent="";
    derive(document.getElementById("pw").value).then(function(raw){return open(raw).then(function(h){keep(raw);paint(h)})})
    .catch(function(){btn.disabled=false;err.textContent="Sai mật khẩu, thử lại nhé."})});
})();
</script>
</body></html>
`;
}
module.exports = { gate };
