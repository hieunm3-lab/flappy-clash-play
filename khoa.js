// Trang khoá + chọn bản của link Flappy Clash (pages_sync.py chép thành khoa.js). Mỗi bản chơi nằm trong <id>.bin đã mã hoá (pages_mahoa.js).
// Mở khoá 2 cách: (1) nhập MÃ SỐ (bàn phím số to cho điện thoại) → PBKDF2 mở pass.bin ra khoá thật; (2) "Dùng khoá": chọn file flappy-clash.key.
// Mở được 1 lần → trình duyệt nhớ khoá thật (localStorage); bỏ nhớ: mở link kèm ?quenkhoa. Sai mã số → chờ tăng dần (1, 2, 4… ≤ 30 s).
// Chỉ 1 bản → mở thẳng bản đó; nhiều bản → menu. ?ban=<id> → tải .bin, giải mã (WebCrypto AES-GCM + gunzip), chạy trong iframe blob phủ kín màn.
(()=>{const me=document.currentScript,KIEM=me.dataset.kiem,PASS=me.dataset.pass||"",BANS=JSON.parse(document.getElementById("fcbans").textContent);
const LS="fcplay_key",LF="fcplay_fail";
const lsGet=k=>{try{return localStorage.getItem(k)}catch(e){return null}},lsSet=(k,v)=>{try{v==null?localStorage.removeItem(k):localStorage.setItem(k,v)}catch(e){}};
if(/[?&]quenkhoa\b/.test(location.search)){lsSet(LS,null);history.replaceState(null,"",location.pathname)}
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),tob64=u=>btoa(String.fromCharCode(...u));
let KEY=null,frame=null,url=null;const $=s=>document.querySelector(s);
(()=>{const st=document.createElement("style");st.textContent=`
#fcbox form{display:flex;gap:8px;margin:0 0 12px}
#fcpin{flex:1;min-width:0;font:600 26px/1 ui-monospace,Consolas,monospace;letter-spacing:.32em;text-align:center;padding:12px 8px;border-radius:10px;border:1px solid #2b3447;background:#0f1420;color:#fff;-webkit-text-security:disc;outline:none}
#fcpin:focus{border-color:#fbbf24}#fcpin::placeholder{letter-spacing:normal;font-size:16px;color:#5b6478}
#fcbox button{font:600 18px/1 "Segoe UI",system-ui,sans-serif;border-radius:10px;border:1px solid #2b3447;background:#1d2536;color:#fff;cursor:pointer;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
#fcbox button:active{background:#2b3447}#fcbox button:disabled{opacity:.45;cursor:default}
#fcok{padding:0 18px;background:#fbbf24;color:#111;border-color:#fbbf24}
#fcbox .kp{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
#fcbox .kp button{height:60px;font-size:24px}#fcbox .kp .ok{background:#fbbf24;color:#111;border-color:#fbbf24;font-size:18px}
@media (pointer:fine){#fcbox .kp button{height:46px;font-size:20px}}
#fcbox .hint{font-size:12px;color:#7d879b;margin:12px 0 0}#fcbox .hint a{color:#a7b0c2}`;document.head.appendChild(st)})();
async function open(key,buf){const u=new Uint8Array(buf);if(String.fromCharCode(...u.subarray(0,4))!=="FCE1")throw new Error("file mã hoá sai định dạng");
  let z;try{z=await crypto.subtle.decrypt({name:"AES-GCM",iv:u.subarray(4,16)},key,u.subarray(16))}catch(e){throw new Error(e.name==="OperationError"?"sai khoá":e.message)}
  return new Response(new Blob([z]).stream().pipeThrough(new DecompressionStream("gzip"))).blob()}
async function get(u,prog){const r=await fetch(u);if(!r.ok)throw new Error("không tải được "+u.split("?")[0]+" ("+r.status+")");
  const n=+r.headers.get("content-length")||0;if(!prog||!r.body||!n)return r.arrayBuffer();
  const rd=r.body.getReader(),parts=[];let got=0;for(;;){const {done,value}=await rd.read();if(done)break;parts.push(value);got+=value.length;prog(got/n)}
  return new Blob(parts).arrayBuffer()}
async function tryKey(k){const raw=b64(k);if(raw.length!==32)throw new Error("khoá phải 32 byte");
  const key=await crypto.subtle.importKey("raw",raw,"AES-GCM",false,["decrypt"]);
  if(await (await open(key,await get(KIEM))).text()!=="FC-OK")throw new Error("sai khoá");KEY=key}
// pass.bin: "FCP1" + số vòng u32 BE + salt 16 + iv 12 + AES-GCM(khoá 32 byte)+tag 16 → trả khoá thật dạng base64
async function passKey(pc){const u=new Uint8Array(await get(PASS));if(String.fromCharCode(...u.subarray(0,4))!=="FCP1")throw new Error("pass.bin sai định dạng");
  const it=new DataView(u.buffer,u.byteOffset).getUint32(4),base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pc),"PBKDF2",false,["deriveKey"]);
  const wk=await crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:u.subarray(8,24),iterations:it},base,{name:"AES-GCM",length:256},false,["decrypt"]);
  let raw;try{raw=await crypto.subtle.decrypt({name:"AES-GCM",iv:u.subarray(24,36)},wk,u.subarray(36))}catch(e){throw new Error(e.name==="OperationError"?"sai mã số":e.message)}
  return tob64(new Uint8Array(raw))}
const msg=(t,ok)=>{const e=$("#fcmsg");if(e){e.textContent=t;e.className=ok?"ok":""}};
const fails=()=>{try{return JSON.parse(lsGet(LF))||{n:0,t:0}}catch(e){return {n:0,t:0}}};
function lockUI(why){document.title="Flappy Clash";
  const keyHTML=`<div class="d" tabindex="0">📂 Bấm để chọn file khoá — hoặc kéo thả file vào đây</div><input type="file" accept=".key,.txt" hidden>`;
  $("#fcbox").innerHTML=PASS?`<h1>🔒 Flappy Clash</h1><p>Bản demo nội bộ đã mã hoá. Nhập <b>mã số</b> để mở (xin người quản lý dự án). Chỉ cần nhập 1 lần — trình duyệt này sẽ tự nhớ.</p>
<div id="fcpass"><form autocomplete="off"><input id="fcpin" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="off" autocorrect="off" spellcheck="false" placeholder="mã số 8 chữ số" aria-label="Mã số"><button id="fcok" type="submit">Mở</button></form>
<div class="kp">${[1,2,3,4,5,6,7,8,9].map(n=>`<button type="button" data-k="${n}">${n}</button>`).join("")}<button type="button" data-k="x" aria-label="Xoá">⌫</button><button type="button" data-k="0">0</button><button type="button" data-k="ok" class="ok">Mở</button></div></div>
<div id="fckey" hidden>${keyHTML}</div><div id="fcmsg"></div><p class="hint"><a href="#" id="fcdoi">Dùng khoá</a> <span id="fcdoit">(file flappy-clash.key)</span></p>`
  :`<h1>🔒 Flappy Clash</h1><p>Bản demo nội bộ đã mã hoá. Chọn file khoá <b>flappy-clash.key</b> để mở (xin file từ người quản lý dự án). Chỉ cần chọn 1 lần — trình duyệt này sẽ tự nhớ.</p>${keyHTML}<div id="fcmsg"></div>`;
  if(why)msg(why);
  // --- mã số
  const pin=$("#fcpin");let busy=false,tick=null;
  function gate(){const f=fails(),w=f.n?Math.min(30,2**(f.n-1))*1000-(Date.now()-f.t):0;
    document.querySelectorAll("#fcpass button").forEach(b=>b.disabled=busy||w>0);clearTimeout(tick);
    if(w>0){msg("❌ Sai mã số — thử lại sau "+Math.ceil(w/1000)+" s");tick=setTimeout(gate,Math.min(w,250))}
    else if(!busy&&/thử lại sau/.test(($("#fcmsg")||{}).textContent||""))msg("❌ Sai mã số — nhập lại");return w<=0&&!busy}
  async function submit(){if(!pin||!gate())return;const pc=pin.value.replace(/\D/g,"");if(pc.length!==8){msg("Mã số có 8 chữ số");return}
    busy=true;gate();msg("⏳ Đang kiểm mã số…",1);
    try{const k=await passKey(pc);await tryKey(k);lsSet(LS,k);lsSet(LF,null);busy=false;clearTimeout(tick);route()}
    catch(e){busy=false;pin.value="";if(/sai mã số/.test(e.message)){const f=fails();lsSet(LF,JSON.stringify({n:f.n+1,t:Date.now()}));msg("❌ Sai mã số — nhập lại")}else msg("❌ "+e.message);gate()}}
  if(pin){pin.oninput=()=>{pin.value=pin.value.replace(/\D/g,"").slice(0,8);if(pin.value.length===8)submit()};
    $("#fcpass form").onsubmit=e=>{e.preventDefault();submit()};
    document.querySelectorAll("#fcpass .kp button").forEach(b=>b.onclick=()=>{const k=b.dataset.k;
      if(k==="ok")return submit();if(k==="x")pin.value=pin.value.slice(0,-1);else if(pin.value.length<8)pin.value+=k;if(pin.value.length===8)submit()});
    if(matchMedia("(pointer:fine)").matches)pin.focus();gate();
    $("#fcdoi").onclick=e=>{e.preventDefault();const k=$("#fckey"),p=$("#fcpass");k.hidden=!k.hidden;p.hidden=!k.hidden;
      $("#fcdoi").textContent=k.hidden?"Dùng khoá":"Dùng mã số";$("#fcdoit").hidden=!k.hidden;msg("")}}
  // --- file khoá
  const d=$("#fcbox .d"),inp=$("#fcbox input[type=file]");
  async function use(f){if(!f)return;msg("⏳ Đang kiểm khoá…",1);
    try{const m=/FCKEY1:([A-Za-z0-9+/=]+)/.exec(await f.text());if(!m)throw new Error("không phải file khoá Flappy Clash");
      await tryKey(m[1]);lsSet(LS,m[1]);clearTimeout(tick);route()}catch(e){msg("❌ "+e.message)}}
  d.onclick=()=>inp.click();d.onkeydown=e=>{if(e.key==="Enter"||e.key===" ")inp.click()};inp.onchange=()=>use(inp.files[0]);
  document.body.ondragover=e=>{e.preventDefault();d.classList.add("on")};document.body.ondragleave=()=>d.classList.remove("on");
  document.body.ondrop=e=>{e.preventDefault();d.classList.remove("on");use(e.dataTransfer.files[0])}}
function menuUI(){$("#fcbox").innerHTML=`<h1>🐤 Flappy Clash</h1><p>Chọn bản để chơi. Bấm Back của trình duyệt để quay lại đây.</p>`+
  BANS.map(b=>`<a class="b" href="?ban=${b.id}" data-id="${b.id}"><b>${b.ten}</b><span>${b.mota}</span><i>Build ${b.ngay} · ${b.mb} MB</i></a>`).join("")+
  `<div id="fcmsg"></div><p class="q"><a href="?quenkhoa">Quên khoá trên trình duyệt này</a></p>`;
  document.querySelectorAll("#fcbox a.b").forEach(a=>a.onclick=e=>{e.preventDefault();history.pushState(null,"","?ban="+a.dataset.id);route()})}
async function play(b){$("#fcbox").innerHTML=`<h1>🐤 ${b.ten}</h1><p>Đang tải bản chơi (${b.mb} MB)…</p><div class="bar"><div></div></div><div id="fcmsg"></div>`;
  try{const buf=await get(b.bin,p=>{const e=$("#fcbox .bar div");if(e)e.style.width=(p*100).toFixed(0)+"%"});
    msg("⏳ Đang giải mã…",1);const html=await open(KEY,buf);
    if(new URLSearchParams(location.search).get("ban")!==b.id)return;
    url=URL.createObjectURL(new Blob([html],{type:"text/html"}));frame=document.createElement("iframe");frame.id="fcgame";
    frame.allow="autoplay; fullscreen; gamepad";frame.src=url;frame.onload=()=>frame.contentWindow.focus();
    document.body.appendChild(frame);$("#fcwrap").hidden=true;document.title="Flappy Clash — "+b.ten}
  catch(e){msg("❌ "+e.message)}}
function route(){if(frame){frame.remove();frame=null;URL.revokeObjectURL(url);url=null}$("#fcwrap").hidden=false;document.title="Flappy Clash";
  document.body.ondragover=document.body.ondrop=document.body.ondragleave=null;
  if(!KEY)return lockUI();const id=new URLSearchParams(location.search).get("ban");let b=BANS.find(x=>x.id===id);
  if(!b&&BANS.length===1){b=BANS[0];history.replaceState(null,"","?ban="+b.id)}b?play(b):menuUI()}
window.addEventListener("popstate",route);
const saved=lsGet(LS);
if(saved){$("#fcbox").innerHTML=`<h1>🐤 Flappy Clash</h1><div id="fcmsg" class="ok">⏳ Đang mở bằng khoá đã nhớ…</div>`;
  tryKey(saved).then(route).catch(e=>{if(/sai khoá|32 byte/.test(e.message))lsSet(LS,null);lockUI("❌ Khoá đã nhớ không dùng được ("+e.message+") — nhập lại mã số / chọn lại file khoá")})}
else lockUI()})();
