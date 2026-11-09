// Trang chọn bản của link Flappy Clash (pages_sync.py chép thành khoa.js). Mỗi bản chơi nằm trong <id>.bin đã mã hoá (pages_mahoa.js).
// Người mở link chọn file flappy-clash.key 1 lần → trình duyệt nhớ (localStorage); bỏ nhớ: mở link kèm ?quenkhoa.
// Chọn bản → ?ban=<id> → tải .bin, giải mã (WebCrypto AES-GCM + gunzip), chạy trong iframe blob phủ kín màn. Nút Back quay về menu.
(()=>{const me=document.currentScript,KIEM=me.dataset.kiem,BANS=JSON.parse(document.getElementById("fcbans").textContent);
const LS="fcplay_key";const lsGet=()=>{try{return localStorage.getItem(LS)}catch(e){return null}},lsSet=v=>{try{v==null?localStorage.removeItem(LS):localStorage.setItem(LS,v)}catch(e){}};
if(/[?&]quenkhoa\b/.test(location.search)){lsSet(null);history.replaceState(null,"",location.pathname)}
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
let KEY=null,frame=null,url=null;const $=s=>document.querySelector(s);
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
const msg=(t,ok)=>{const e=$("#fcmsg");if(e){e.textContent=t;e.className=ok?"ok":""}};
function lockUI(){$("#fcbox").innerHTML=`<h1>🔒 Flappy Clash</h1><p>Bản demo nội bộ đã mã hoá. Chọn file khoá <b>flappy-clash.key</b> để mở (xin file từ người quản lý dự án). Chỉ cần chọn 1 lần — trình duyệt này sẽ tự nhớ.</p>
<div class="d" tabindex="0">📂 Bấm để chọn file khoá — hoặc kéo thả file vào đây</div><input type="file" accept=".key,.txt" hidden><div id="fcmsg"></div>`;
  const d=$("#fcbox .d"),inp=$("#fcbox input");
  async function use(f){if(!f)return;msg("⏳ Đang kiểm khoá…",1);
    try{const m=/FCKEY1:([A-Za-z0-9+/=]+)/.exec(await f.text());if(!m)throw new Error("không phải file khoá Flappy Clash");
      await tryKey(m[1]);lsSet(m[1]);route()}catch(e){msg("❌ "+e.message)}}
  d.onclick=()=>inp.click();d.onkeydown=e=>{if(e.key==="Enter"||e.key===" ")inp.click()};inp.onchange=()=>use(inp.files[0]);
  document.body.ondragover=e=>{e.preventDefault();d.classList.add("on")};document.body.ondragleave=()=>d.classList.remove("on");
  document.body.ondrop=e=>{e.preventDefault();d.classList.remove("on");use(e.dataTransfer.files[0])}}
function menuUI(){document.body.ondragover=document.body.ondrop=null;
  $("#fcbox").innerHTML=`<h1>🐤 Flappy Clash</h1><p>Chọn bản để chơi. Bấm Back của trình duyệt để quay lại đây.</p>`+
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
  if(!KEY)return lockUI();const id=new URLSearchParams(location.search).get("ban"),b=BANS.find(x=>x.id===id);b?play(b):menuUI()}
window.addEventListener("popstate",route);
const saved=lsGet();
if(saved){$("#fcbox").innerHTML=`<h1>🐤 Flappy Clash</h1><div id="fcmsg" class="ok">⏳ Đang mở bằng khoá đã nhớ…</div>`;
  tryKey(saved).then(route).catch(e=>{if(/sai khoá|32 byte/.test(e.message))lsSet(null);lockUI();msg("❌ Khoá đã nhớ không dùng được ("+e.message+") — chọn lại file khoá")})}
else lockUI()})();
