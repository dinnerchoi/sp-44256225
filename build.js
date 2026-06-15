/* Signal Pool(../pool.html + ../pool.json)을 자체완결 HTML로 합친 뒤
   비밀번호로 AES-GCM 암호화해 loader(index.html) 생성.
   공개 저장소엔 암호문만. 폰에서 비밀번호 입력 → 브라우저에서 복호화 → iframe 렌더.
   (2week-plan/_deploy/build.js 와 동일 패턴) */
const fs=require('fs');const path=require('path');

// 1) 자체완결 앱 HTML: pool.json 을 인라인해 외부 pool.js 의존 제거
let app=fs.readFileSync(path.join(__dirname,'..','pool.html'),'utf8');
const pool=fs.readFileSync(path.join(__dirname,'..','pool.json'),'utf8');
const poolMin=JSON.stringify(JSON.parse(pool)); // 공백 제거
if(app.indexOf('<script src="pool.js"></script>')<0){
  console.error('ERROR: pool.html 에 <script src="pool.js"></script> 가 없습니다. 인라인 실패.');
  process.exit(1);
}
app=app.replace('<script src="pool.js"></script>','<script>window.POOL='+poolMin+';</script>');

function gen(){const a="abcdefghijkmnpqrstuvwxyz23456789";const r=crypto.getRandomValues(new Uint8Array(8));let s="";for(const x of r)s+=a[x%a.length];return s.slice(0,4)+"-"+s.slice(4);}
const pass=process.env.PASS||gen();

const LOADER=`<!DOCTYPE html><html lang="ko"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>KALDI ART · Signal Pool</title>
<link href="https://fonts.googleapis.com/css2?family=Rethink+Sans:wght@500;700&family=Noto+Sans+KR:wght@400;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0}html,body{height:100%}
body{font-family:'Rethink Sans','Noto Sans KR',-apple-system,Helvetica,Arial,sans-serif;background:#0d1b2a;color:#f8f7f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.box{width:100%;max-width:340px;text-align:center}
.wm{font-weight:700;letter-spacing:.28em;font-size:15px;margin-bottom:6px}
.sub{font-size:11px;letter-spacing:.06em;color:#9aa3ad;text-transform:uppercase;margin-bottom:30px}
input{width:100%;font-family:inherit;font-size:17px;text-align:center;letter-spacing:.08em;padding:14px;border:1px solid #2b3a4d;border-radius:12px;background:#13243a;color:#fff;outline:none}
input:focus{border-color:#f8f7f5}
button{width:100%;margin-top:11px;font-family:inherit;font-size:15px;font-weight:700;padding:14px;border:none;border-radius:12px;background:#f8f7f5;color:#0d1b2a;cursor:pointer}
.err{color:#e8a07a;font-size:13px;margin-top:14px;min-height:18px}
.hint{color:#6b7785;font-size:11px;margin-top:22px;line-height:1.6}
</style></head>
<body>
<div class="box" id="gate">
  <div class="wm">KALDI&nbsp;ART</div>
  <div class="sub">Signal Pool · Private</div>
  <input id="pc" type="password" inputmode="text" autocomplete="off" placeholder="비밀번호" enterkeyhint="go">
  <button id="go">열기</button>
  <div class="err" id="err"></div>
  <div class="hint">텔레그램으로 받은 비밀번호를 입력하세요.<br>★개발 선택은 이 기기에 저장됩니다.</div>
</div>
<script>
var P=__PAYLOAD__;
function b64d(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});}
async function dec(pass){
  var enc=new TextEncoder();
  var bk=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  var key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64d(P.s),iterations:150000,hash:'SHA-256'},bk,{name:'AES-GCM',length:256},false,['decrypt']);
  var buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(P.i)},key,b64d(P.c));
  return new TextDecoder().decode(buf);
}
function show(html){
  document.body.innerHTML="";document.documentElement.style.height="100%";document.body.style.cssText="margin:0;height:100%";
  var f=document.createElement('iframe');
  f.setAttribute('allow','clipboard-write');
  f.style.cssText="position:fixed;inset:0;width:100%;height:100%;border:0";
  document.body.appendChild(f);f.srcdoc=html;
}
async function go(){
  var p=document.getElementById('pc').value.trim();if(!p)return;
  document.getElementById('err').textContent="";
  try{var html=await dec(p);try{sessionStorage.setItem('sppass',p);}catch(e){}show(html);}
  catch(e){document.getElementById('err').textContent="비밀번호가 맞지 않아요. 다시 시도하세요.";}
}
document.getElementById('go').addEventListener('click',go);
document.getElementById('pc').addEventListener('keydown',function(e){if(e.key==='Enter')go();});
window.addEventListener('load',async function(){
  var p=null;try{p=sessionStorage.getItem('sppass');}catch(e){}
  if(p){try{show(await dec(p));}catch(e){}}
  document.getElementById('pc').focus();
});
</script>
</body></html>`;

(async()=>{
  const enc=new TextEncoder();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const bk=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},bk,{name:'AES-GCM',length:256},false,['encrypt']);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(app));
  const b64=b=>Buffer.from(b).toString('base64');
  const payload=JSON.stringify({s:b64(salt),i:b64(iv),c:b64(new Uint8Array(ct))});
  fs.writeFileSync(path.join(__dirname,'index.html'),LOADER.replace('__PAYLOAD__',payload));
  console.log("PASSCODE="+pass);
  console.log("ITEMS="+JSON.parse(pool).length);
  console.log("SIZE="+(payload.length/1024).toFixed(0)+"KB");
})();
