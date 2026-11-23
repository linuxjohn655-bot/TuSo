(()=>{
'use strict';
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>(crypto.randomUUID?crypto.randomUUID():'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,c=>{const r=crypto.getRandomValues(new Uint8Array(1))[0]&15;return (c==='x'?r:(r&3|8)).toString(16)}));
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
const phone=()=>matchMedia('(max-width:760px)').matches;
const wait=ms=>new Promise(r=>setTimeout(r,ms));

/* ---------- icons ---------- */
const svg=(d,s=18)=>`<svg viewBox="0 0 24 24" width="${s}" height="${s}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const I={
  gear:svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
  send:svg('<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>'),
  back:svg('<path d="M15 18l-6-6 6-6"/>',20),
  x:svg('<path d="M18 6 6 18M6 6l12 12"/>',20),
  bug:svg('<rect x="8" y="8" width="8" height="11" rx="4"/><path d="M9 5.5 10.5 8M15 5.5 13.5 8M8 12H4M16 12h4M8.5 16.5 5 18.5M15.5 16.5 19 18.5M12 8v11"/>')
};

/* ---------- data lives in memory; Supabase is the source of truth ---------- */
const storeOK=true;
const blank=()=>({users:[],session:null,data:{},dms:{},servers:{},bugs:[]});
let db=blank();
const load=()=>db;
function save(){queueFlush()}
/* ---------- cloud: Supabase + end-to-end encryption ---------- */
const CFG=window.TUSO_CONFIG||{url:'https://jurtdrigndqflozwiffb.supabase.co',key:'sb_publishable_eoo-b7WzkexPDs84VXp0fQ_IAmByBbk'};
const te=new TextEncoder(),td=new TextDecoder();
const b64=buf=>{const a=new Uint8Array(buf);let s='';for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode.apply(null,a.subarray(i,i+0x8000));return btoa(s)};
const ub64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const subtle=(window.crypto&&crypto.subtle)||null;
const emsg=e=>(e&&(e.message||e.error_description||e.msg))||'Something went wrong. Try again.';
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const E2E={
  iters:300000,
  async pwKey(pw,salt){
    const k=await subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
    return subtle.deriveKey({name:'PBKDF2',salt:ub64(salt),iterations:E2E.iters,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  },
  async recKey(rec){
    const norm=rec.toUpperCase().replace(/[^A-Z2-7]/g,'');
    const h=await subtle.digest('SHA-256',te.encode('tuso/recovery/v1/'+norm));
    return subtle.importKey('raw',h,{name:'AES-GCM'},false,['encrypt','decrypt']);
  },
  newRecovery(){
    const a=crypto.getRandomValues(new Uint8Array(32));let bits=0,val=0,out='';
    for(const x of a){val=(val<<8)|x;bits+=8;while(bits>=5){out+=B32[(val>>>(bits-5))&31];bits-=5}}
    if(bits)out+=B32[(val<<(5-bits))&31];
    return out.match(/.{1,4}/g).join('-');
  },
  async seal(key,bytes,aad){
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const p={name:'AES-GCM',iv};if(aad)p.additionalData=te.encode(aad);
    return {iv:b64(iv),ct:b64(await subtle.encrypt(p,key,bytes))};
  },
  async open(key,iv,ct,aad){
    const p={name:'AES-GCM',iv:ub64(iv)};if(aad)p.additionalData=te.encode(aad);
    return new Uint8Array(await subtle.decrypt(p,key,ub64(ct)));
  },
  async wrapIdentity(pkcs8,pub,pw,rec){
    const salt=b64(crypto.getRandomValues(new Uint8Array(16)));
    const w=await E2E.seal(await E2E.pwKey(pw,salt),pkcs8,'tuso/priv');
    rec=rec||E2E.newRecovery();
    const r=await E2E.seal(await E2E.recKey(rec),pkcs8,'tuso/priv-rec');
    return {pub,pkcs8,enc_priv:w.iv+'.'+w.ct,key_salt:salt,enc_priv_rec:r.iv+'.'+r.ct,recovery:rec};
  },
  async newIdentity(pw){
    const kp=await subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
    const j=await subtle.exportKey('jwk',kp.publicKey);
    const pub={kty:j.kty,crv:j.crv,x:j.x,y:j.y};
    const pkcs8=new Uint8Array(await subtle.exportKey('pkcs8',kp.privateKey));
    return E2E.wrapIdentity(pkcs8,pub,pw);
  },
  importPriv:pkcs8=>subtle.importKey('pkcs8',pkcs8,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),
  importPub:jwk=>subtle.importKey('jwk',{kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y},{name:'ECDH',namedCurve:'P-256'},false,[]),
  async openPriv(pw,blob,salt){const [iv,ct]=blob.split('.');return E2E.open(await E2E.pwKey(pw,salt),iv,ct,'tuso/priv')},
  async openPrivRec(rec,blob){const [iv,ct]=blob.split('.');return E2E.open(await E2E.recKey(rec),iv,ct,'tuso/priv-rec')},
  async shared(info,peerPub){
    const bits=await subtle.deriveBits({name:'ECDH',public:await E2E.importPub(peerPub)},SB.priv,256);
    const hk=await subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
    return subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(0),info:te.encode(info)},hk,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  },
  async fingerprint(pub){
    const h=new Uint8Array(await subtle.digest('SHA-256',te.encode(pub.x+'.'+pub.y))).slice(0,16);
    return [...h].map(b=>b.toString(16).padStart(2,'0')).join('').match(/.{4}/g).join(' ');
  }
};

/* keeps the unlocked (non-extractable) key in this browser so a reload doesn't ask for the password again */
const KS={
  open:()=>new Promise((res,rej)=>{const r=indexedDB.open('tuso-keys',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error)}),
  async get(id){try{const d=await KS.open();return await new Promise(res=>{const q=d.transaction('k').objectStore('k').get(id);q.onsuccess=()=>res(q.result||null);q.onerror=()=>res(null)})}catch(e){return null}},
  async set(id,v){try{const d=await KS.open();await new Promise(res=>{const t=d.transaction('k','readwrite');t.objectStore('k').put(v,id);t.oncomplete=res;t.onerror=res})}catch(e){}},
  async del(id){try{const d=await KS.open();await new Promise(res=>{const t=d.transaction('k','readwrite');t.objectStore('k').delete(id);t.oncomplete=res;t.onerror=res})}catch(e){}}
};

/* ---------- state ---------- */
let sb=null;
const SB={skew:0,user:null,priv:null,ready:false,tick:0,timer:0,chan:null,pulling:false,flushing:null,flushT:0,errAt:0,
  maxDm:0,maxSys:0,maxSrv:0,srvDirty:false,bugDirty:false,syn:null,dmK:new Map(),fp:new Map(),media:new Set(),healed:new Set(),recon:false,pv:null};
const freshSyn=()=>({profile:{},prefs:'',state:new Map(),dm:new Set(),srv:new Set()});
function resetCloud(){
  clearInterval(SB.timer);clearTimeout(SB.flushT);
  if(sb&&SB.chan){try{sb.removeChannel(SB.chan)}catch(e){}}
  Object.assign(SB,{user:null,priv:null,ready:false,tick:0,timer:0,chan:null,pulling:false,flushing:null,maxDm:0,maxSys:0,maxSrv:0,syn:null,pv:null,recon:false});
  SB.dmK.clear();SB.media.clear();SB.healed.clear();
}
const PCOLS='id,username,display,bio,banner,status,seen,role,hunter,ban,protected,pubkey,created';
const mapProfile=r=>({id:r.id,username:r.username,display:r.display,bio:r.bio||'',banner:r.banner||0,status:r.status||'online',seen:+r.seen||0,
  role:r.role==='user'?undefined:r.role,hunter:r.hunter||undefined,ban:r.ban||undefined,protected:!!r.protected,pubkey:r.pubkey||null,created:+r.created||0});
const profFields=u=>({username:u.username,display:u.display,bio:u.bio||'',avatar:u.avatar||null,banner:u.banner||0,banner_img:u.bannerImg||null,status:u.status||'online',seen:u.seen||0});
async function fetchAll(make){
  const out=[];
  for(let from=0;;from+=1000){const {data,error}=await make(from,from+999);if(error)throw error;out.push(...data);if(data.length<1000)break}
  return out;
}
const chunk=(a,n)=>{const o=[];for(let i=0;i<a.length;i+=n)o.push(a.slice(i,i+n));return o};
const byId=id=>db.users.find(u=>u.id===id);
const snow=()=>Date.now()+(SB.skew||0);

/* ---------- conversation keys + decoding ---------- */
async function dmKeyFor(peer){
  if(!peer||!peer.pubkey)throw new Error('no key');
  const ck=peer.id+':'+peer.pubkey.x;
  if(SB.dmK.has(ck))return SB.dmK.get(ck);
  const k=await E2E.shared('tuso/dm/v1/'+dmKey(me.id,peer.id),peer.pubkey);
  SB.dmK.set(ck,k);return k;
}
const BAD='🔒 This message can’t be decrypted on this device.';
async function decodeDm(r){
  const peer=byId(r.a===me.id?r.b:r.a);
  try{
    const k=await dmKeyFor(peer);
    return {id:r.id,from:r.sender,ts:+r.ts,text:td.decode(await E2E.open(k,r.iv,r.ct,`dm:${r.a}:${r.b}:${r.sender}`)),seq:+r.seq};
  }catch(e){return {id:r.id,from:r.sender,ts:+r.ts,text:BAD,bad:true,seq:+r.seq}}
}
async function decodeSrv(s,r){
  try{return {id:r.id,from:r.sender,ts:+r.ts,text:td.decode(await E2E.open(s.key,r.iv,r.ct,`srv:${s.id}:${r.sender}`)),seq:+r.seq}}
  catch(e){return {id:r.id,from:r.sender,ts:+r.ts,text:BAD,bad:true,seq:+r.seq}}
}
const sortMsgs=d=>d.msgs.sort((a,b)=>a.ts-b.ts||(a.seq||0)-(b.seq||0));
function dmOf(a,b){
  const k=dmKey(a,b);
  return db.dms[k]||(db.dms[k]={users:[a,b],msgs:[],read:{},open:{},closed:{}});
}
async function ingestDm(rows){
  let changed=false;
  for(const r of rows){
    SB.maxDm=Math.max(SB.maxDm,+r.seq);
    const d=dmOf(r.a,r.b),have=d.msgs.find(m=>m.id===r.id);
    if(have){have.ts=+r.ts;have.seq=+r.seq;SB.syn.dm.add(r.id);continue}
    d.msgs.push(await decodeDm(r));SB.syn.dm.add(r.id);changed=true;
  }
  if(rows.length){for(const d of Object.values(db.dms))sortMsgs(d)}
  return changed;
}
function ingestSys(rows){
  let changed=false;
  const d=dmOf(me.id,'tuso');
  for(const r of rows){
    SB.maxSys=Math.max(SB.maxSys,+r.seq);
    if(d.msgs.some(m=>m.id===r.id))continue;
    d.msgs.push({id:r.id,from:'tuso',ts:+r.ts,text:r.text,seq:+r.seq,tag:r.tag||null});changed=true;
  }
  if(rows.length)sortMsgs(d);
  return changed;
}
async function ingestSrvMsgs(rows){
  let changed=false;
  for(const r of rows){
    SB.maxSrv=Math.max(SB.maxSrv,+r.seq);
    const s=db.servers[r.server_id];if(!s||!s.key)continue;
    const have=s.msgs.find(m=>m.id===r.id);
    if(have){have.ts=+r.ts;have.seq=+r.seq;SB.syn.srv.add(r.id);continue}
    s.msgs.push(await decodeSrv(s,r));SB.syn.srv.add(r.id);changed=true;
  }
  if(rows.length)for(const s of Object.values(db.servers))sortMsgs(s);
  return changed;
}
async function loadServerMsgs(s){
  const rows=await fetchAll((a,b)=>sb.from('server_msgs').select('id,seq,server_id,sender,iv,ct,ts').eq('server_id',s.id).order('seq').range(a,b));
  return ingestSrvMsgs(rows);
}

/* ---------- servers: membership + key hand-out ---------- */
async function srvKeyFrom(s,row){
  const wp=byId(row.wrapper);if(!wp||!wp.pubkey)throw new Error('no wrapper key');
  const k=await E2E.shared(`tuso/skey/v1/${s.id}`,wp.pubkey);
  const raw=await E2E.open(k,row.iv,row.ct,`skey:${s.id}:${me.id}`);
  return subtle.importKey('raw',raw,{name:'AES-GCM'},true,['encrypt','decrypt']);
}
async function wrapSrvKey(s,key,member){
  const raw=new Uint8Array(await subtle.exportKey('raw',key));
  const k=await E2E.shared(`tuso/skey/v1/${s.id}`,member.pubkey);
  const o=await E2E.seal(k,raw,`skey:${s.id}:${member.id}`);
  return {server_id:s.id,user_id:member.id,wrapper:me.id,iv:o.iv,ct:o.ct};
}
async function ingestServers(srvs,mems,keys){
  let changed=false;const unlocked=[];
  const ids=new Set(srvs.map(s=>s.id));
  for(const id of Object.keys(db.servers))if(!ids.has(id)){for(const m of db.servers[id].msgs)SB.syn.srv.delete(m.id);delete db.servers[id];changed=true}
  for(const r of srvs){
    let s=db.servers[r.id];
    if(!s){s=db.servers[r.id]={id:r.id,name:r.name,owner:r.owner,code:r.code,members:[],msgs:[],created:+r.created,key:null,locked:true,keyed:new Set()};changed=true}
    const m=mems.filter(x=>x.server_id===r.id).sort((a,b)=>a.joined-b.joined).map(x=>x.user_id);
    if(m.join()!==s.members.join()||s.name!==r.name||s.owner!==r.owner){s.members=m;s.name=r.name;s.owner=r.owner;changed=true}
    const rows=keys.filter(k=>k.server_id===r.id);
    s.keyed=new Set(rows.map(k=>k.user_id));
    if(!s.key){
      const mine=rows.find(k=>k.user_id===me.id);
      if(mine){
        try{s.key=await srvKeyFrom(s,mine);s.locked=false;unlocked.push(s);changed=true}
        catch(e){
          s.locked=true;
          if(!SB.healed.has(r.id)){SB.healed.add(r.id);sb.from('server_keys').delete().eq('server_id',r.id).eq('user_id',me.id).then(()=>{})}
        }
      }else if(r.owner===me.id&&!rows.length&&me.pubkey){
        try{
          const key=await subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
          const ins=await sb.from('server_keys').insert(await wrapSrvKey(s,key,me));
          if(!ins.error){s.key=key;s.locked=false;s.keyed.add(me.id);unlocked.push(s);changed=true}else s.locked=true;
        }catch(e){s.locked=true}
      }else s.locked=true;
    }
  }
  for(const s of unlocked)await loadServerMsgs(s);
  return changed;
}
async function shareKeys(){
  const rows=[];
  for(const s of Object.values(db.servers)){
    if(!s.key)continue;
    for(const id of s.members){
      if(s.keyed.has(id))continue;
      const p=byId(id);if(!p||!p.pubkey)continue;
      try{rows.push(await wrapSrvKey(s,s.key,p));s.keyed.add(id)}catch(e){}
    }
  }
  if(rows.length)await sb.from('server_keys').upsert(rows,{onConflict:'server_id,user_id',ignoreDuplicates:true});
}

/* ---------- media (avatars and banners load on demand) ---------- */
async function fetchMedia(ids,banner){
  const need=ids.filter(id=>{const u=byId(id);return u&&!SB.media.has(id+(banner?':b':':a'))});
  if(!need.length)return false;
  for(const id of need)SB.media.add(id+(banner?':b':':a'));
  let any=false;
  for(const part of chunk(need,40)){
    const {data}=await sb.from('profiles').select(banner?'id,avatar,banner_img':'id,avatar').in('id',part);
    for(const r of data||[]){const u=byId(r.id);if(!u)continue;if(u.id!==me.id){u.avatar=r.avatar||null;if(banner)u.bannerImg=r.banner_img||null}any=true}
  }
  return any;
}
const wantMedia=()=>{
  const s=new Set([me.id]);
  for(const d of Object.values(db.dms))for(const x of d.users)if(x!=='tuso')s.add(x);
  for(const sv of Object.values(db.servers))for(const x of sv.members)s.add(x);
  if(isStaff(me)&&adminOpen())for(const u of db.users)s.add(u.id);
  return [...s].slice(0,200);
};
const adminOpen=()=>{const p=$('#p-admin');return !!p&&!p.hidden&&$('#settings').classList.contains('open')};

/* ---------- initial load ---------- */
async function loadAll(){
  const id=SB.user.id;
  const [profs,pv,states,sys,mems,srvs,keys,warns,bugs]=await Promise.all([
    fetchAll((a,b)=>sb.from('profiles').select(PCOLS).order('created').range(a,b)),
    sb.from('profile_private').select('email,prefs').eq('user_id',id).single(),
    sb.from('dm_state').select('peer,read_ts,open_ts,closed_ts'),
    fetchAll((a,b)=>sb.from('system_msgs').select('id,seq,tag,text,ts').order('seq').range(a,b)),
    sb.from('server_members').select('server_id,user_id,joined'),
    sb.from('servers').select('id,name,owner,code,created'),
    sb.from('server_keys').select('server_id,user_id,wrapper,iv,ct'),
    sb.from('warnings').select('id,issued_by,reason,ts,ack').eq('user_id',id),
    sb.from('bugs').select('id,reporter,ts,title,reason,steps,shots,status,prev,handler,upd').order('ts')
  ]);
  for(const r of [pv,states,mems,srvs,keys,warns,bugs])if(r.error)throw r.error;
  {const t0=Date.now(),r=await sb.rpc('ms_now');if(r.data)SB.skew=+r.data-Math.round((t0+Date.now())/2)}
  db=blank();SB.syn=freshSyn();SB.maxDm=SB.maxSys=SB.maxSrv=0;SB.dmK.clear();
  db.users=profs.map(mapProfile);
  me=byId(id);if(!me)throw new Error('Your account was not found.');
  Object.assign(me,{avatar:null,bannerImg:null});
  me.email=pv.data.email||'';
  me.warnings=warns.data.map(w=>({id:w.id,ts:+w.ts,by:w.issued_by,reason:w.reason,ack:!!w.ack}));
  db.session=id;
  db.data[id]=Object.assign({last:null,prefs:{}},pv.data.prefs||{});
  for(const s of states.data){
    const d=dmOf(me.id,s.peer);
    d.read[me.id]=+s.read_ts;d.open[me.id]=+s.open_ts;d.closed[me.id]=+s.closed_ts;
    SB.syn.state.set(s.peer,JSON.stringify([+s.read_ts,+s.open_ts,+s.closed_ts]));
  }
  ingestSys(sys);
  await ingestServers(srvs.data,mems.data,keys.data);
  for(const s of Object.values(db.servers))if(s.key)await loadServerMsgs(s);
  const dmRows=await fetchAll((a,b)=>sb.from('dm_msgs').select('id,seq,a,b,sender,iv,ct,ts').order('seq').range(a,b));
  await ingestDm(dmRows);
  db.bugs=bugs.data.map(mapBug);
  await fetchStaffExtras();
  SB.syn.profile=JSON.parse(JSON.stringify(profFields(me)));
  SB.syn.prefs=JSON.stringify(db.data[id]);
  // avatar + banner for me (needed for the editor); others arrive on demand
  const {data:mm}=await sb.from('profiles').select('avatar,banner_img').eq('id',id).single();
  if(mm){me.avatar=mm.avatar||null;me.bannerImg=mm.banner_img||null;SB.syn.profile.avatar=me.avatar;SB.syn.profile.banner_img=me.bannerImg}
  SB.media.add(id+':a');SB.media.add(id+':b');
  await fetchMedia(wantMedia().filter(x=>x!==id),false);
}
const mapBug=b=>({id:b.id,by:b.reporter,ts:+b.ts,title:b.title,reason:b.reason,steps:b.steps,shots:b.shots||[],status:b.status,prev:b.prev||null,handler:b.handler||null,upd:b.upd?+b.upd:null});
async function fetchStaffExtras(){
  if(!isStaff(me))return;
  const [em,wn]=await Promise.all([sb.rpc('admin_emails'),sb.rpc('admin_warnings')]);
  for(const r of em.data||[]){const u=byId(r.id);if(u&&u.id!==me.id)u.email=r.email}
  for(const r of wn.data||[]){const u=byId(r.user_id);if(u&&u.id!==me.id)u.warnings=Array.from({length:+r.n},()=>({ack:true}))}
}

/* ---------- pushing local changes (save() lands here) ---------- */
function queueFlush(){
  if(!me||!SB.ready)return;
  clearTimeout(SB.flushT);
  SB.flushT=setTimeout(()=>{flush()},200);
}
function flush(){
  const run=()=>flushNow().catch(e=>{
    const rejected=!!(e&&e.code);   // the database said no: retrying won't help
    if(Date.now()-SB.errAt>15000){SB.errAt=Date.now();toast(rejected?emsg(e):'Couldn’t reach TuSo. Retrying…')}
    if(!rejected){clearTimeout(SB.flushT);SB.flushT=setTimeout(()=>{flush()},5000)}
  });
  SB.flushing=(SB.flushing||Promise.resolve()).then(run);
  return SB.flushing;
}
async function flushNow(){
  const M=me;if(!M||!SB.ready)return;
  const syn=SB.syn;if(!syn)return;
  const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  // profile
  const cur=profFields(M),ch={};
  for(const k in cur)if(!same(cur[k],syn.profile[k]))ch[k]=cur[k];
  if(Object.keys(ch).length){
    const {error}=await sb.from('profiles').update(ch).eq('id',M.id);if(error)throw error;
    Object.assign(syn.profile,JSON.parse(JSON.stringify(ch)));
  }
  // settings
  const ud=db.data[M.id];
  if(ud){const p=JSON.stringify(ud);if(p!==syn.prefs){const {error}=await sb.from('profile_private').update({prefs:ud}).eq('user_id',M.id);if(error)throw error;syn.prefs=p}}
  // conversation state
  const rows=[];
  for(const d of Object.values(db.dms)){
    if(!d.users.includes(M.id))continue;
    const peer=d.users.find(x=>x!==M.id);
    const v=[d.read[M.id]||0,d.open[M.id]||0,d.closed[M.id]||0];
    if(JSON.stringify(v)!==syn.state.get(peer))rows.push({user_id:M.id,peer,read_ts:v[0],open_ts:v[1],closed_ts:v[2]});
  }
  if(rows.length){
    const {error}=await sb.from('dm_state').upsert(rows,{onConflict:'user_id,peer'});if(error)throw error;
    for(const r of rows)syn.state.set(r.peer,JSON.stringify([r.read_ts,r.open_ts,r.closed_ts]));
  }
  // direct messages: new ones out (encrypted), deleted ones removed
  const present=new Set();
  for(const d of Object.values(db.dms)){
    if(!d.users.includes(M.id)||d.users.includes('tuso'))continue;
    const peer=byId(d.users.find(x=>x!==M.id));
    const [a,b]=d.users.slice().sort();
    const fresh=d.msgs.filter(m=>{present.add(m.id);return m.from===M.id&&!m.bad&&!syn.dm.has(m.id)});
    if(!fresh.length)continue;
    if(!peer||!peer.pubkey)continue;
    const key=await dmKeyFor(peer);
    for(const part of chunk(fresh,25)){
      const out=[];
      for(const m of part){const o=await E2E.seal(key,te.encode(m.text),`dm:${a}:${b}:${M.id}`);out.push({id:m.id,a,b,sender:M.id,iv:o.iv,ct:o.ct})}
      const {data,error}=await sb.from('dm_msgs').insert(out).select('id,ts,seq');if(error)throw error;
      for(const r of data){const m=part.find(x=>x.id===r.id);if(m){m.ts=+r.ts;m.seq=+r.seq}syn.dm.add(r.id);SB.maxDm=Math.max(SB.maxDm,+r.seq)}
    }
  }
  const gone=[...syn.dm].filter(id=>!present.has(id));
  for(const part of chunk(gone,100)){
    const {error}=await sb.from('dm_msgs').delete().in('id',part);if(error)throw error;
    for(const id of part)syn.dm.delete(id);
  }
  // server messages
  const presentS=new Set();
  for(const s of Object.values(db.servers)){
    const fresh=s.msgs.filter(m=>{presentS.add(m.id);return m.from===M.id&&!m.bad&&!syn.srv.has(m.id)});
    if(!fresh.length||!s.key)continue;
    for(const part of chunk(fresh,25)){
      const out=[];
      for(const m of part){const o=await E2E.seal(s.key,te.encode(m.text),`srv:${s.id}:${M.id}`);out.push({id:m.id,server_id:s.id,sender:M.id,iv:o.iv,ct:o.ct})}
      const {data,error}=await sb.from('server_msgs').insert(out).select('id,ts,seq');if(error)throw error;
      for(const r of data){const m=part.find(x=>x.id===r.id);if(m){m.ts=+r.ts;m.seq=+r.seq}syn.srv.add(r.id);SB.maxSrv=Math.max(SB.maxSrv,+r.seq)}
    }
  }
  const goneS=[...syn.srv].filter(id=>!presentS.has(id));
  for(const part of chunk(goneS,100)){
    const {error}=await sb.from('server_msgs').delete().in('id',part);if(error)throw error;
    for(const id of part)syn.srv.delete(id);
  }
}

/* ---------- pulling remote changes ---------- */
async function pull(full){
  if(!me||!SB.ready||SB.pulling)return;
  SB.pulling=true;
  try{
    await flushNow().catch(()=>{});
    const t=++SB.tick,before=totalUnread();let changed=false,ban=false;
    {
      const r=await sb.from('profiles').select('role,hunter,ban').eq('id',me.id).maybeSingle();
      if(r.data){
        const nr=r.data.role==='user'?undefined:r.data.role,nh=r.data.hunter||undefined;
        if(nr!==me.role||nh!==me.hunter){me.role=nr;me.hunter=nh;changed=true}
        if(r.data.ban){me.ban=r.data.ban;enforceBan();return}
      }
    }
    if(full||t%3===0){
      const rows=await fetchAll((a,b)=>sb.from('profiles').select(PCOLS).order('created').range(a,b));
      const ids=new Set(rows.map(r=>r.id));
      for(const r of rows){
        const m=mapProfile(r),u=byId(r.id);
        if(!u){db.users.push(m);changed=true;continue}
        if(u.id===me.id){
          const was=u.ban?1:0;
          Object.assign(u,{role:m.role,hunter:m.hunter,ban:m.ban,protected:m.protected,pubkey:m.pubkey});
          if(m.ban&&!was)ban=true;
        }else{
          const keep={avatar:u.avatar,bannerImg:u.bannerImg,email:u.email,warnings:u.warnings};
          const sig=JSON.stringify([u.display,u.status,u.seen,u.role,u.hunter,u.ban,u.banner,u.bio,u.pubkey&&u.pubkey.x]);
          Object.assign(u,m,keep);
          if(sig!==JSON.stringify([u.display,u.status,u.seen,u.role,u.hunter,u.ban,u.banner,u.bio,u.pubkey&&u.pubkey.x]))changed=true;
        }
      }
      const before2=db.users.length;db.users=db.users.filter(u=>ids.has(u.id));if(db.users.length!==before2)changed=true;
      me=byId(me.id)||me;
      if(me.ban||ban){enforceBan();return}
      if(await fetchMedia(wantMedia().filter(x=>x!==me.id),false))changed=true;
      if(isStaff(me))await fetchStaffExtras();
    }
    const [dm,sy,sm]=await Promise.all([
      fetchAll((a,b)=>sb.from('dm_msgs').select('id,seq,a,b,sender,iv,ct,ts').gt('seq',SB.maxDm).order('seq').range(a,b)),
      fetchAll((a,b)=>sb.from('system_msgs').select('id,seq,tag,text,ts').gt('seq',SB.maxSys).order('seq').range(a,b)),
      fetchAll((a,b)=>sb.from('server_msgs').select('id,seq,server_id,sender,iv,ct,ts').gt('seq',SB.maxSrv).order('seq').range(a,b))
    ]);
    if(await ingestDm(dm))changed=true;
    if(ingestSys(sy))changed=true;
    if(full||t%2===0||SB.srvDirty){
      SB.srvDirty=false;
      const [sv,mm,kk]=await Promise.all([
        sb.from('servers').select('id,name,owner,code,created'),
        sb.from('server_members').select('server_id,user_id,joined'),
        sb.from('server_keys').select('server_id,user_id,wrapper,iv,ct')
      ]);
      if(!sv.error&&!mm.error&&!kk.error){
        if(await ingestServers(sv.data,mm.data,kk.data))changed=true;
        await shareKeys().catch(()=>{});
      }
    }
    if(await ingestSrvMsgs(sm))changed=true;
    // conversation state from my other devices
    const st=await sb.from('dm_state').select('peer,read_ts,open_ts,closed_ts');
    for(const s of st.data||[]){
      const d=dmOf(me.id,s.peer),v=[+s.read_ts,+s.open_ts,+s.closed_ts];
      const l=[d.read[me.id]||0,d.open[me.id]||0,d.closed[me.id]||0];
      const n=[Math.max(v[0],l[0]),Math.max(v[1],l[1]),Math.max(v[2],l[2])];
      if(n.join()!==l.join()){d.read[me.id]=n[0];d.open[me.id]=n[1];d.closed[me.id]=n[2];changed=true}
      SB.syn.state.set(s.peer,JSON.stringify(v));
    }
    // warnings + bugs
    const w=await sb.from('warnings').select('id,issued_by,reason,ts,ack').eq('user_id',me.id);
    if(w.data){
      const nw=w.data.map(x=>({id:x.id,ts:+x.ts,by:x.issued_by,reason:x.reason,ack:!!x.ack}));
      if(JSON.stringify(nw)!==JSON.stringify(me.warnings)){me.warnings=nw;changed=true}
    }
    if(full||t%3===1||SB.bugDirty){
      SB.bugDirty=false;
      const pr=await sb.from('bugs').select('id,status,upd').order('ts');
      if(pr.data){
        const sig=a=>JSON.stringify(a.map(b=>[b.id,b.status,+b.upd||0]));
        if(sig(pr.data)!==sig(db.bugs)){
          const bg=await sb.from('bugs').select('id,reporter,ts,title,reason,steps,shots,status,prev,handler,upd').order('ts');
          if(bg.data){db.bugs=bg.data.map(mapBug);changed=true}
        }
      }
    }
    if(SB.recon||t%10===0){
      SB.recon=false;
      const [a,b]=await Promise.all([
        fetchAll((x,y)=>sb.from('dm_msgs').select('id').order('seq').range(x,y)),
        fetchAll((x,y)=>sb.from('server_msgs').select('id').order('seq').range(x,y))
      ]);
      const ra=new Set(a.map(r=>r.id)),rb=new Set(b.map(r=>r.id));
      for(const d of Object.values(db.dms)){
        if(d.users.includes('tuso'))continue;
        const n=d.msgs.length;
        d.msgs=d.msgs.filter(m=>!SB.syn.dm.has(m.id)||ra.has(m.id));
        if(d.msgs.length!==n)changed=true;
      }
      for(const id of [...SB.syn.dm])if(!ra.has(id))SB.syn.dm.delete(id);
      for(const s of Object.values(db.servers)){
        const n=s.msgs.length;
        s.msgs=s.msgs.filter(m=>!SB.syn.srv.has(m.id)||rb.has(m.id));
        if(s.msgs.length!==n)changed=true;
      }
      for(const id of [...SB.syn.srv])if(!rb.has(id))SB.syn.srv.delete(id);
    }
    if(changed)afterRemote(before);
    else if(!document.hidden){checkWarnings()}
  }catch(e){/* try again on the next tick */}
  finally{SB.pulling=false}
}
function afterRemote(before){
  if(!me)return;
  if(activeServer&&!db.servers[activeServer]){showDms();toast('That server is no longer available.')}
  const d=active&&getDm(active,false);
  if(active&&(!d||!contact(active))){active=null;$('#shell').classList.remove('chat-open');renderChat(true)}
  else if(active&&!document.hidden&&d&&markRead(d))save();
  const after=totalUnread();
  if(after>before&&prefs().sound)blip();
  renderMe();renderRail();renderList();
  if(activeServer){const s=db.servers[activeServer];if(s){renderServerSide();renderHead();syncComposer();renderMsgs({})}}
  else if(active){renderHead();renderMsgs({})}
  applyPrefs();checkWarnings();
  if(isStaff(me)&&!$('#p-admin').hidden)renderAdmin();
}
function startLive(){
  clearInterval(SB.timer);
  SB.timer=setInterval(()=>{if(!document.hidden)pull()},6000);
  try{
    SB.chan=sb.channel('tuso-live');
    let nt=0;const nudge=del=>{if(del)SB.recon=true;clearTimeout(nt);nt=setTimeout(()=>pull(),120)};
    for(const t of ['dm_msgs','server_msgs','system_msgs','server_members','server_keys','bugs','warnings'])
      SB.chan.on('postgres_changes',{event:'*',schema:'public',table:t},p=>{
        if(t==='server_members'||t==='server_keys')SB.srvDirty=true;
        if(t==='bugs')SB.bugDirty=true;
        nudge(p&&p.eventType==='DELETE');
      });
    SB.chan.subscribe();
  }catch(e){}
}

/* ---------- sign in / sign up / unlock ---------- */
function showBoot(msg,retry){
  $('#auth').hidden=true;$('#boot').hidden=false;
  $('#bootMsg').textContent=msg||'';$('#bootRetry').hidden=!retry;$('#bootOut').hidden=!retry;
}
function showAuth(err){
  $('#boot').hidden=true;$('#auth').hidden=false;
  if(err)$('#liErr').textContent=err;
}
async function bootstrap(user,password){
  SB.user=user;
  const [p,pv]=await Promise.all([
    sb.from('profiles').select(PCOLS).eq('id',user.id).maybeSingle(),
    sb.from('profile_private').select('enc_priv,key_salt,enc_priv_rec').eq('user_id',user.id).maybeSingle()
  ]);
  if(p.error)throw p.error;
  if(!p.data){await sb.auth.signOut();resetCloud();showAuth('That account no longer exists.');return false}
  if(p.data.ban){
    const r=p.data.ban.reason;await sb.auth.signOut();resetCloud();
    showAuth('This account is banned.'+(r?' Reason: '+r:''));return false;
  }
  SB.pv=pv.data||{};
  showBoot('Unlocking…');
  const ok=await establishKeys(p.data,SB.pv,password);
  if(!ok){await sb.auth.signOut();resetCloud();showAuth();return false}
  showBoot('Loading your messages…');
  await loadAll();
  SB.ready=true;
  startLive();
  await shareKeys().catch(()=>{});
  enter(me);
  $('#boot').hidden=true;
  return true;
}
async function establishKeys(p,pv,password){
  const have=!!(p.pubkey&&pv.enc_priv);
  const fp=p.pubkey?await E2E.fingerprint(p.pubkey):null;
  if(have){
    const c=await KS.get(SB.user.id);
    if(c&&c.fp===fp&&c.key){SB.priv=c.key;return true}
    if(password){
      try{await adoptPriv(await E2E.openPriv(password,pv.enc_priv,pv.key_salt),p.pubkey);return true}catch(e){}
    }
    return promptUnlock(p,pv,'password');
  }
  if(password){await createKeys(password);return true}
  return promptUnlock(p,pv,'create');
}
async function adoptPriv(pkcs8,pub){
  SB.priv=await E2E.importPriv(pkcs8);
  await KS.set(SB.user.id,{key:SB.priv,fp:await E2E.fingerprint(pub)});
}
async function createKeys(pw){
  const id=await E2E.newIdentity(pw);
  const a=await sb.from('profiles').update({pubkey:id.pub}).eq('id',SB.user.id);if(a.error)throw a.error;
  const b=await sb.from('profile_private').update({enc_priv:id.enc_priv,key_salt:id.key_salt,enc_priv_rec:id.enc_priv_rec}).eq('user_id',SB.user.id);if(b.error)throw b.error;
  await sb.from('server_keys').delete().eq('user_id',SB.user.id);
  await adoptPriv(id.pkcs8,id.pub);
  SB.pv={enc_priv:id.enc_priv,key_salt:id.key_salt,enc_priv_rec:id.enc_priv_rec};
  await showRecovery(id.recovery);
}
function showRecovery(rec){
  return new Promise(res=>{
    $('#recKey').textContent=rec;$('#recM').classList.add('open');
    $('#recCopy').onclick=async()=>{try{await navigator.clipboard.writeText(rec);toast('Recovery key copied.')}catch(e){toast('Select the key and copy it by hand.')}};
    $('#recDone').onclick=()=>{$('#recM').classList.remove('open');res()};
  });
}
function promptUnlock(p,pv,mode){
  return new Promise(res=>{
    const m=$('#unlockM'),f=$('#fUnlock'),pw=$('#ulPw'),rc=$('#ulRec');
    const ui=()=>{
      const rec=mode==='recovery',mk=mode==='create';
      $('#ulT').textContent=mk?'Set up encryption':'Unlock your messages';
      $('#ulP').textContent=mk?'Enter your password to create your encryption key. It protects your messages on this device.':rec?'Enter the recovery key you saved when you made your account, plus your current password so your key can be protected again.':'Enter your password to unlock your encryption key on this device.';
      $('#ulRecF').hidden=!rec;
      $('#ulPwLbl').textContent=rec?'Current password':'Password';
      $('#ulMode').hidden=mk;$('#ulMode').textContent=rec?'Use my password instead':'Use my recovery key instead';
      $('#ulReset').hidden=mk||!pv.enc_priv;
      $('#ulGo').textContent=mk?'Create key':'Unlock';
      setErr(pw,'');setErr(rc,'');
      setTimeout(()=>(rec?rc:pw).focus(),60);
    };
    const done=v=>{m.classList.remove('open');f.onsubmit=null;res(v)};
    f.onsubmit=async e=>{
      e.preventDefault();const rec=mode==='recovery';setErr(pw,'');setErr(rc,'');
      if(rec&&!rc.value.trim()){setErr(rc,'Enter your recovery key.');return}
      if(!pw.value){setErr(pw,'Enter your password.');return}
      const btn=$('#ulGo');busy(btn,true);let bad=pw;
      try{
        if(mode==='create')await createKeys(pw.value);
        else if(rec){
          bad=rc;const k=await E2E.openPrivRec(rc.value,pv.enc_priv_rec);
          bad=pw;if(!await verifyLogin(pw.value))throw new Error('That isn’t your account password.');
          await adoptPriv(k,p.pubkey);
          const w=await rewrap(k,pw.value);
          await sb.from('profile_private').update(w).eq('user_id',SB.user.id);
        }else await adoptPriv(await E2E.openPriv(pw.value,pv.enc_priv,pv.key_salt),p.pubkey);
        busy(btn,false);pw.value='';rc.value='';done(true);
      }catch(err){busy(btn,false);setErr(bad,bad===rc?'That recovery key doesn’t match.':(mode==='create'||rec)?emsg(err):'That password doesn’t unlock your key. If you changed it elsewhere, use your recovery key.')}
    };
    $('#ulMode').onclick=()=>{mode=mode==='recovery'?'password':'recovery';ui()};
    $('#ulOut').onclick=()=>done(false);
    $('#ulReset').onclick=async()=>{
      if(!pw.value){setErr(pw,'Enter your account password first, then choose reset.');pw.focus();return}
      if(!await ask({title:'Reset encryption?',body:'You get a new key and won’t be able to read your old messages. People you talk to will see your new key. This can’t be undone.',ok:'Reset encryption',danger:true}))return;
      try{
        if(!await verifyLogin(pw.value))throw new Error('That isn’t your account password.');
        await createKeys(pw.value);pw.value='';done(true);
      }catch(err){setErr(pw,emsg(err))}
    };
    m.classList.add('open');ui();
  });
}
/* checks the account password against the server */
async function verifyLogin(pw){
  const {error}=await sb.auth.signInWithPassword({email:SB.user.email,password:pw});
  return !error;
}
/* protects the private key with a (new) password; the recovery wrap stays valid */
async function rewrap(pkcs8,pw){
  const salt=b64(crypto.getRandomValues(new Uint8Array(16)));
  const w=await E2E.seal(await E2E.pwKey(pw,salt),pkcs8,'tuso/priv');
  return {enc_priv:w.iv+'.'+w.ct,key_salt:salt};
}

/* ---------- misc cloud actions ---------- */
async function cloudLogout(){
  const M=me;
  try{if(M&&SB.ready){M.seen=0;await flushNow().catch(()=>{})}}catch(e){}
  SB.ready=false;
  try{await sb.auth.signOut()}catch(e){}
  if(M)await KS.del(M.id);
}


/* ---------- animated background ---------- */
const cv=$('#bg'), cx=cv.getContext('2d');
let W=0,H=0;
const BL=[
  {r:.62,l:64,a:.20,fx:.000071,fy:.000093,px:0,py:.4},
  {r:.50,l:82,a:.13,fx:.000113,fy:.000067,px:2.1,py:1.1},
  {r:.72,l:38,a:.32,fx:.000053,fy:.000081,px:4.2,py:2.3},
  {r:.42,l:92,a:.09,fx:.000137,fy:.000109,px:1,py:5},
  {r:.56,l:52,a:.24,fx:.000089,fy:.000061,px:3.3,py:3.7}
];
const ptr={x:.5,y:.5,tx:.5,ty:.5};
const bg={mode:'animated',speed:1,clock:26000,last:0,raf:0};
function bgSize(){const s=.18;W=cv.width=Math.max(2,Math.ceil(innerWidth*s));H=cv.height=Math.max(2,Math.ceil(innerHeight*s))}
function bgDraw(t){
  cx.globalCompositeOperation='source-over';
  cx.fillStyle='#060606';cx.fillRect(0,0,W,H);
  cx.globalCompositeOperation='lighter';
  for(const b of BL){
    const x=W*(.5+.4*Math.sin(t*b.fx+b.px)), y=H*(.5+.4*Math.cos(t*b.fy+b.py)), r=Math.max(W,H)*b.r;
    const g=cx.createRadialGradient(x,y,0,x,y,r);
    g.addColorStop(0,`hsla(0,0%,${b.l}%,${b.a})`);
    g.addColorStop(.5,`hsla(0,0%,${b.l}%,${b.a*.32})`);
    g.addColorStop(1,'hsla(0,0%,0%,0)');
    cx.fillStyle=g;cx.fillRect(0,0,W,H);
  }
  // soft light that follows the pointer
  const gx=W*ptr.x, gy=H*ptr.y, gr=Math.max(W,H)*.34;
  const pg=cx.createRadialGradient(gx,gy,0,gx,gy,gr);
  pg.addColorStop(0,'hsla(0,0%,88%,.12)');pg.addColorStop(1,'hsla(0,0%,0%,0)');
  cx.fillStyle=pg;cx.fillRect(0,0,W,H);
  // one slow diagonal light sweep
  const p=((t*.000028)%1.8)-.4, bx=W*p, bw=W*.22;
  cx.save();cx.translate(bx,0);cx.transform(1,0,-.55,1,0,0);
  const sg=cx.createLinearGradient(-bw,0,bw,0);
  sg.addColorStop(0,'rgba(255,255,255,0)');sg.addColorStop(.5,'rgba(255,255,255,.045)');sg.addColorStop(1,'rgba(255,255,255,0)');
  cx.fillStyle=sg;cx.fillRect(-bw,0,bw*2,H);cx.restore();
  cx.globalCompositeOperation='source-over';
}
const GATE=matchMedia('(pointer:coarse)').matches?72:42;
function bgLoop(ts){
  bg.raf=0;
  if(document.hidden||bg.mode==='static')return;
  if(ts-bg.last>=GATE){
    bg.clock+=Math.min(100,ts-bg.last)*bg.speed;bg.last=ts;
    ptr.x+=(ptr.tx-ptr.x)*.06;ptr.y+=(ptr.ty-ptr.y)*.06;
    bgDraw(bg.clock);
  }
  bg.raf=requestAnimationFrame(bgLoop);
}
function bgSet(mode){
  bg.mode=mode;bg.speed=mode==='calm'?.35:1;
  document.documentElement.classList.toggle('still',mode==='static');
  if(bg.raf){cancelAnimationFrame(bg.raf);bg.raf=0}
  bgDraw(bg.clock);
  if(mode!=='static'){bg.last=performance.now();bg.raf=requestAnimationFrame(bgLoop)}
}
function makeGrain(){
  try{
    const n=document.createElement('canvas');n.width=n.height=160;
    const g=n.getContext('2d'),d=g.createImageData(160,160);
    for(let i=0;i<d.data.length;i+=4){const v=Math.random()*255|0;d.data[i]=d.data[i+1]=d.data[i+2]=v;d.data[i+3]=255}
    g.putImageData(d,0,0);$('#grain').style.backgroundImage=`url(${n.toDataURL()})`;
  }catch(e){}
}
addEventListener('resize',()=>{bgSize();bgDraw(bg.clock)});
addEventListener('pointermove',e=>{ptr.tx=e.clientX/innerWidth;ptr.ty=e.clientY/innerHeight},{passive:true});

/* ---------- helpers ---------- */
const hashNum=s=>{let h=7;for(let i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))>>>0;return h};
const STATUS={online:'Online',idle:'Idle',dnd:'Do not disturb',invisible:'Invisible',offline:'Offline'};
const OFFICIAL={id:'tuso',display:'TuSo',username:'tuso',official:true,status:'online',banner:2,avatar:null,bio:'Official messages from the TuSo team.'};
const STAFF='<span class="staff" data-tip="Staff: part of the TuSo team. Can warn and ban members." role="img" aria-label="Staff"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" aria-hidden="true"><path d="M6 1 10.5 3.2v3.1C10.5 8.7 8.6 10.4 6 11 3.4 10.4 1.5 8.7 1.5 6.3V3.2z"/><path d="M6 4v3" stroke-linecap="round"/></svg></span>';
const ADMIN='<span class="admin" data-tip="Admin: runs TuSo. Manages staff, accounts and servers." role="img" aria-label="Admin"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" aria-hidden="true"><path d="M1.6 9.6 1.2 4l3 2.4L6 2.4l1.8 4L10.8 4l-.4 5.6z"/></svg></span>';
const HUNTER='<span class="hunter" data-tip="Bug hunter: reported a bug that got fixed." role="img" aria-label="Bug hunter"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.6" y="3.4" width="4.8" height="6.2" rx="2.4"/><path d="M4.6 3.2 3.9 1.8M7.4 3.2 8.1 1.8M3.6 6H1.6M8.4 6h2M3.8 8.2 2.2 9.4M8.2 8.2l1.6 1.2M6 3.8v5.6"/></svg></span>';
const isAdmin=u=>!!u&&u.role==='admin';
const isStaff=u=>!!u&&(u.role==='admin'||u.role==='staff');
const tags=u=>!u?'':u.official?TAG:((isAdmin(u)?ADMIN:(u.role==='staff'?STAFF:''))+(u.hunter?HUNTER:''));
const TAG='<span class="official" data-tip="Official: a verified TuSo account." role="img" aria-label="Official"><svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 6.4 4.8 9 10 3.2"/></svg>Official</span>';
function av(u,s=40,st=null){
  const h=hashNum(u.id||u.username||'x'), a=90-(h%12), b=a-28-((h>>3)%10), ang=120+(h%90);
  if(u.official)return `<span class="av" style="--s:${s}px;--bgv:#f1f1ef;letter-spacing:-.06em;font-size:${Math.round(s*.4)}px">Tu${st?`<i class="dot" data-s="${st}"></i>`:''}</span>`;
  const inner=u.avatar?`<img src="${esc(u.avatar)}" alt="">`:esc((u.display||u.username||'?').trim().charAt(0).toUpperCase()||'?');
  return `<span class="av" style="--s:${s}px;--bgv:linear-gradient(${ang}deg,hsl(0 0% ${a}%),hsl(0 0% ${b}%))">${inner}${st?`<i class="dot" data-s="${st}"></i>`:''}</span>`;
}
const hm=ts=>new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
const sameDay=(a,b)=>new Date(a).toDateString()===new Date(b).toDateString();
function dayLabel(ts){
  const d=new Date(ts),n=new Date(),y=new Date(snow()-864e5);
  if(d.toDateString()===n.toDateString())return 'Today';
  if(d.toDateString()===y.toDateString())return 'Yesterday';
  return d.toLocaleDateString([],{weekday:'long',day:'numeric',month:'long',year:d.getFullYear()===n.getFullYear()?undefined:'numeric'});
}
function fmt(t){return esc(t).replace(/(https?:\/\/[^\s<]+[^\s<.,;:!?)\]'"])/g,u=>`<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`)}
const BANNERS=[
  {n:'Graphite',css:'linear-gradient(135deg,#323232,#0e0e0e)'},
  {n:'Fog',css:'radial-gradient(circle at 18% 25%,#a4a4a0,transparent 62%),linear-gradient(135deg,#3b3b39,#141414)'},
  {n:'Chalk',css:'linear-gradient(135deg,#dcdcd8,#7c7c78)'},
  {n:'Stripe',css:'repeating-linear-gradient(45deg,#1a1a1a 0 10px,#262626 10px 20px)'},
  {n:'Ink',css:'linear-gradient(180deg,#000,#222)'},
  {n:'Halftone',css:'radial-gradient(circle,#666663 1.2px,transparent 1.7px) 0 0/10px 10px,#131313'}
];
const STALE=150000;
function presence(u){
  if(u&&u.official)return 'online';
  if(!u||!u.seen||snow()-u.seen>STALE)return 'offline';
  return u.status==='invisible'?'offline':(u.status||'online');
}
function bannerBg(u,o){
  const img=o.bannerImg!==undefined?o.bannerImg:u.bannerImg;
  if(img&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(img))return `url('${img}') center/cover no-repeat,#111`;
  return (BANNERS[o.banner??u.banner??0]||BANNERS[0]).css;
}
function pcard(u,o={}){
  const name=o.display??u.display, bio=o.bio??u.bio, st=o.state||'offline';
  const au={...u,display:name,avatar:o.avatar!==undefined?o.avatar:u.avatar};
  return `<div class="pcard"><div class="banner" style="background:${bannerBg(u,o)}"></div><div class="pbody"><div class="pav">${av(au,84,st)}</div><b class="pname">${esc(name)}${tags(u)}</b><span class="un">@${esc(u.username)}</span><span class="pill"><i class="dot" data-s="${st}"></i>${STATUS[st]}</span>${bio?`<div class="psec"><span class="lbl">About me</span><p>${esc(bio)}</p></div>`:''}</div></div>`;
}

let toastT=0;
function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.add('show');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('show'),2400)}
function ask({title,body,ok='Confirm',danger=false}){
  return new Promise(res=>{
    const m=$('#modal'),y=$('#mYes'),n=$('#mNo'),prev=document.activeElement;
    $('#mTitle').textContent=title;$('#mBody').textContent=body;
    y.textContent=ok;y.className='btn '+(danger?'btn-danger':'btn-primary');
    m.classList.add('open');
    const done=v=>{m.classList.remove('open');y.onclick=n.onclick=m.onclick=m.onkeydown=null;if(prev&&prev.focus)prev.focus();res(v)};
    y.onclick=()=>done(true);n.onclick=()=>done(false);
    m.onclick=e=>{if(e.target===m)done(false)};
    m.onkeydown=e=>{if(e.key==='Escape'){e.stopPropagation();done(false)}};
    setTimeout(()=>n.focus(),30);
  });
}
function setErr(input,msg){
  const f=input.closest('.field');if(!f)return;
  f.classList.toggle('bad',!!msg);
  const e=f.querySelector('.err');if(e)e.textContent=msg||'';
  input.setAttribute('aria-invalid',msg?'true':'false');
}
function clearErrs(form){$$('.input',form).forEach(i=>setErr(i,''));$$('.formerr',form).forEach(e=>e.textContent='')}
function busy(btn,on,label){btn.disabled=on;btn.classList.toggle('loading',on)}
function shake(){const c=$('#authCard');c.classList.remove('shake');void c.offsetWidth;c.classList.add('shake')}
$('#authCard').addEventListener('animationend',e=>{if(e.animationName==='shake')e.currentTarget.classList.remove('shake')});

const reEmail=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const reUser=/^[a-z0-9_.]{2,24}$/;

/* ---------- auth ---------- */
let swapping=false;
function authTab(which,animate){
  const login=which==='login';
  const to=login?$('#fLogin'):$('#fSignup'), from=login?$('#fSignup'):$('#fLogin');
  const title=login?'Welcome back!':'Create an account', sub=login?'We’re so excited to see you again!':'';
  const set=()=>{from.hidden=true;to.hidden=false;$('#authTitle').textContent=title;$('#authSub').textContent=sub};
  if(!to.hidden)return;
  if(!animate||reduce){set();return}
  if(swapping)return;swapping=true;
  const wrap=$('#formWrap'),head=$('#cardHead'),h0=wrap.offsetHeight;
  wrap.style.height=h0+'px';wrap.style.overflow='hidden';
  from.classList.add('leaving');head.classList.add('leaving');
  setTimeout(()=>{
    set();from.classList.remove('leaving');head.classList.remove('leaving');to.classList.add('entering');
    wrap.style.height='auto';const h1=wrap.offsetHeight;
    wrap.style.height=h0+'px';void wrap.offsetHeight;
    wrap.style.transition='height .45s cubic-bezier(.22,1,.36,1)';wrap.style.height=h1+'px';
    setTimeout(()=>{wrap.style.cssText='';to.classList.remove('entering');swapping=false},470);
  },170);
}
$$('[data-go]').forEach(b=>b.onclick=()=>authTab(b.dataset.go,true));
document.addEventListener('click',e=>{
  const b=e.target.closest('.pwt');if(!b)return;
  const i=document.getElementById(b.dataset.for),show=i.type==='password';
  i.type=show?'text':'password';b.textContent=show?'Hide':'Show';b.setAttribute('aria-label',show?'Hide password':'Show password');
});
async function syncNow(){for(let i=0;i<50&&SB.pulling;i++)await wait(100);await pull(true)}
async function startSession(user,pw){
  try{return await bootstrap(user,pw)}
  catch(err){resetCloud();try{await sb.auth.signOut()}catch(e){}showAuth(emsg(err));return false}
}
$('#fLogin').addEventListener('submit',async e=>{
  e.preventDefault();
  const f=e.target,idEl=$('#liId'),pwEl=$('#liPw');clearErrs(f);
  const id=idEl.value.trim().toLowerCase().replace(/^@/,''),pw=pwEl.value;
  let ok=true;
  if(!id){setErr(idEl,'Enter your email or username.');ok=false}
  if(!pw){setErr(pwEl,'Enter your password.');ok=false}
  if(!ok){shake();return}
  if(!sb){$('#liErr').textContent='TuSo can’t reach its server right now.';return}
  const btn=$('#liBtn');busy(btn,true);
  try{
    let email=id;
    if(!id.includes('@')){const r=await sb.rpc('login_email',{ident:id});email=r.data||''}
    const res=email?await sb.auth.signInWithPassword({email,password:pw}):{error:{message:'Invalid login credentials'}};
    if(res.error){
      const m=/confirm/i.test(res.error.message||'')?'Confirm your email first. Check your inbox for the link.':'Email, username or password is invalid.';
      [idEl,pwEl].forEach(i=>i.closest('.field').classList.add('bad'));$('#liErr').textContent=m;shake();return;
    }
    pwEl.value='';showBoot('Signing you in…');
    await startSession(res.data.user,pw);
  }catch(err){showAuth(emsg(err))}
  finally{busy(btn,false)}
});

$('#fSignup').addEventListener('submit',async e=>{
  e.preventDefault();
  const f=e.target;clearErrs(f);
  const emEl=$('#suEmail'),dnEl=$('#suName'),unEl=$('#suUser'),pwEl=$('#suPw'),p2El=$('#suPw2');
  const em=emEl.value.trim().toLowerCase(),dn=dnEl.value.trim(),un=unEl.value.trim().toLowerCase().replace(/^@/,''),pw=pwEl.value;
  let ok=true;
  if(!reEmail.test(em)){setErr(emEl,'Enter a valid email address.');ok=false}
  if(!reUser.test(un)){setErr(unEl,'Use 2 to 24 letters, numbers, dots or underscores.');ok=false}
  else if(un==='tuso'){setErr(unEl,'That username is taken.');ok=false}
  if(pw.length<8){setErr(pwEl,'Use at least 8 characters.');ok=false}
  if(p2El.value!==pw){setErr(p2El,'The passwords do not match.');ok=false}
  if(!ok){shake();return}
  if(!sb){$('#suErr').textContent='TuSo can’t reach its server right now.';return}
  const btn=$('#suBtn');busy(btn,true);
  try{
    const fr=await sb.rpc('username_free',{u:un});
    if(fr.data===false){setErr(unEl,'That username is taken.');shake();return}
    const r=await sb.auth.signUp({email:em,password:pw,options:{data:{username:un,display:dn||un}}});
    if(r.error){
      const m=r.error.message||'';
      if(/registered|exists/i.test(m))setErr(emEl,'An account with this email already exists. Try logging in.');
      else if(/password/i.test(m))setErr(pwEl,m);else $('#suErr').textContent=m;
      shake();return;
    }
    if(r.data.user&&r.data.user.identities&&!r.data.user.identities.length){setErr(emEl,'An account with this email already exists. Try logging in.');shake();return}
    if(!r.data.session){f.reset();authTab('login',true);$('#liErr').textContent='Account created. Confirm your email, then log in.';return}
    f.reset();showBoot('Setting up encryption…');
    await startSession(r.data.user,pw);
  }catch(err){showAuth(emsg(err))}
  finally{busy(btn,false)}
});

/* ---------- state ---------- */
const DEF={bg:reduce?'static':'animated',dens:'cozy',size:'md',badges:true,sound:false};
let me=null,active=null,activeServer=null;
const MAX_SERVERS=100;
const UD=()=>db.data[me.id];
const prefs=()=>UD().prefs;
const contact=id=>id==='tuso'?OFFICIAL:(db.users.find(u=>u.id===id)||null);
const dmKey=(a,b)=>[a,b].sort().join(':');
const lastOf=d=>d.msgs[d.msgs.length-1];
function getDm(other,create){
  const k=dmKey(me.id,other);let d=db.dms[k];
  if(!d&&create)d=db.dms[k]={users:[me.id,other],msgs:[],read:{},open:{},closed:{}};
  return d||null;
}
const activity=d=>Math.max((lastOf(d)||{}).ts||0,(d.open||{})[me.id]||0);
const dmVisible=d=>d.users.includes('tuso')||activity(d)>((d.closed||{})[me.id]||0);
const unreadOf=d=>{const r=(d.read||{})[me.id]||0;return d.msgs.reduce((n,m)=>n+(m.from!==me.id&&m.ts>r?1:0),0)};
function markRead(d){const l=lastOf(d);if(l&&((d.read||(d.read={}))[me.id]||0)<l.ts){d.read[me.id]=l.ts;return true}return false}
function convoList(){
  return Object.values(db.dms).filter(d=>d.users.includes(me.id)).map(d=>({d,u:contact(d.users.find(x=>x!==me.id))})).filter(r=>r.u&&dmVisible(r.d)).sort((a,b)=>(b.u.official?1:0)-(a.u.official?1:0)||activity(b.d)-activity(a.d));
}
const totalUnread=()=>convoList().reduce((n,r)=>n+unreadOf(r.d),0);

/* A new release is posted once to each account's TuSo conversation (the database keeps one per version). */
async function announce(){
  const ud=UD();if(!ud||ud.newsSent===NEWS_VER||!me)return;
  const r=RELEASES[0];
  const text=`TuSo v${r.ver} is out: ${r.title}\n\n${r.blurb}\n\n${r.items.map(i=>'• '+i[1]).join('\n')}\n\nMore detail is in Settings, What’s new.`;
  const {error}=await sb.from('system_msgs').insert({user_id:me.id,tag:'release-'+NEWS_VER,text});
  if(error&&error.code!=='23505')return;
  ud.newsSent=NEWS_VER;save();pull();
}

/* ---------- entering / leaving ---------- */
function enter(u){
  me=u;db.session=u.id;
  db.data[u.id]=db.data[u.id]||{last:null,prefs:{}};
  const ud=UD();ud.prefs={...DEF,...ud.prefs};
  u.seen=snow();if(!ud.newsSent){ud.newsSent=NEWS_VER}else announce();save();
  const d=ud.last&&getDm(ud.last,false);
  active=(d&&contact(ud.last)&&dmVisible(d))?ud.last:null;
  const auth=$('#auth'),app=$('#app');
  activeServer=null;applyPrefs();renderMe();renderRail();showSide();renderList(true);renderChat(false);
  $('#shell').classList.remove('chat-open');
  app.hidden=false;void app.offsetWidth;app.classList.add('in');
  auth.classList.add('out');setTimeout(()=>{auth.hidden=true;auth.classList.remove('out')},reduce?0:340);
  if(!phone()&&active)setTimeout(()=>$('#ta').focus(),400);
  checkWarnings();
}
function leave(){
  try{if(sb)sb.auth.signOut().catch(()=>{})}catch(e){}
  resetCloud();db=blank();
  closeSettings(true);closeQS();closeSrvM();closeEmoji();
  me=null;active=null;activeServer=null;
  const auth=$('#auth'),app=$('#app');
  app.classList.remove('in');
  auth.hidden=false;auth.classList.remove('out');
  const a=$('#authIn');a.style.animation='none';void a.offsetWidth;a.style.animation='';
  setTimeout(()=>{app.hidden=true},reduce?0:420);
  authTab('login',false);
}

/* ---------- prefs ---------- */
function applyPrefs(){
  const p=prefs(),app=$('#app');
  app.dataset.dens=p.dens;app.dataset.size=p.size;app.classList.toggle('nobadge',!p.badges);
  if(bg.mode!==p.bg||document.documentElement.classList.contains('still')!==(p.bg==='static'))bgSet(p.bg);
}
function syncPrefUI(){
  const p=prefs();
  $$('#p-appearance [data-pref]').forEach(g=>$$('[role=radio]',g).forEach(b=>b.setAttribute('aria-checked',b.dataset.v===p[g.dataset.pref])));
  $$('.switch').forEach(s=>s.setAttribute('aria-checked',!!p[s.dataset.pref]));
}
$('#p-appearance').addEventListener('click',e=>{
  const b=e.target.closest('[role=radio]');if(!b)return;
  const g=b.closest('[data-pref]');prefs()[g.dataset.pref]=b.dataset.v;save();applyPrefs();syncPrefUI();
});
$('#p-notify').addEventListener('click',e=>{
  const s=e.target.closest('.switch');if(!s)return;
  const k=s.dataset.pref;prefs()[k]=!prefs()[k];save();applyPrefs();syncPrefUI();
  if(k==='sound'&&prefs().sound)blip();
});
let actx=null;
function blip(){
  try{
    actx=actx||new (window.AudioContext||window.webkitAudioContext)();
    const o=actx.createOscillator(),g=actx.createGain();
    o.type='sine';o.frequency.value=660;g.gain.setValueAtTime(.0001,actx.currentTime);
    g.gain.exponentialRampToValueAtTime(.07,actx.currentTime+.02);g.gain.exponentialRampToValueAtTime(.0001,actx.currentTime+.28);
    o.connect(g);g.connect(actx.destination);o.start();o.stop(actx.currentTime+.3);
  }catch(e){}
}

/* ---------- sidebar ---------- */
function renderMe(){
  $('#me').innerHTML=`${av(me,38,me.status||'online')}<div class="who"><b><span class="nmt">${esc(me.display)}</span>${tags(me)}</b><span>@${esc(me.username)}</span></div><button class="icon-btn" id="bugBtn" type="button" aria-label="Report a bug" title="Report a bug">${I.bug}</button><button class="icon-btn" id="openSettings" type="button" aria-label="Open settings">${I.gear}</button>`;
  $('#openSettings').onclick=()=>openSettings('account');
  $('#bugBtn').onclick=openBug;
  $('#adminTab').hidden=!isStaff(me);syncNewDot();
}
let staggerT=0;
function renderList(stagger){
  const rows=convoList(),ul=$('#dmList');
  if(stagger){ul.classList.add('stagger');clearTimeout(staggerT);staggerT=setTimeout(()=>ul.classList.remove('stagger'),1400)}
  ul.innerHTML=rows.length?rows.map(({d,u},i)=>{
    const l=lastOf(d),n=unreadOf(d),pv=l?((l.from===me.id?'You: ':'')+l.text.replace(/\s+/g,' ')):'No messages yet';
    return `<li style="--i:${i}"><button type="button" class="dm${u.id===active?' active':''}${n?' unread':''}" data-id="${u.id}">${av(u,40,presence(u))}<span class="meta"><span class="nm">${esc(u.display)}${tags(u)}</span><span class="pv">${esc(pv)}</span></span>${n?`<span class="badge" aria-label="${n} unread">${n>99?'99+':n}</span>`:''}</button></li>`;
  }).join(''):`<li class="none"><b>No conversations yet</b><span>Use “Find or start a conversation” to message someone.</span></li>`;
}
$('#dmList').addEventListener('click',e=>{const b=e.target.closest('.dm');if(b)select(b.dataset.id)});
$('#findKbd').textContent=/Mac|iPhone|iPad/.test(navigator.platform||navigator.userAgent)?'⌘ K':'Ctrl K';
$('#findBtn').onclick=openQS;
$('#emptyStart').onclick=openQS;

function select(id){
  if(activeServer){activeServer=null;renderRail();showSide()}
  active=id;const d=getDm(id,false);
  if(d&&markRead(d))save();
  UD().last=id;save();
  renderList();renderChat(true);
  $('#shell').classList.add('chat-open');
  if(!phone())setTimeout(()=>$('#ta').focus(),60);
}
function closeConvo(){
  const d=getDm(active,false);if(!d||active==='tuso')return;
  d.closed[me.id]=Math.max(snow(),activity(d));
  UD().last=null;active=null;save();
  renderList();renderChat(true);
  $('#shell').classList.remove('chat-open');
}

/* ---------- quick switcher ---------- */
let qsSel=0,qsItems=[];
function openQS(){
  if(!me)return;
  $('#qs').classList.add('open');$('#qsIn').value='';qsSel=0;renderQS();
  pull(true).then(()=>{if($('#qs').classList.contains('open'))renderQS()});
  setTimeout(()=>$('#qsIn').focus(),40);
}
function closeQS(){$('#qs').classList.remove('open')}
function renderQS(){
  const q=$('#qsIn').value.trim().toLowerCase().replace(/^@/,'');
  const others=[OFFICIAL,...db.users.filter(u=>u.id!==me.id)];
  const inConvo=u=>{const d=getDm(u.id,false);return d&&dmVisible(d)?1:0};
  qsItems=others.filter(u=>!q||u.display.toLowerCase().includes(q)||u.username.includes(q)).sort((a,b)=>inConvo(b)-inConvo(a)||a.display.localeCompare(b.display));
  qsSel=Math.min(qsSel,Math.max(0,qsItems.length-1));
  $('#qsList').innerHTML=qsItems.length?qsItems.map((u,i)=>`<li><button type="button" data-i="${i}" class="${i===qsSel?'sel':''}">${av(u,36,presence(u))}<span class="q-meta"><b>${esc(u.display)}${tags(u)}</b><span>@${esc(u.username)}</span></span>${inConvo(u)?'<span class="q-tag">Open</span>':''}</button></li>`).join('')
    :`<li class="none">${others.length?`Nobody matches “${esc(q)}”.`:'No other accounts yet. Invite a friend to sign up, then message them from here.'}</li>`;
}
function qsMove(d){
  if(!qsItems.length)return;
  qsSel=(qsSel+d+qsItems.length)%qsItems.length;
  $$('#qsList button').forEach((b,i)=>b.classList.toggle('sel',i===qsSel));
  const el=$$('#qsList button')[qsSel];if(el)el.scrollIntoView({block:'nearest'});
}
function openDm(id){
  const d=getDm(id,true);
  d.open[me.id]=Math.max(snow(),(d.closed[me.id]||0)+1);
  save();closeQS();select(id);
}
$('#qsIn').addEventListener('input',()=>{qsSel=0;renderQS()});
$('#qsIn').addEventListener('keydown',e=>{
  if(e.key==='ArrowDown'){e.preventDefault();qsMove(1)}
  else if(e.key==='ArrowUp'){e.preventDefault();qsMove(-1)}
  else if(e.key==='Enter'){e.preventDefault();if(qsItems[qsSel])openDm(qsItems[qsSel].id)}
});
$('#qsList').addEventListener('click',e=>{const b=e.target.closest('button[data-i]');if(b&&qsItems[+b.dataset.i])openDm(qsItems[+b.dataset.i].id)});
$('#qs').addEventListener('click',e=>{if(e.target===e.currentTarget)closeQS()});

/* ---------- chat ---------- */
let seen=new Set();
function renderHead(){
  const srv=activeServer&&db.servers[activeServer];
  if(srv){
    $('#chHead').innerHTML=`<button class="icon-btn back" id="backBtn" type="button" aria-label="Back to server">${I.back}</button><span class="hash" aria-hidden="true">#</span><div class="t"><b>general</b><span>${esc(srv.name)} · ${srv.members.length} member${srv.members.length===1?'':'s'}</span></div>`;
    $('#backBtn').onclick=()=>$('#shell').classList.remove('chat-open');
    return;
  }
  const c=contact(active);if(!c)return;
  const st=presence(c);
  $('#chHead').innerHTML=`<button class="icon-btn back" id="backBtn" type="button" aria-label="Back to conversations">${I.back}</button>${av(c,36,st)}<div class="t"><b>${esc(c.display)}${tags(c)}</b><span>@${esc(c.username)} · ${STATUS[st]}</span></div>${c.official?'':`<button class="icon-btn" id="closeBtn" type="button" aria-label="Close conversation" title="Close conversation">${I.x}</button>`}`;
  $('#backBtn').onclick=()=>$('#shell').classList.remove('chat-open');
  if($('#closeBtn'))$('#closeBtn').onclick=closeConvo;
}
function syncComposer(){
  const srv=activeServer&&db.servers[activeServer],c=srv?null:(active&&contact(active));
  const ta=$('#ta');if(!srv&&!c)return;
  const off=!!(c&&c.official),lock=!!(srv&&srv.locked),nokey=!!(c&&!c.official&&!c.pubkey);
  const dis=off||lock||nokey;
  ta.disabled=dis;$('.composer').classList.toggle('locked',dis);
  $('#lockedTxt').textContent=off?'TuSo is an official account. Replies are turned off.':lock?'Waiting for a member to share this server’s encryption key. It arrives the next time one of them opens TuSo.':'This person hasn’t set up encryption yet. You can message them once they log in.';
  ta.placeholder=srv?'Message #general':(off?'This is an official account. You can’t reply.':`Message @${c.username}`);
  grow();
}
async function fillFp(){
  for(const el of $$('#msgs [data-fp]')){
    const u=byId(el.dataset.fp);
    if(!u||!u.pubkey){el.textContent=u?'They haven’t set up encryption yet. You can message them once they log in.':'';continue}
    const k=u.id+u.pubkey.x;let f=SB.fp.get(k);
    if(!f){f=await E2E.fingerprint(u.pubkey);SB.fp.set(k,f)}
    el.innerHTML=`🔒 End-to-end encrypted. Safety number <code>${f}</code>`;
  }
}
function renderChat(animate){
  const srv=activeServer&&db.servers[activeServer];
  if(activeServer&&!srv)activeServer=null;
  const c=srv?null:(active&&contact(active));
  const has=!!(srv||c);
  $('#chatEmpty').hidden=has;$('#chatMain').hidden=!has;
  closeEmoji();
  if(!has){active=null;return}
  renderHead();
  const ta=$('#ta');ta.value='';syncComposer();
  $('#sendBtn').innerHTML=I.send;
  seen=new Set();renderMsgs({initial:true});
  if(animate&&!reduce){const m=$('#chatMain');m.classList.remove('switching');void m.offsetWidth;m.classList.add('switching')}
}
function msgHTML(m,prev,isNew){
  const a=contact(m.from)||{id:m.from,display:'Deleted user',username:'deleted'},mine=m.from===me.id;
  const cont=prev&&prev.from===m.from&&m.ts-prev.ts<300000;
  return `<div class="msg${cont?' cont':''}${isNew?' enter':''}" data-id="${m.id}">${cont?`<span class="gt">${hm(m.ts)}</span>`:av(a,40)}<div class="mb">${cont?'':`<div class="mh"><span class="who">${esc(a.display)}</span>${tags(a)}<time class="when" datetime="${new Date(m.ts).toISOString()}">${hm(m.ts)}</time></div>`}<div class="txt">${fmt(m.text)}</div></div><div class="tools"><button type="button" data-act="copy">Copy</button>${mine?'<button type="button" data-act="del">Delete</button>':''}</div></div>`;
}
function renderMsgs(o={}){
  const box=$('#msgs'),srv=activeServer&&db.servers[activeServer],c=srv?null:contact(active);if(!srv&&!c)return;
  const st=store(),msgs=st?st.msgs:[];
  const near=box.scrollHeight-box.scrollTop-box.clientHeight<140;
  const fresh=o.initial?' fresh':'';
  let intro;
  if(srv)intro=`<div class="intro${fresh}"><div class="hash big" aria-hidden="true">#</div><h3>Welcome to #general</h3><p>This is the start of the <b>#general</b> channel in <b>${esc(srv.name)}</b>. Share the invite code <b>${esc(srv.code)}</b> to bring people in.</p></div>`;
  else if(c.official)intro=`<div class="intro${fresh}"><div class="intro-row">${av(c,56,'online')}<h3>${esc(c.display)}${TAG}</h3></div><p>Official messages from the TuSo team land here. You can’t reply to this account.</p></div>`;
  else intro=`<div class="intro${fresh}">${pcard(c,{state:presence(c)})}<p>This is the beginning of your direct message history with <b>@${esc(c.username)}</b>.</p><p class="fp" data-fp="${esc(c.id)}"></p></div>`;
  let h=intro,prev=null,day=null;
  for(const m of msgs){
    if(day===null||!sameDay(day,m.ts)){h+=`<div class="day"><span>${esc(dayLabel(m.ts))}</span></div>`;day=m.ts;prev=null}
    h+=msgHTML(m,prev,!o.initial&&!seen.has(m.id));prev=m;
  }
  box.innerHTML=h;fillFp();
  seen=new Set(msgs.map(m=>m.id));
  if(o.initial)box.scrollTop=box.scrollHeight;
  else if(o.stick||near)box.scrollTo({top:box.scrollHeight,behavior:reduce?'auto':'smooth'});
}
$('#msgs').addEventListener('click',async e=>{
  const row=e.target.closest('.msg');if(!row)return;
  const btn=e.target.closest('[data-act]');
  if(!btn){if(!e.target.closest('a')){$$('.msg.tap').forEach(r=>{if(r!==row)r.classList.remove('tap')});row.classList.toggle('tap')}return}
  const d=store();if(!d)return;
  const m=d.msgs.find(x=>x.id===row.dataset.id);if(!m)return;
  if(btn.dataset.act==='copy'){
    try{await navigator.clipboard.writeText(m.text);toast('Copied.')}catch(err){toast('Copying is not available here.')}
  }else if(btn.dataset.act==='del'&&m.from===me.id){
    row.style.transition='opacity .25s,transform .3s';row.style.opacity='0';row.style.transform='translateX(14px)';
    await wait(reduce?0:260);
    d.msgs=d.msgs.filter(x=>x.id!==m.id);save();renderMsgs({});renderList();toast('Message deleted.');
  }
});

/* ---------- composer ---------- */
const ta=$('#ta');
function grow(){
  ta.style.height='auto';ta.style.height=Math.min(ta.scrollHeight,160)+'px';
  const n=ta.value.length,over=n>2000;
  $('#sendBtn').disabled=!ta.value.trim()||over||ta.disabled;
  $('#emojiBtn').disabled=ta.disabled;
  const cnt=$('#cnt');cnt.textContent=n>1600?`${n} / 2000`:'';cnt.classList.toggle('over',over);
}
ta.addEventListener('input',grow);
ta.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();send()}});
$('#sendBtn').addEventListener('click',send);
function send(){
  const v=ta.value.trim();
  if(!v||v.length>2000||(!active&&!activeServer)||ta.disabled)return;
  const d=activeServer?db.servers[activeServer]:getDm(active,true);if(!d)return;
  const l=lastOf(d),ts=Math.max(snow(),(l?l.ts:0)+1);
  d.msgs.push({id:uid(),from:me.id,ts,text:v});
  if(!activeServer){d.read[me.id]=ts;d.open[me.id]=ts}
  save();ta.value='';grow();closeEmoji();renderMsgs({stick:true});if(!activeServer)renderList();
}

/* ---------- settings ---------- */
const S=$('#settings');
function openSettings(t){
  initDraft();S.inert=false;S.classList.add('open');tab(t||'account');
  setTimeout(()=>{const b=$('.snav button');if(b)b.focus({preventScroll:true})},80);
}
function closeSettings(silent){
  if(!S.classList.contains('open'))return;
  S.classList.remove('open');S.inert=true;
  if(!silent&&$('#openSettings'))$('#openSettings').focus();
}
function tab(name){
  if(name==='admin'&&!isStaff(me))name='account';
  $$('.snav button[data-tab]').forEach(b=>b.setAttribute('aria-current',b.dataset.tab===name?'page':'false'));
  $$('.spanel').forEach(p=>p.hidden=p.id!=='p-'+name);
  if(name==='account')initAccount();
  if(name==='profile')syncProfile();
  if(name==='appearance'||name==='notify')syncPrefUI();
  if(name==='storage')renderStorage();
  if(name==='admin')renderAdmin();
  if(name==='new'){renderNews();UD().seenNew=NEWS_VER;save();syncNewDot()}
  $('#scontent').scrollTop=0;
}
$$('.snav button[data-tab]').forEach(b=>b.onclick=()=>tab(b.dataset.tab));
$('#sClose').innerHTML=I.x;
$('#sClose').onclick=()=>closeSettings();
$('#logoutBtn').onclick=async()=>{
  if(await ask({title:'Log out of TuSo?',body:'Your messages stay encrypted in your account. Log back in any time to read them.',ok:'Log out'})){await cloudLogout();leave()}
};
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if($('#modal').classList.contains('open'))return;
    if($('#lbM').classList.contains('open')){$('#lbM').classList.remove('open');return}
    if($('#bugM').classList.contains('open')){closeBug();return}
    if($('#delM').classList.contains('open')){closeDel();return}
    if($('#srvM').classList.contains('open')){closeSrvM();return}
    if($('#qs').classList.contains('open')){closeQS();return}
    if($('#emojiPop').classList.contains('open')){closeEmoji();return}
    if(me&&S.classList.contains('open'))closeSettings();
  }
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'&&me){
    e.preventDefault();
    if($('#qs').classList.contains('open')){closeQS();return}
    closeSettings(true);openQS();
  }
});

/* account */
function initAccount(){
  $('#acctTop').innerHTML=`${av(me,72,me.status||'online')}<div class="nm"><b>${esc(me.display)}${tags(me)}</b><span>@${esc(me.username)} · ${esc(me.email)}</span></div>`;
  $('#acUser').value=me.username;$('#acEmail').value=me.email;
  clearErrs($('#fAccount'));clearErrs($('#fPass'));
  const fp=$('#encFp');fp.textContent='…';
  if(me.pubkey)E2E.fingerprint(me.pubkey).then(f=>{fp.textContent=f});else fp.textContent='Not set up yet';
}
$('#fAccount').addEventListener('submit',async e=>{
  e.preventDefault();clearErrs(e.target);
  const uEl=$('#acUser'),un=uEl.value.trim().toLowerCase().replace(/^@/,'');
  if(!reUser.test(un)){setErr(uEl,'Use 2 to 24 letters, numbers, dots or underscores.');return}
  if(un===me.username){toast('Nothing to change.');return}
  if(me.protected){setErr(uEl,'The default admin username can’t be changed.');return}
  if(un==='tuso'){setErr(uEl,'That username is taken.');return}
  const btn=e.target.querySelector('button[type=submit]');busy(btn,true);
  try{
    const r=await sb.rpc('username_free',{u:un});
    if(r.data===false){setErr(uEl,'That username is taken.');return}
    const old=me.username;me.username=un;
    try{await flushNow()}catch(err){me.username=old;throw err}
    renderMe();initAccount();toast('Account updated.');
  }catch(err){setErr(uEl,emsg(err))}
  finally{busy(btn,false)}
});
$('#fPass').addEventListener('submit',async e=>{
  e.preventDefault();clearErrs(e.target);
  const c=$('#pwCur'),n=$('#pwNew'),n2=$('#pwNew2');let ok=true;
  if(!c.value){setErr(c,'Enter your current password.');ok=false}
  if(n.value.length<8){setErr(n,'Use at least 8 characters.');ok=false}
  if(n2.value!==n.value){setErr(n2,'The passwords do not match.');ok=false}
  if(!ok)return;
  const btn=e.target.querySelector('button[type=submit]');busy(btn,true);
  try{
    if(!await verifyLogin(c.value)){setErr(c,'That is not your current password.');return}
    const old=SB.pv&&SB.pv.enc_priv?{enc_priv:SB.pv.enc_priv,key_salt:SB.pv.key_salt}:null;
    let w=null;
    if(old){
      try{w=await rewrap(await E2E.openPriv(c.value,old.enc_priv,old.key_salt),n.value)}
      catch(err){setErr(c,'This password can’t unlock your encryption key. Use your recovery key at the next login.');return}
      const r=await sb.from('profile_private').update(w).eq('user_id',me.id);if(r.error)throw r.error;
    }
    const up=await sb.auth.updateUser({password:n.value});
    if(up.error){if(old)await sb.from('profile_private').update(old).eq('user_id',me.id);throw up.error}
    if(w)SB.pv={...SB.pv,...w};
    e.target.reset();toast('Password updated.');
  }catch(err){setErr(c,emsg(err))}
  finally{busy(btn,false)}
});
$('#fRec').addEventListener('submit',async e=>{
  e.preventDefault();const p=$('#recPw');setErr(p,'');
  if(!p.value){setErr(p,'Enter your password.');return}
  const btn=e.target.querySelector('button[type=submit]');busy(btn,true);
  try{
    if(!SB.pv||!SB.pv.enc_priv)throw new Error('Your encryption key isn’t set up yet.');
    let pk;try{pk=await E2E.openPriv(p.value,SB.pv.enc_priv,SB.pv.key_salt)}catch(err){setErr(p,'That password doesn’t unlock your key.');return}
    const id=await E2E.wrapIdentity(pk,me.pubkey,p.value);
    const w={enc_priv:id.enc_priv,key_salt:id.key_salt,enc_priv_rec:id.enc_priv_rec};
    const r=await sb.from('profile_private').update(w).eq('user_id',me.id);if(r.error)throw r.error;
    SB.pv=w;e.target.reset();await showRecovery(id.recovery);
  }catch(err){setErr(p,emsg(err))}
  finally{busy(btn,false)}
});

/* profile */
let draft=null;
const savedProfile=()=>({display:me.display,bio:me.bio||'',avatar:me.avatar||null,banner:me.banner||0,bannerImg:me.bannerImg||null,status:me.status||'online'});
const isDirty=()=>{const s=savedProfile();return Object.keys(s).some(k=>s[k]!==draft[k])};
function initDraft(){
  draft=savedProfile();
  $('#prName').value=draft.display;$('#prBio').value=draft.bio;$('#prErr').textContent='';$('#bnErr').textContent='';
  setErr($('#prName'),'');
}
$('#prBanner').innerHTML=BANNERS.map((b,i)=>`<button type="button" class="sw" role="radio" data-i="${i}" aria-checked="false" aria-label="${b.n}" title="${b.n}" style="background:${b.css}"></button>`).join('');
function syncProfile(){
  if(!draft)return;
  $$('#prStatus .chip').forEach(b=>b.setAttribute('aria-checked',b.dataset.v===draft.status));
  $$('#prBanner .sw').forEach(b=>b.setAttribute('aria-checked',!draft.bannerImg&&+b.dataset.i===draft.banner));
  $('#prCount').textContent=`${draft.bio.length} / 190`;
  $('#prRm').disabled=!draft.avatar;
  $('#bnRm').disabled=!draft.bannerImg;
  const name=draft.display.trim()||me.display;
  $('#prAvThumb').innerHTML=av({...me,display:name,avatar:draft.avatar},72);
  $('#prPreview').innerHTML=pcard(me,{display:name,bio:draft.bio.trim(),avatar:draft.avatar,banner:draft.banner,bannerImg:draft.bannerImg,state:draft.status});
  $('#saveBar').classList.toggle('show',isDirty());
}
$('#prName').addEventListener('input',e=>{draft.display=e.target.value;setErr(e.target,'');syncProfile()});
$('#prBio').addEventListener('input',e=>{draft.bio=e.target.value;syncProfile()});
$('#prStatus').addEventListener('click',e=>{const b=e.target.closest('.chip');if(!b)return;draft.status=b.dataset.v;syncProfile()});
$('#prBanner').addEventListener('click',e=>{const b=e.target.closest('.sw');if(!b)return;draft.banner=+b.dataset.i;draft.bannerImg=null;syncProfile()});
$('#prUp').onclick=()=>$('#prFile').click();
$('#prRm').onclick=()=>{draft.avatar=null;syncProfile()};
$('#bnUp').onclick=()=>$('#bnFile').click();
$('#bnRm').onclick=()=>{draft.bannerImg=null;syncProfile()};
$('#bnFile').addEventListener('change',async e=>{
  const f=e.target.files[0];e.target.value='';if(!f)return;
  $('#bnErr').textContent='';
  if(f.size>8*1024*1024){$('#bnErr').textContent='Choose an image under 8 MB.';return}
  try{draft.bannerImg=await fileToImage(f,680,180,.8);syncProfile()}catch(err){$('#bnErr').textContent=err.message}
});
$('#prFile').addEventListener('change',async e=>{
  const f=e.target.files[0];e.target.value='';if(!f)return;
  $('#prErr').textContent='';
  if(f.size>8*1024*1024){$('#prErr').textContent='Choose an image under 8 MB.';return}
  try{draft.avatar=await fileToImage(f,160,160,.85);syncProfile()}catch(err){$('#prErr').textContent=err.message}
});
function fileToImage(file,W,H,q){
  return new Promise((res,rej)=>{
    if(!/^image\//.test(file.type))return rej(new Error('Choose an image file.'));
    const fr=new FileReader();
    fr.onerror=()=>rej(new Error('That file could not be read.'));
    fr.onload=()=>{
      const im=new Image();
      im.onerror=()=>rej(new Error('That image could not be opened.'));
      im.onload=()=>{
        const c=document.createElement('canvas');c.width=W;c.height=H;
        const sc=Math.max(W/im.width,H/im.height),sw=W/sc,sh=H/sc;
        c.getContext('2d').drawImage(im,(im.width-sw)/2,(im.height-sh)/2,sw,sh,0,0,W,H);
        res(c.toDataURL('image/jpeg',q));
      };
      im.src=fr.result;
    };
    fr.readAsDataURL(file);
  });
}
$('#prReset').onclick=()=>{initDraft();syncProfile()};
$('#prSave').onclick=()=>{
  const name=draft.display.trim();
  if(!name){setErr($('#prName'),'Display name can’t be empty.');$('#prName').focus();return}
  db=load();me=db.users.find(u=>u.id===me.id)||me;
  me.display=name;me.bio=draft.bio.trim();me.avatar=draft.avatar;me.banner=draft.banner;me.bannerImg=draft.bannerImg;me.status=draft.status;me.seen=snow();save();
  draft=savedProfile();$('#prName').value=draft.display;
  renderMe();renderList();if(active)renderMsgs({});syncProfile();toast('Profile saved.');
};

/* ---------- emoji ---------- */
const EMOJIS=Array.from('😀😃😄😁😆😅😂🤣😊😇🙂🙃😉😌😍🥰😘😋😛😜🤪🤨🧐🤓😎🥳😏😒😞😔😕🙁😣😫🥺😢😭😤😠😡🤯😳🥵🥶😱😨😰🤗🤔🤭🤫😶😐🙄😴👍👎👌🤞🤝👏🙌🙏💪👋🤙👊🤘🤟👀💙💚💛🧡💜🖤🤍💔💯🔥✨⭐🎉🎊🎁🎮🎧🎵🏆🚀💡💻📱📷🍕🍔🍟🍺☕🌙');
$('#emojiPop').innerHTML=EMOJIS.map(e=>`<button type="button" data-e="${e}" aria-label="${e}">${e}</button>`).join('');
function closeEmoji(){$('#emojiPop').classList.remove('open');$('#emojiBtn').setAttribute('aria-expanded','false')}
$('#emojiBtn').addEventListener('click',()=>{
  const pop=$('#emojiPop'),open=!pop.classList.contains('open');
  pop.classList.toggle('open',open);$('#emojiBtn').setAttribute('aria-expanded',String(open));
});
$('#emojiPop').addEventListener('click',e=>{
  const b=e.target.closest('button[data-e]');if(!b)return;
  const t=$('#ta');if(t.disabled)return;
  const a=t.selectionStart==null?t.value.length:t.selectionStart,z=t.selectionEnd==null?a:t.selectionEnd;
  const next=t.value.slice(0,a)+b.dataset.e+t.value.slice(z);
  if(next.length>2400)return;
  t.value=next;const pos=a+b.dataset.e.length;t.focus();t.setSelectionRange(pos,pos);grow();
});
document.addEventListener('click',e=>{if(!e.target.closest('#emojiPop,#emojiBtn'))closeEmoji()});

/* ---------- servers ---------- */
const ALPHA='ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function refresh(){db=load();if(me)me=db.users.find(u=>u.id===me.id)||me}
function store(){return activeServer?(db.servers[activeServer]||null):(active?getDm(active,false):null)}
const mySrvs=()=>Object.values(db.servers).filter(s=>s.members.includes(me.id)).sort((a,b)=>a.created-b.created);
const joinedCount=()=>mySrvs().length;
function genCode(){
  let c;
  do{c='';for(let i=0;i<8;i++)c+=ALPHA[Math.floor(Math.random()*ALPHA.length)]}while(Object.values(db.servers).some(s=>s.code===c));
  return c;
}
function initials(n){const w=n.trim().split(/\s+/);return (w.length>1?Array.from(w[0])[0]+Array.from(w[1])[0]:Array.from(n.trim()).slice(0,2).join('')).toUpperCase()}
function renderRail(){
  const list=mySrvs();
  $('#rail').innerHTML=`<button class="rail-btn${activeServer?'':' active'}" id="railDm" type="button" aria-label="Direct messages" title="Direct messages"${activeServer?'':' aria-current="page"'}>Tu</button><hr>`
    +list.map(s=>`<button class="rail-btn srv${s.id===activeServer?' active':''}" type="button" data-sid="${s.id}" aria-label="${esc(s.name)}" title="${esc(s.name)}">${esc(initials(s.name))}</button>`).join('')
    +`<button class="rail-btn add" id="railAdd" type="button" aria-label="Add a server" title="Add a server (${list.length} / ${MAX_SERVERS})">+</button>`;
}
function showSide(){$('#dmSide').hidden=!!activeServer;$('#srvSide').hidden=!activeServer}
function renderServerSide(){
  const s=db.servers[activeServer];if(!s)return;
  const members=s.members.map(contact).filter(Boolean).sort((a,b)=>((presence(b)!=='offline')-(presence(a)!=='offline'))||a.display.localeCompare(b.display));
  $('#srvSide').innerHTML=`<div class="srv-head"><b>${esc(s.name)}</b><span>${s.members.length} member${s.members.length===1?'':'s'}</span></div>
  <div class="srv-scroll"><div class="side-label">Text channels</div><div class="chan"><span aria-hidden="true">#</span>general</div>
  <div class="side-label">Members · ${members.length}</div>
  <ul class="mems">${members.map(u=>`<li class="mem">${av(u,32,presence(u))}<span class="mn"><span>${esc(u.display)}</span>${tags(u)}${u.id===s.owner?'<span class="owner">Owner</span>':''}</span></li>`).join('')}</ul></div>
  <div class="srv-foot"><div class="invite"><div><span class="lbl">Invite code</span><code>${esc(s.code)}</code></div><button class="btn btn-ghost" id="copyInvite" type="button">Copy</button></div><button class="btn btn-danger" id="leaveSrv" type="button">Leave server</button></div>`;
  $('#copyInvite').onclick=async()=>{try{await navigator.clipboard.writeText(s.code);toast('Invite code copied.')}catch(err){toast('Copying isn’t available here. Select the code instead.')}};
  $('#leaveSrv').onclick=leaveServer;
}
function selectServer(id){
  const s=db.servers[id];if(!s||!s.members.includes(me.id))return;
  activeServer=id;active=null;
  renderRail();showSide();renderServerSide();renderChat(true);
  if(phone())$('#shell').classList.add('chat-open');
  else setTimeout(()=>$('#ta').focus(),60);
}
function showDms(){
  activeServer=null;
  const last=UD().last,d=last&&getDm(last,false);
  active=(d&&contact(last)&&dmVisible(d))?last:null;
  renderRail();showSide();renderList();renderChat(true);
  $('#shell').classList.remove('chat-open');
}
async function leaveServer(){
  const s=db.servers[activeServer];if(!s)return;
  if(!await ask({title:`Leave ${s.name}?`,body:'You can rejoin later with the invite code. Leaving frees up a spot toward your limit of 100 servers.',ok:'Leave server',danger:true}))return;
  const {error}=await sb.rpc('leave_server',{p_id:s.id});
  if(error){toast(emsg(error));return}
  for(const m of s.msgs)SB.syn.srv.delete(m.id);
  delete db.servers[s.id];showDms();
  toast(`Left ${s.name}. ${joinedCount()} of ${MAX_SERVERS} spots used.`);
}
$('#rail').addEventListener('click',e=>{
  const b=e.target.closest('button');if(!b)return;
  if(b.id==='railDm'){if(activeServer)showDms()}
  else if(b.id==='railAdd')openSrvM('create');
  else if(b.dataset.sid)selectServer(b.dataset.sid);
});
let srvTab='create';
function syncSrvM(){
  const n=joinedCount(),full=n>=MAX_SERVERS;
  $('#srvCount').textContent=`${n} of ${MAX_SERVERS} servers joined`;
  $$('#srvTabs [role=radio]').forEach(b=>b.setAttribute('aria-checked',b.dataset.t===srvTab));
  $('#fSrvCreate').hidden=srvTab!=='create';$('#fSrvJoin').hidden=srvTab!=='join';
  $('#srvLimit').textContent=full?`You are in ${MAX_SERVERS} servers, the most allowed. Leave one to make room.`:'';
  $$('#srvM button[type=submit]').forEach(b=>b.disabled=full);
}
function openSrvM(tab){
  if(!me)return;
  srvTab=tab||'create';
  [$('#fSrvCreate'),$('#fSrvJoin')].forEach(f=>{f.reset();clearErrs(f)});
  syncSrvM();$('#srvM').classList.add('open');
  setTimeout(()=>$(srvTab==='create'?'#svName':'#svCode').focus(),60);
}
function closeSrvM(){$('#srvM').classList.remove('open')}
$('#srvM').addEventListener('click',e=>{if(e.target===e.currentTarget||e.target.closest('[data-close]'))closeSrvM()});
$('#srvTabs').addEventListener('click',e=>{
  const b=e.target.closest('[role=radio]');if(!b)return;
  srvTab=b.dataset.t;syncSrvM();setTimeout(()=>$(srvTab==='create'?'#svName':'#svCode').focus(),30);
});
$('#fSrvCreate').addEventListener('submit',async e=>{
  e.preventDefault();clearErrs(e.target);
  const el=$('#svName'),name=el.value.trim().replace(/\s+/g,' ');
  if(joinedCount()>=MAX_SERVERS){syncSrvM();return}
  if(name.length<2||name.length>32){setErr(el,'Use 2 to 32 characters.');return}
  const btn=e.target.querySelector('button[type=submit]');busy(btn,true);
  try{
    const r=await sb.rpc('create_server',{p_name:name});if(r.error)throw r.error;
    const row=r.data,key=await subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
    const s=db.servers[row.id]={id:row.id,name:row.name,owner:row.owner,code:row.code,members:[me.id],msgs:[],created:+row.created,key,locked:false,keyed:new Set([me.id])};
    const kr=await sb.from('server_keys').insert(await wrapSrvKey(s,key,me));if(kr.error)throw kr.error;
    closeSrvM();selectServer(s.id);toast(`Created ${name}.`);
  }catch(err){setErr(el,emsg(err))}
  finally{busy(btn,false)}
});
$('#fSrvJoin').addEventListener('submit',async e=>{
  e.preventDefault();clearErrs(e.target);
  const el=$('#svCode'),code=el.value.trim().toUpperCase().replace(/[^A-Z0-9]/g,'');
  if(joinedCount()>=MAX_SERVERS){syncSrvM();return}
  if(!code){setErr(el,'Enter an invite code.');return}
  const btn=e.target.querySelector('button[type=submit]');busy(btn,true);
  try{
    const r=await sb.rpc('join_server',{p_code:code});if(r.error){setErr(el,emsg(r.error));return}
    await syncNow();
    const s=db.servers[r.data.id];
    closeSrvM();if(s){selectServer(s.id);toast(`Joined ${s.name}. ${joinedCount()} of ${MAX_SERVERS} spots used.`)}
  }catch(err){setErr(el,emsg(err))}
  finally{busy(btn,false)}
});

/* ---------- storage panel ---------- */
const LIMIT=10*1024*1024;
function fmtB(n){return n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(2)} MB`}
function renderStorage(){
  const total=JSON.stringify(db).length;
  const msgs=JSON.stringify(db.dms).length+JSON.stringify(Object.values(db.servers).map(s=>s.msgs)).length;
  let img=0;for(const u of db.users)img+=(u.avatar||'').length+(u.bannerImg||'').length;
  img+=JSON.stringify(db.bugs.map(b=>b.shots)).length;
  const other=Math.max(0,total-msgs-img),pct=100;
  $('#stBig').innerHTML=`<b>${fmtB(total)}</b><span>loaded on this device</span>`;
  const seg=(n,c)=>`<i class="${c}" style="width:${total?Math.min(100,n/total*100):0}%"></i>`;
  $('#stBar').innerHTML=seg(msgs,'s1')+seg(img,'s2')+seg(other,'s3');
  $('#stLegend').innerHTML=[['s1','Messages',msgs],['s2','Images',img],['s3','Accounts and settings',other]].map(([c,l,n])=>`<li><i class="sw-dot ${c}"></i><span>${l}</span><b>${fmtB(n)}</b></li>`).join('');
  $('#stWarn').textContent='';
  const n=joinedCount();
  $('#stSrv').innerHTML=`<div class="srow"><div><b>Servers joined</b><span>You can be in up to ${MAX_SERVERS}. Leaving a server frees a spot straight away.</span></div><b>${n} / ${MAX_SERVERS}</b></div><div class="stbar thin" role="img" aria-label="${n} of ${MAX_SERVERS} servers"><i class="s1" style="width:${n/MAX_SERVERS*100}%"></i></div>`;
}
$('#stClearMsgs').onclick=async()=>{
  if(!await ask({title:'Clear your direct messages?',body:'Every message in your direct message conversations will be deleted for you and for the people you talked to. This can’t be undone.',ok:'Clear messages',danger:true}))return;
  refresh();const now=snow();
  for(const d of Object.values(db.dms)){
    if(!d.users.includes(me.id)||d.users.includes('tuso'))continue;
    d.msgs=[];d.closed[me.id]=Math.max(now,activity(d));
  }
  UD().last=null;if(!activeServer)active=null;
  save();renderList();renderChat(true);
  if(!activeServer)$('#shell').classList.remove('chat-open');
  renderStorage();toast('Direct messages cleared.');
};
$('#stClearImg').onclick=()=>{
  refresh();me.avatar=null;me.bannerImg=null;save();
  initDraft();renderMe();renderList();
  if(active||activeServer)renderMsgs({});
  renderStorage();toast('Images removed.');
};

/* ---------- what's new ---------- */
const NEWS_VER='0.7';
const RELEASES=[
  {ver:'0.7',date:'Nov 22, 2026',title:'TuSo goes online, end to end encrypted',blurb:'Your account, servers and messages now live in the cloud and follow you to any device. Chats stay private: they are encrypted before they leave your device.',items:[
    ['New','Cloud accounts','Sign in from any device with your email. Admins can still use their username.'],
    ['Security','End-to-end encryption','Direct messages and server chats are encrypted on your device. Only people in the conversation can read them.'],
    ['New','Recovery key','Shown once when you sign up. It is the only way back to your old messages if you forget your password.'],
    ['New','Safety numbers','Compare numbers with a friend to be sure nobody is listening in.'],
    ['Improved','Live updates','New messages, members and reports arrive without refreshing.']]},
  {ver:'0.6',date:'Nov 21, 2026',title:'Safer bug triage and update messages',blurb:'Marking a bug fixed now asks first and can be undone. New releases are also posted to you by TuSo.',items:[
    ['New','Release messages','Every new update is posted to your TuSo conversation, so you never miss one.'],
    ['Improved','Fixed warning','Admins confirm before a report is marked fixed.'],
    ['Improved','Revert a fix','A fixed report can be reverted, which also removes the Bug hunter badge if it was the only one.']]},
  {ver:'0.5',date:'Nov 20, 2026',title:'Bug reports and a smoother phone',blurb:'Tell us what broke, and get a badge when it gets fixed. TuSo also feels lighter under your thumb.',items:[
    ['New','Bug reports','The bug button opens a form with a title, what went wrong, steps and up to 5 screenshots.'],
    ['New','Admin triage','Reports land in the Admin panel. Admins mark them Checking, Fixed or Not a bug, and you get a TuSo message.'],
    ['New','Bug hunter badge','Get a report fixed and the badge appears next to your name.'],
    ['Improved','Phone experience','Full-screen layout for iPhone and Android, bottom sheets, bigger touch targets, safe areas, no zoom on typing and slide transitions.'],
    ['Improved','Status dots','Online, Idle, Do not disturb and Invisible dots are larger and easier to read.']]},
  {ver:'0.4',date:'Nov 20, 2026',title:'Moderation, roles and a lighter TuSo',blurb:'Staff can now warn and ban, admins manage the team, and the whole site runs with far less weight.',items:[
    ['Security','Password hashing','Passwords are hashed with PBKDF2 and a unique salt. Older accounts upgrade the next time they log in.'],
    ['New','Warn and Ban','Staff can warn or ban members from the Admin panel. Warnings arrive as a notice and a TuSo message. Bans block sign-in.'],
    ['New','Admin and Staff roles','Admins add or remove Staff. Staff can warn and ban members, but not other staff.'],
    ['New','Badge tooltips','Hover any badge to see what it means.'],
    ['Improved','Lighter and faster','No blur effects, still film grain, fewer fonts and a gentler background redraw.'],
    ['Improved','Delete account','Moved under Log out. It asks for your password first.'],
    ['Improved','What’s new','Redesigned, with release notes you can expand.']]},
  {ver:'0.3',date:'Nov 20, 2026',title:'Servers, emoji and storage',blurb:'Group spaces, a bigger toolbox for messages, and a clear view of what TuSo keeps.',items:[
    ['New','Servers','Create one, join with an invite code and chat in #general. You can be in up to 100.'],
    ['New','Emoji picker','100 emoji, one click away from the message box.'],
    ['New','Profile banners','Pick a style or upload your own image.'],
    ['New','Storage page','A 10 MB meter with tools to clear messages and images.'],
    ['New','Admin panel and Staff badge','Manage accounts, servers and who is on staff.'],
    ['New','Bug report button','Next to Settings. It does nothing yet.']]},
  {ver:'0.2',date:'Nov 19, 2026',title:'Real conversations',blurb:'Direct messages between accounts, with a friendly official account.',items:[
    ['New','Live direct messages','Accounts in the same browser can talk, and updates appear across tabs.'],
    ['New','Official TuSo account','Sends the welcome message. It can’t be closed or replied to.'],
    ['Improved','Profile settings','Reorganised, with a live preview and an unsaved-changes bar.'],
    ['Improved','Motion','Smooth transitions across the whole site.']]},
  {ver:'0.1',date:'Nov 19, 2026',title:'First build',blurb:'The foundation.',items:[
    ['New','Login and sign up','Styled after Discord.'],
    ['New','Settings','Account, appearance and notifications.'],
    ['New','Animated background','Slow black, grey and white fog.']]}
];
const nitems=r=>r.items.map(([t,h,d])=>`<div class="nitem"><span class="ntag ${t[0].toLowerCase()}">${esc(t)}</span><div><b>${esc(h)}</b><span>${esc(d)}</span></div></div>`).join('');
function syncNewDot(){$('#newDot').hidden=!me||UD().seenNew===NEWS_VER}
function renderNews(){
  const [top,...rest]=RELEASES;
  $('#newsList').innerHTML=`<article class="hero"><div class="hero-top"><span class="ver">v${esc(top.ver)}</span><span class="latest">Latest</span><span class="rel-date">${esc(top.date)}</span></div><h3>${esc(top.title)}</h3><p>${esc(top.blurb)}</p><div class="nlist">${nitems(top)}</div></article><div class="news-h">Earlier releases</div>`
    +rest.map(r=>`<details class="reld"><summary><span class="ver o">v${esc(r.ver)}</span><b>${esc(r.title)}</b><span class="rel-date">${esc(r.date)}</span></summary><p>${esc(r.blurb)}</p><div class="nlist">${nitems(r)}</div></details>`).join('');
}

/* ---------- moderation helpers ---------- */
let noticeOpen=false;
function notice(title,body,ok){
  return new Promise(res=>{
    const m=$('#modal'),y=$('#mYes'),n=$('#mNo');
    $('#mTitle').textContent=title;$('#mBody').textContent=body;y.textContent=ok||'OK';y.className='btn btn-primary';n.hidden=true;
    m.classList.add('open');
    const done=()=>{m.classList.remove('open');n.hidden=false;y.onclick=null;m.onkeydown=null;res()};
    y.onclick=done;m.onkeydown=e=>{if(e.key==='Escape'){e.stopPropagation();done()}};
    setTimeout(()=>y.focus(),30);
  });
}
function enforceBan(){
  if(me&&me.ban){
    const r=me.ban.reason;leave();
    notice('Your account was banned',r?`Reason: ${r}`:'A staff member banned this account.');
    return true;
  }
  return false;
}
async function checkWarnings(){
  if(noticeOpen||!me)return;
  const w=(me.warnings||[]).find(x=>!x.ack);if(!w)return;
  noticeOpen=true;
  await notice('You received a warning',w.reason||'A staff member warned you about your behavior.','I understand');
  noticeOpen=false;
  if(!me)return;
  const w2=me&&(me.warnings||[]).find(x=>x.id===w.id);
  if(w2){w2.ack=true;sb.from('warnings').update({ack:true}).eq('id',w.id).then(()=>{})}
  checkWarnings();
}
function tusoSay(){/* the server sends these messages now */}
function askReason({title,body,ok}){
  return new Promise(res=>{
    const m=$('#reasonM'),inp=$('#rsIn'),f=$('#fReason');
    $('#rsT').textContent=title;$('#rsB').textContent=body;$('#rsYes').textContent=ok;inp.value='';setErr(inp,'');
    m.classList.add('open');setTimeout(()=>inp.focus(),60);
    const done=v=>{m.classList.remove('open');f.onsubmit=null;$('#rsNo').onclick=null;m.onclick=null;m.onkeydown=null;res(v)};
    f.onsubmit=e=>{e.preventDefault();const r=inp.value.trim();if(r.length<3){setErr(inp,'Write a short reason, at least 3 characters.');return}done(r)};
    $('#rsNo').onclick=()=>done(null);
    m.onclick=e=>{if(e.target===m)done(null)};
    m.onkeydown=e=>{if(e.key==='Escape'){e.stopPropagation();done(null)}};
  });
}
const canManage=(actor,t)=>{
  if(!actor||!t||t.id===actor.id||t.protected||isAdmin(t))return false;
  return isAdmin(actor)||(isStaff(actor)&&!isStaff(t));
};
function removeUser(id){
  db.users=db.users.filter(u=>u.id!==id);delete db.data[id];
  for(const k of Object.keys(db.dms))if(db.dms[k].users.includes(id))delete db.dms[k];
  for(const sid of Object.keys(db.servers)){
    const sv=db.servers[sid];sv.members=sv.members.filter(x=>x!==id);
    if(!sv.members.length)delete db.servers[sid];else if(sv.owner===id)sv.owner=sv.members[0];
  }
}

/* ---------- bug reports ---------- */
const BUG_ST={open:'New',checking:'Checking',fixed:'Fixed',nobug:'Not a bug'};
let bugFilter='all';const openBugs=new Set();
const when=ts=>new Date(ts).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
function renderBugs(){
  const A=isAdmin(me),all=[...db.bugs].sort((a,b)=>b.ts-a.ts);
  const cnt=k=>k==='all'?all.length:all.filter(b=>b.status===k).length;
  $('#bugF').innerHTML=[['all','All'],['open','New'],['checking','Checking'],['fixed','Fixed'],['nobug','Not a bug']].map(([k,l])=>`<button type="button" class="bf" data-bf="${k}" aria-pressed="${bugFilter===k}">${l}<span>${cnt(k)}</span></button>`).join('');
  const list=bugFilter==='all'?all:all.filter(b=>b.status===bugFilter);
  $('#adBugs').innerHTML=list.length?list.map(b=>{
    const u=db.users.find(x=>x.id===b.by);
    const shots=b.shots.map((x,i)=>`<button type="button" class="thumb" data-lb="${b.id}:${i}" aria-label="Open screenshot ${i+1}"><img src="${x}" alt="" loading="lazy"></button>`).join('');
    const sb=(st,l)=>`<button class="btn ${b.status===st?'btn-primary':'btn-ghost'}" type="button" data-act="bugst" data-id="${b.id}" data-st="${st}" aria-pressed="${b.status===st}">${l}</button>`;
    return `<li class="bug"><details data-bid="${b.id}"${openBugs.has(b.id)?' open':''}><summary><div class="ad-meta"><b>${esc(b.title)}</b><span>${u?esc(u.display)+' · @'+esc(u.username):'Deleted user'} · ${when(b.ts)}${b.shots.length?` · ${b.shots.length} photo${b.shots.length===1?'':'s'}`:''}</span></div><span class="bs ${b.status}">${BUG_ST[b.status]}</span></summary><div class="bug-body"><h4>What went wrong</h4><p>${esc(b.reason)}</p><h4>Steps</h4><p>${esc(b.steps)}</p>${shots?`<div class="thumbs">${shots}</div>`:''}${A?`<div class="actions">${sb('checking','Checking')}${sb('fixed','Fixed')}${sb('nobug','Not a bug')}${b.status==='fixed'?`<button class="btn btn-danger" type="button" data-act="bugst" data-id="${b.id}" data-st="revert">Revert fix</button>`:''}</div>`:'<p>Only admins can change the status.</p>'}</div></details></li>`;
  }).join(''):`<li class="none">${all.length?'No reports in this filter.':'No bug reports yet.'}</li>`;
}
$('#p-admin').addEventListener('click',e=>{
  const f=e.target.closest('[data-bf]');if(f){bugFilter=f.dataset.bf;renderBugs();return}
  const t=e.target.closest('[data-lb]');
  if(t){const [id,i]=t.dataset.lb.split(':'),b=db.bugs.find(x=>x.id===id);if(b){$('#lbImg').src=b.shots[+i];$('#lbM').classList.add('open')}}
});
$('#adBugs').addEventListener('toggle',e=>{const d=e.target;if(d.dataset&&d.dataset.bid){d.open?openBugs.add(d.dataset.bid):openBugs.delete(d.dataset.bid)}},true);
$('#lbM').addEventListener('click',()=>$('#lbM').classList.remove('open'));

/* ---------- send a bug report ---------- */
let bugShots=[];
const closeBug=()=>$('#bugM').classList.remove('open');
function drawShots(){
  $('#bgShots').innerHTML=bugShots.map((x,i)=>`<div class="shot"><img src="${x}" alt="Screenshot ${i+1}"><button type="button" data-rm="${i}" aria-label="Remove screenshot ${i+1}">×</button></div>`).join('')+(bugShots.length<5?'<button type="button" class="shot-add" id="bgAdd" aria-label="Add screenshots">+</button>':'');
  $('#bgCount').textContent=bugShots.length+' / 5';
}
function openBug(){
  refresh();bugShots=[];$('#fBug').reset();
  for(const k of ['#bgTitle','#bgReason','#bgSteps'])setErr($(k),'');
  $('#bgPhotoErr').textContent='';drawShots();
  $('#bugM').classList.add('open');
  if(!phone())setTimeout(()=>$('#bgTitle').focus(),60);
}
function fileToShot(file,max,q){
  return new Promise((res,rej)=>{
    if(!/^image\//.test(file.type))return rej(new Error('Only image files can be attached.'));
    const url=URL.createObjectURL(file),im=new Image();
    im.onerror=()=>{URL.revokeObjectURL(url);rej(new Error('One image could not be opened.'))};
    im.onload=()=>{
      URL.revokeObjectURL(url);
      const sc=Math.min(1,max/Math.max(im.width,im.height)),c=document.createElement('canvas');
      c.width=Math.round(im.width*sc);c.height=Math.round(im.height*sc);
      const g=c.getContext('2d');g.fillStyle='#fff';g.fillRect(0,0,c.width,c.height);g.drawImage(im,0,0,c.width,c.height);
      res(c.toDataURL('image/jpeg',q));
    };
    im.src=url;
  });
}
$('#bgShots').addEventListener('click',e=>{
  if(e.target.closest('#bgAdd')){$('#bgFile').click();return}
  const r=e.target.closest('[data-rm]');if(r){bugShots.splice(+r.dataset.rm,1);$('#bgPhotoErr').textContent='';drawShots()}
});
$('#bgFile').addEventListener('change',async e=>{
  const fs=[...e.target.files];e.target.value='';
  const err=$('#bgPhotoErr');err.textContent='';
  const room=5-bugShots.length;
  if(fs.length>room)err.textContent='You can attach up to 5 screenshots. The extra ones were skipped.';
  for(const f of fs.slice(0,room)){
    if(f.size>15*1024*1024){err.textContent='Each screenshot must be under 15 MB.';continue}
    try{bugShots.push(await fileToShot(f,720,.7))}catch(x){err.textContent=x.message}
  }
  drawShots();
});
$('#bgNo').onclick=closeBug;
for(const k of ['#bgTitle','#bgReason','#bgSteps'])$(k).addEventListener('input',()=>setErr($(k),''));
$('#fBug').addEventListener('submit',async e=>{
  e.preventDefault();
  const t=$('#bgTitle'),r=$('#bgReason'),st=$('#bgSteps');
  for(const k of [t,r,st])setErr(k,'');
  let bad=null;
  if(t.value.trim().length<3){setErr(t,'Add a short title.');bad=bad||t}
  if(r.value.trim().length<10){setErr(r,'Describe what went wrong, at least 10 characters.');bad=bad||r}
  if(st.value.trim().length<5){setErr(st,'List the steps so we can repeat it.');bad=bad||st}
  if(bad){bad.focus();return}
  const title=t.value.trim(),btn=$('#fBug button[type=submit]');busy(btn,true);
  try{
    const row={id:uid(),reporter:me.id,title,reason:r.value.trim(),steps:st.value.trim(),shots:bugShots.slice()};
    const {data,error}=await sb.from('bugs').insert(row).select('id,reporter,ts,title,reason,steps,shots,status,prev,handler,upd').single();
    if(error)throw error;
    db.bugs.push(mapBug(data));closeBug();toast('Report sent. Thank you!');pull();
  }catch(err){toast(emsg(err))}
  finally{busy(btn,false)}
});

/* ---------- admin panel ---------- */
function renderAdmin(){
  if(!isStaff(me))return;
  const A=isAdmin(me),users=[...db.users].sort((a,b)=>a.created-b.created),srvs=Object.values(db.servers).sort((a,b)=>a.created-b.created);
  const msgs=Object.values(db.dms).reduce((n,d)=>n+d.msgs.length,0)+srvs.reduce((n,s)=>n+s.msgs.length,0);
  $('#adStats').innerHTML=[['Accounts',users.length],['Staff',users.filter(isStaff).length],['Banned',users.filter(u=>u.ban).length],['Servers',srvs.length],['Bug reports',db.bugs.length],['New reports',db.bugs.filter(b=>b.status==='open').length]].map(([l,n])=>`<div class="stat"><b>${n}</b><span>${l}</span></div>`).join('');
  $('#adUsers').innerHTML=users.map(u=>{
    const w=(u.warnings||[]).length,m=canManage(me,u),acts=[];
    const btn=(act,label,cls)=>`<button class="btn ${cls||'btn-ghost'}" type="button" data-act="${act}" data-id="${u.id}">${label}</button>`;
    if(A&&!isAdmin(u)&&u.id!==me.id)acts.push(btn('staff',u.role==='staff'?'Remove staff':'Make staff'));
    if(m&&!u.ban)acts.push(btn('warn','Warn'));
    if(m)acts.push(u.ban?btn('unban','Unban'):btn('ban','Ban','btn-danger'));
    if(A&&m)acts.push(btn('deluser','Delete','btn-danger'));
    if(u.protected)acts.push('<span class="owner">Protected</span>');
    const meta=`@${esc(u.username)} · ${esc(u.email)} · joined ${new Date(u.created).toLocaleDateString()}${w?` · ${w} warning${w===1?'':'s'}`:''}${u.ban?` · <span class="ad-flag">banned${u.ban.reason?': '+esc(u.ban.reason):''}</span>`:''}`;
    return `<li>${av(u,36,presence(u))}<div class="ad-meta"><b>${esc(u.display)}${tags(u)}</b><span>${meta}</span></div><div class="actions">${acts.join('')}</div></li>`;
  }).join('');
  $('#adSrvs').innerHTML=srvs.length?srvs.map(s=>{const o=contact(s.owner);return `<li><span class="hash" aria-hidden="true">#</span><div class="ad-meta"><b>${esc(s.name)}</b><span>${s.members.length} member${s.members.length===1?'':'s'} · owner ${o?esc(o.display):'unknown'} · code ${esc(s.code)}</span></div><div class="actions">${A?`<button class="btn btn-danger" type="button" data-act="delsrv" data-id="${s.id}">Delete</button>`:''}</div></li>`}).join(''):'<li class="none">No servers yet.</li>';
  renderBugs();
}
$('#p-admin').addEventListener('click',async e=>{
  const b=e.target.closest('button[data-act]');if(!b)return;
  if(!isStaff(me)){toast('Staff only.');return}
  const id=b.dataset.id,act=b.dataset.act,u=db.users.find(x=>x.id===id);
  const rpc=async(fn,args,msg)=>{
    busy(b,true);const {error}=await sb.rpc(fn,args);busy(b,false);
    if(error){toast(emsg(error));return false}
    await syncNow();renderAdmin();if(msg)toast(msg);return true;
  };
  if(act==='delsrv'){
    const sv=db.servers[id];if(!sv||!isAdmin(me))return;
    if(!await ask({title:`Delete ${sv.name}?`,body:'The server and its messages are removed for everyone.',ok:'Delete server',danger:true}))return;
    if(await rpc('admin_delete_server',{p_id:id},'Server deleted.')){if(activeServer===id)showDms();else renderRail()}
    return;
  }
  if(act==='bugst'){
    if(!isAdmin(me)){toast('Only admins can change a report’s status.');return}
    const rp=db.bugs.find(x=>x.id===id);let st=b.dataset.st;
    if(!rp)return;
    const revert=st==='revert';
    if(revert)st=(rp.prev&&rp.prev!=='fixed'&&BUG_ST[rp.prev])?rp.prev:'open';
    if(!BUG_ST[st]||rp.status===st)return;
    const reporter=db.users.find(x=>x.id===rp.by);
    if(st==='fixed'&&!await ask({title:'Mark this bug as fixed?',body:`${reporter?reporter.display:'The reporter'} gets the Bug hunter badge and a TuSo message. You can revert this afterwards.`,ok:'Mark as fixed'}))return;
    if(revert&&!await ask({title:'Revert this fix?',body:'The report goes back to '+BUG_ST[st].toLowerCase()+'. The Bug hunter badge is removed unless they have another fixed report.',ok:'Revert',danger:true}))return;
    await rpc('bug_set_status',{p_id:id,p_status:st},revert?`Reverted to ${BUG_ST[st].toLowerCase()}.`:`Marked as ${BUG_ST[st].toLowerCase()}.`);
    return;
  }
  if(!u)return;
  if(act==='staff'){
    if(!isAdmin(me)||isAdmin(u)||u.id===me.id)return;
    const on=u.role!=='staff';
    await rpc('set_staff',{target:id,on_:on},on?`${u.display} is now staff.`:`${u.display} is no longer staff.`);
  }else if(act==='warn'||act==='ban'){
    if(!canManage(me,u))return;
    const warn=act==='warn';
    const r=await askReason(warn?{title:`Warn ${u.display}?`,body:'They see this reason as a notice and in their TuSo messages.',ok:'Send warning'}:{title:`Ban ${u.display}?`,body:'They are signed out now and can’t log in until you unban them.',ok:'Ban member'});
    if(!r)return;
    await rpc(warn?'mod_warn':'mod_ban',{target:id,p_reason:r},warn?`Warning sent to ${u.display}.`:`${u.display} is banned.`);
  }else if(act==='unban'){
    if(!canManage(me,u))return;
    await rpc('mod_unban',{target:id},`${u.display} is unbanned.`);
  }else if(act==='deluser'){
    if(!isAdmin(me)||!canManage(me,u))return;
    if(!await ask({title:`Delete ${u.display}?`,body:'Their account, conversations and server memberships are removed for good.',ok:'Delete account',danger:true}))return;
    if(await rpc('admin_delete_user',{target:id},'Account deleted.')){renderList();renderRail()}
  }
});

/* ---------- delete my account ---------- */
const closeDel=()=>$('#delM').classList.remove('open');
$('#delBtn').onclick=()=>{
  if(me.protected){toast('The default admin account can’t be deleted.');return}
  $('#fDel').reset();setErr($('#delPw'),'');$('#delM').classList.add('open');setTimeout(()=>$('#delPw').focus(),60);
};
$('#delNo').onclick=closeDel;
$('#delM').addEventListener('click',e=>{if(e.target===e.currentTarget)closeDel()});
$('#fDel').addEventListener('submit',async e=>{
  e.preventDefault();const p=$('#delPw');setErr(p,'');
  if(!p.value){setErr(p,'Enter your password to confirm.');return}
  const btn=$('#fDel button[type=submit]');busy(btn,true);
  try{
    if(!await verifyLogin(p.value)){setErr(p,'That password is not right.');return}
    const {error}=await sb.rpc('delete_my_account');if(error)throw error;
    const id=me.id;SB.ready=false;closeDel();await KS.del(id);leave();toast('Account deleted.');
  }catch(err){setErr(p,emsg(err))}
  finally{busy(btn,false)}
});

/* ---------- tooltips for badges ---------- */
const tipEl=$('#tip');let tipT=0;
function showTip(el,touch){
  tipEl.textContent=el.dataset.tip;tipEl.classList.add('show');
  const r=el.getBoundingClientRect(),w=tipEl.offsetWidth,h=tipEl.offsetHeight;
  let x=Math.max(8,Math.min(innerWidth-w-8,r.left+r.width/2-w/2)),y=r.top-h-8;if(y<8)y=r.bottom+8;
  tipEl.style.left=x+'px';tipEl.style.top=y+'px';
  clearTimeout(tipT);if(touch)tipT=setTimeout(()=>tipEl.classList.remove('show'),2200);
}
document.addEventListener('pointerover',e=>{const t=e.target.closest&&e.target.closest('[data-tip]');if(t)showTip(t,e.pointerType==='touch')});
document.addEventListener('pointerout',e=>{if(e.target.closest&&e.target.closest('[data-tip]'))tipEl.classList.remove('show')});

/* ---------- staying in sync ---------- */
document.addEventListener('visibilitychange',()=>{
  if(document.hidden)return;
  if(bg.mode!=='static'&&!bg.raf){bg.last=performance.now();bg.raf=requestAnimationFrame(bgLoop)}
  if(me&&SB.ready){me.seen=snow();const d=active&&getDm(active,false);if(d)markRead(d);save();renderList();pull()}
});
setInterval(()=>{if(!me||!SB.ready||document.hidden)return;me.seen=snow();save()},60000);
addEventListener('online',()=>{if(me&&SB.ready){flush();pull(true)}});

/* ---------- init ---------- */
async function restore(){
  showBoot('Signing you in…');
  try{
    const {data}=await sb.auth.getSession();
    if(!data.session){showAuth();return}
    await bootstrap(data.session.user,null);
  }catch(err){resetCloud();showBoot('Couldn’t reach TuSo. '+emsg(err),true)}
}
async function initCloud(){
  if(!window.supabase||!window.supabase.createClient){showBoot('TuSo couldn’t load its files. Reload the page.');return}
  try{sb=window.supabase.createClient(CFG.url,CFG.key,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:false,storageKey:'tuso.auth'}})}
  catch(e){showBoot('TuSo isn’t set up correctly.');return}
  sb.auth.onAuthStateChange(ev=>{if(ev==='SIGNED_OUT')setTimeout(()=>{if(me&&SB.ready){leave();toast('You were signed out.')}},0)});
  $('#bootRetry').onclick=()=>{resetCloud();restore()};
  $('#bootOut').onclick=async()=>{try{await sb.auth.signOut()}catch(e){}resetCloud();showAuth()};
  await restore();
}
$('#sendBtn').innerHTML=I.send;
bgSize();makeGrain();bgSet(reduce?'static':'animated');
initCloud();
})();
