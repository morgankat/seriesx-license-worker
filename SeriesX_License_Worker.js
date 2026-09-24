/* Series X owner license service for Cloudflare Workers.
 *
 * Required binding:
 *   KV namespace binding named LICENSES
 * Required Worker secret:
 *   OWNER_ADMIN_KEY
 *
 * KV record format (JSON):
 *   {"status":"active","expiresAt":0}
 * status may be pending, active, blocked, suspended, expired.
 *
 * IMPORTANT: this service only becomes a real anti-unlock mechanism when the
 * trading gateway/OAuth exchange also checks this license server before issuing
 * trading credentials. A browser-only check can always be edited by a client.
 */

function cors(){return {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Methods':'GET,POST,OPTIONS'}}
function json(data,status=200){return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json',...cors()}})}
function norm(v){return String(v||'').trim()}
async function readLicense(env,id){
  if(!id)return null;
  const raw=await env.LICENSES.get('license:'+id);
  if(!raw)return null;
  try{return JSON.parse(raw)}catch{return null}
}
function activeStatus(rec){
  if(!rec)return 'unknown';
  if(rec.expiresAt&&Date.now()>Number(rec.expiresAt))return 'expired';
  return rec.status||'unknown';
}

export default {
  async fetch(req,env){
    if(req.method==='OPTIONS')return new Response('',{status:204,headers:cors()});
    const u=new URL(req.url);

    // Public client registration: called automatically after a successful
    // broker login. It never grants owner/admin access. New accounts start as
    // pending so the owner can see every login immediately and activate paid
    // clients with one tap; existing status is preserved on later logins.
    if(u.pathname==='/register'&&req.method==='POST'){
      let body={};try{body=await req.json()}catch{return json({description:'Invalid JSON.'},400)}
      const clientId=norm(body.clientId);
      if(!clientId||clientId.length>120)return json({description:'Invalid clientId.'},400);
      const key='license:'+clientId;
      const raw=await env.LICENSES.get(key);
      let rec=null;try{rec=raw?JSON.parse(raw):null}catch{}
      const now=Date.now();
      if(!rec){
        rec={status:'pending',createdAt:now,updatedAt:now,lastSeenAt:now,expiresAt:0,broker:norm(body.broker)||'unknown',env:norm(body.env)||'unknown',appVersion:norm(body.appVersion)||'Series X'};
      }else{
        rec.lastSeenAt=now;rec.updatedAt=now;
        if(body.broker)rec.broker=norm(body.broker);
        if(body.env)rec.env=norm(body.env);
        if(body.appVersion)rec.appVersion=norm(body.appVersion);
      }
      await env.LICENSES.put(key,JSON.stringify(rec));
      return json({ok:true,clientId,status:activeStatus(rec),createdAt:rec.createdAt||now,lastSeenAt:rec.lastSeenAt});
    }

    if(u.pathname==='/license'&&req.method==='GET'){
      const id=norm(u.searchParams.get('clientId'));
      const rec=await readLicense(env,id);
      return json({clientId:id,status:activeStatus(rec),expiresAt:rec?.expiresAt||null});
    }

    if(u.pathname==='/admin/session'&&req.method==='POST'){
      const auth=norm(req.headers.get('Authorization'));
      const expected='Bearer '+norm(env.OWNER_ADMIN_KEY);
      if(!env.OWNER_ADMIN_KEY||auth!==expected)return json({description:'Owner authentication failed.'},401);
      const sessionToken=crypto.randomUUID()+'.'+crypto.randomUUID();
      // Short-lived owner token. For production, store a hash/server session in KV.
      await env.LICENSES.put('admin-session:'+sessionToken,JSON.stringify({createdAt:Date.now()}),{expirationTtl:1800});
      return json({sessionToken,expiresIn:1800});
    }

    if(u.pathname==='/admin/license'&&req.method==='POST'){
      const auth=norm(req.headers.get('Authorization'));
      const token=auth.startsWith('Bearer ')?auth.slice(7):'';
      const sess=token?await env.LICENSES.get('admin-session:'+token):null;
      if(!sess)return json({description:'Owner session expired or invalid.'},401);
      let body={};try{body=await req.json()}catch{return json({description:'Invalid JSON.'},400)}
      const clientId=norm(body.clientId),status=norm(body.status);
      if(!clientId||!['pending','active','blocked','suspended','expired'].includes(status))return json({description:'Invalid clientId or status.'},400);
      const existingRaw=await env.LICENSES.get('license:'+clientId);
      let existing=null;try{existing=existingRaw?JSON.parse(existingRaw):null}catch{}
      const now=Date.now();
      const record={...(existing||{}),status,updatedAt:now,expiresAt:body.expiresAt?Number(body.expiresAt):(existing?.expiresAt||0),lastSeenAt:existing?.lastSeenAt||now,createdAt:existing?.createdAt||now};
      await env.LICENSES.put('license:'+clientId,JSON.stringify(record));
      return json({ok:true,clientId,status,expiresAt:record.expiresAt});
    }

    if(u.pathname==='/admin/clients'&&req.method==='GET'){
      const auth=norm(req.headers.get('Authorization'));
      const token=auth.startsWith('Bearer ')?auth.slice(7):'';
      const sess=token?await env.LICENSES.get('admin-session:'+token):null;
      if(!sess)return json({description:'Owner session expired or invalid.'},401);
      const list=await env.LICENSES.list({prefix:'license:'});
      const clients=await Promise.all(list.keys.map(async k=>{
        const id=k.name.slice('license:'.length);
        const raw=await env.LICENSES.get(k.name);
        let rec=null;try{rec=raw?JSON.parse(raw):null}catch{}
        return {clientId:id,status:activeStatus(rec),createdAt:rec?.createdAt||null,updatedAt:rec?.updatedAt||null,lastSeenAt:rec?.lastSeenAt||null,expiresAt:rec?.expiresAt||null,broker:rec?.broker||null,env:rec?.env||null};
      }));
      clients.sort((a,b)=>(b.lastSeenAt||0)-(a.lastSeenAt||0));
      return json({clients});
    }

    return json({ok:true,service:'Series X License Service'});
  }
}
