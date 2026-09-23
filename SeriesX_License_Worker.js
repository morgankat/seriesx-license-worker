/* Series X owner license service for Cloudflare Workers.
 *
 * Required binding:
 *   KV namespace binding named LICENSES
 * Required Worker secret:
 *   OWNER_ADMIN_KEY
 *
 * KV record format (JSON):
 *   {"status":"active","expiresAt":0}
 * status may be active, blocked, suspended, expired.
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
      if(!clientId||!['active','blocked','suspended','expired'].includes(status))return json({description:'Invalid clientId or status.'},400);
      const record={status,updatedAt:Date.now(),expiresAt:body.expiresAt?Number(body.expiresAt):0};
      await env.LICENSES.put('license:'+clientId,JSON.stringify(record));
      return json({ok:true,clientId,status,expiresAt:record.expiresAt});
    }

    return json({ok:true,service:'Series X License Service'});
  }
}
