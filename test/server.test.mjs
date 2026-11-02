import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import vm from 'node:vm';
import { createHash, randomBytes } from 'node:crypto';
import { createApp } from './process-app.mjs';
import {loadEngine,taskFor} from './transfer-support.mjs';

test('four-character password is accepted and three characters are rejected',async t=>{
  const f=await fixture(t);
  assert.equal((await f.req('/api/settings',{method:'POST',body:JSON.stringify({password:'123'})})).status,400);
  const saved=await f.req('/api/settings',{method:'POST',body:JSON.stringify({password:'1234'})});
  assert.equal(saved.status,200);
  const login=await fetch(f.base+'/api/login',{method:'POST',headers:{'X-FileShare':'1'},body:JSON.stringify({password:'1234'})});
  assert.equal(login.status,200);
  assert.equal((await fs.readFile(path.join(f.dir,'settings.ini'),'utf8')).includes('Password = 1234'),false);
});

test('64 MiB real upload recovers lost responses and confirms final SHA256',async t=>{
  const f=await fixture(t);
  const {engine}=loadEngine();
  const data=randomBytes(64*1024*1024), task=taskFor(data);
  task.file=new File([data],'recovery.mov');
  let dropped=new Set(), completed=false, retries=0;
  await engine.upload(task,{
    sleep:async()=>{},onState:phase=>{if(phase==='retrying')retries++;},
    fetch:async(url,options)=>{
      if(url.endsWith('/chunks')){
        const start=Number(options.headers['Upload-Offset']);
        const section=Math.floor(start/(10*1024*1024));
        const fail=!dropped.has(section);dropped.add(section);
        if(fail&&section%2===1)throw new Error('network failed before commit');
        const response=await f.req(url,options);
        if(fail){await response.arrayBuffer();throw new Error('response lost after commit');}
        return response;
      }
      const response=await f.req(url,options);
      if(url.endsWith('/complete')){await response.json();completed=true;throw new Error('completion response lost');}
      return response;
    }
  });
  assert.equal(completed,true);assert.ok(retries>=7);
  const downloaded=Buffer.from(await (await f.req('/api/content?path=recovery.mov')).arrayBuffer());
  assert.equal(createHash('sha256').update(downloaded).digest('hex'),createHash('sha256').update(data).digest('hex'));
});

async function fixture(t) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'fileshare-test-'));
  let app,base,cookie;
  async function start(){app=await createApp({dataDir:dir,pin:'12345678'});await new Promise(r=>app.server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${app.server.address().port}`;const res=await fetch(base+'/api/login',{method:'POST',headers:{'X-FileShare':'1'},body:JSON.stringify({pin:'12345678'})});cookie=res.headers.get('set-cookie')?.split(';')[0] || '';}
  async function stop(){app.server.closeAllConnections();await new Promise(r=>app.server.close(r));}
  await start();t.after(async()=>{await stop();await fs.rm(dir,{recursive:true,force:true});});
  return { get base(){return base;},get cookie(){return cookie;},dir,stop,start,
    req:(url,options={})=>fetch(base+url,{...options,headers:{cookie,'X-FileShare':'1',...options.headers}}),
    async init(name,size, fingerprint='a'.repeat(64)){const r=await this.req('/api/uploads',{method:'POST',body:JSON.stringify({name,size,fingerprint})});assert.equal(r.status,201);return r.json();}
  };
}

test('4.6 MiB photo crosses chunk boundaries with receipt timings and identical content', async t=>{
  const f=await fixture(t), data=randomBytes(Math.round(4.6*1024*1024));
  const chunkSize=(await (await f.req('/api/info')).json()).chunkSize;
  assert.equal(chunkSize,1024*1024);
  const u=await f.init('photo-boundary.jpg',data.length);
  const elapsed=[];
  for(let offset=0;offset<data.length;){
    const end=Math.min(offset+chunkSize,data.length), started=performance.now();
    const response=await f.req(`/api/uploads/${u.id}/chunks`,{method:'POST',headers:{'Upload-Offset':String(offset)},body:data.subarray(offset,end),signal:AbortSignal.timeout(10000)});
    assert.equal(response.status,200);
    assert.notEqual(response.headers.get('connection'),'close');
    assert.match(response.headers.get('server-timing'),/^receive;dur=[\d.]+, close;dur=[\d.]+$/);
    assert.equal((await response.json()).offset,end);
    assert.deepEqual(await (await f.req(`/api/uploads/${u.id}/progress`)).json(),{active:false,offset:end,complete:false});
    elapsed.push(Math.round(performance.now()-started)); offset=end;
  }
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  assert.deepEqual(await (await f.req(`/api/uploads/${u.id}/progress`)).json(),{active:false,offset:data.length,complete:true});
  assert.deepEqual(Buffer.from(await (await f.req('/api/content?path=photo-boundary.jpg')).arrayBuffer()),data);
  const diagnostics=await (await f.req('/api/diagnostics/uploads')).json();
  const ends=diagnostics.events.filter(e=>e.stage==='end'&&e.path.includes(u.id));
  assert.ok(ends.some(e=>e.method==='POST'&&e.path.endsWith('/chunks')));
  assert.ok(ends.some(e=>e.path.endsWith('/complete')));
  assert.ok(ends.every(e=>Number.isInteger(e.durationMs||0)&&!e.errorStatus));
  t.diagnostic(`Local chunk response times (ms): ${elapsed.join(', ')}`);
});
test('authentication, CSRF guard, login throttling and logout',async t=>{
  const f=await fixture(t);
  assert.equal((await fetch(f.base+'/')).status,200);
  assert.equal((await fetch(f.base+'/api/entries')).status,401);
  assert.equal((await f.req('/api/uploads',{method:'POST',headers:{Origin:'http://evil.test'}})).status,403);
  assert.equal((await fetch(f.base+'/api/login',{method:'POST',body:'{}'})).status,403);
  for(let i=0;i<10;i++)assert.equal((await f.req('/api/login',{method:'POST',body:'{"pin":"bad"}'})).status,401);
  assert.equal((await f.req('/api/login',{method:'POST',body:'{"pin":"bad"}'})).status,429);
  assert.equal((await f.req('/api/logout',{method:'POST'})).status,200);
  assert.equal((await f.req('/api/entries')).status,401);
});
test('unicode file roundtrip, restart resume, wrong offset, ranges and deletion',async t=>{
  const f=await fixture(t);const data=randomBytes(1024*1024+17);const u=await f.init('여행 영상 🎬.mov',data.length);
  let r=await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:data.subarray(0,700000)});assert.equal(r.status,200);
  assert.equal((await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:Buffer.from('bad')})).status,409);
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,409);
  await f.stop();await f.start();
  r=await f.req('/api/uploads',{method:'POST',body:JSON.stringify({name:u.name,size:u.size,fingerprint:u.fingerprint})});const resumed=await r.json();assert.equal(resumed.id,u.id);assert.equal(resumed.offset,700000);
  r=await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'700000'},body:data.subarray(700000)});assert.equal(r.status,200);
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  r=await f.req('/api/content?path='+encodeURIComponent(u.name));assert.match(r.headers.get('content-disposition'),/attachment/);assert.deepEqual(Buffer.from(await r.arrayBuffer()),data);
  r=await f.req('/api/content?preview=1&path='+encodeURIComponent(u.name),{headers:{Range:'bytes=123-456'}});assert.equal(r.status,206);assert.equal(r.headers.get('content-type'),'video/quicktime');assert.deepEqual(Buffer.from(await r.arrayBuffer()),data.subarray(123,457));
  r=await f.req('/api/content?path='+encodeURIComponent(u.name),{headers:{Range:'bytes=-17'}});assert.deepEqual(Buffer.from(await r.arrayBuffer()),data.subarray(-17));
  for(const range of ['bytes=999999999-','bytes=2-1','bytes=-0','bytes=0-1,3-4'])assert.equal((await f.req('/api/content?path='+encodeURIComponent(u.name),{headers:{Range:range}})).status,416);
  r=await f.req('/api/content?path='+encodeURIComponent(u.name),{method:'HEAD'});assert.equal(Number(r.headers.get('content-length')),data.length);
  assert.equal((await (await f.req('/api/entries')).json()).entries.length,1);
  assert.equal((await f.req('/api/operations',{method:'POST',body:JSON.stringify({action:'delete',path:u.name})})).status,200);
  assert.equal((await f.req('/api/content?path='+encodeURIComponent(u.name))).status,404);
});
test('empty file, same names, safe file names, upload cancellation and limits',async t=>{
  const f=await fixture(t);const u=await f.init('photo.txt',0);assert.equal(u.name,'photo.txt');
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  const r=await f.req('/api/content?path='+encodeURIComponent(u.name));assert.equal((await r.arrayBuffer()).byteLength,0);
  const another=await f.init('photo.txt',0,'b'.repeat(64));assert.notEqual(u.id,another.id);
  assert.equal((await f.req(`/api/uploads/${another.id}`,{method:'DELETE'})).status,200);
  for(const size of [-1,1.1,Number.MAX_SAFE_INTEGER])assert.equal((await f.req('/api/uploads',{method:'POST',body:JSON.stringify({name:'bad',size,fingerprint:'c'.repeat(64)})})).status,400);
  const free=(await (await f.req('/api/info')).json()).freeBytes;
  if(free>20*1024**3+16*1024**2){const large=await f.init('large.mov',20*1024**3);assert.equal(large.size,21474836480);}
  else {assert.equal((await f.req('/api/uploads',{method:'POST',body:JSON.stringify({name:'large.mov',size:20*1024**3,fingerprint:'f'.repeat(64)})})).status,507);}
  const pending=await f.init('chunk-limit.bin',32*1024**2,'c'.repeat(64));
  assert.equal((await f.req(`/api/uploads/${pending.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:Buffer.alloc(16*1024*1024+1)})).status,413);
});
test('aborted chunk rolls back and can be resumed',async t=>{
  const f=await fixture(t);const u=await f.init('abort.bin',1024*1024);
  await new Promise(resolve=>{
    const req=http.request(f.base+`/api/uploads/${u.id}`,{method:'PATCH',headers:{Cookie:f.cookie,'X-FileShare':'1','Upload-Offset':'0','Content-Length':1024*1024}});
    req.on('error',()=>resolve());req.write(Buffer.alloc(65536,42));setTimeout(()=>req.destroy(),100);
  });
  let value;for(let i=0;i<40;i++){const r=await f.req(`/api/uploads/${u.id}`);if(r.status===200){value=await r.json();break;}await new Promise(r=>setTimeout(r,25));}assert.equal(value.offset,0);
  assert.equal((await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:Buffer.alloc(1024*1024,42)})).status,200);
});

test('silent mobile connection times out, releases the upload and rolls back partial bytes', {timeout:30000}, async t=>{
  const f=await fixture(t), data=randomBytes(1024*1024);
  const u=await f.init('stalled-photo.jpg',data.length);
  let request, initialResponse;
  const response=new Promise((resolve,reject)=>{
    request=http.request(f.base+`/api/uploads/${u.id}`,{method:'PATCH',headers:{Cookie:f.cookie,'X-FileShare':'1','Upload-Offset':'0','Content-Length':data.length}},res=>{
      res.resume(); res.on('end',()=>{initialResponse=res.statusCode;resolve(res.statusCode);});
    });
    request.on('error',reject);
    request.write(data.subarray(0,65536));
  });
  t.after(()=>request.destroy());
  // Wait for actual bytes on disk; a status GET issued before PATCH acquires
  // its lock can itself make PATCH return 409, invalidating this reproduction.
  let busy=false;
  for(let i=0;i<100;i++){
    const stat=await fs.stat(path.join(f.dir,'uploads',u.id,'body'));
    if(stat.size>0){busy=true;break;}
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  assert.equal(busy,true,`initial PATCH response: ${initialResponse}`);
  assert.equal((await f.req(`/api/uploads/${u.id}`)).status,409);
  const progress=await (await f.req(`/api/uploads/${u.id}/progress`)).json();
  assert.equal(progress.active,true);
  assert.equal(progress.received,65536);
  assert.equal(progress.storing,false);
  assert.equal(progress.offset,undefined);
  const diagnostics=await (await f.req('/api/diagnostics/uploads')).json();
  assert.ok(diagnostics.events.some(e=>e.method==='PATCH'&&e.path.endsWith(u.id)&&e.stage==='start'));
  assert.equal(diagnostics.events.some(e=>e.method==='PATCH'&&e.path.endsWith(u.id)&&e.stage==='end'),false);
  assert.equal((await fetch(f.base+`/api/uploads/${u.id}/progress`)).status,401);
  const duplicate=await f.req('/api/uploads',{method:'POST',signal:AbortSignal.timeout(2000),body:JSON.stringify({name:u.name,size:u.size,fingerprint:u.fingerprint})});
  assert.equal(duplicate.status,409);
  // The duplicate request must not block unrelated uploads behind the global lock.
  const other=await f.req('/api/uploads',{method:'POST',signal:AbortSignal.timeout(2000),body:JSON.stringify({name:'other.txt',size:0,fingerprint:'b'.repeat(64)})});
  assert.equal(other.status,201);
  assert.equal(await response,408);
  assert.deepEqual(await (await f.req(`/api/uploads/${u.id}/progress`)).json(),{active:false,offset:0,complete:false});
  assert.equal((await (await f.req(`/api/uploads/${u.id}`)).json()).offset,0);
  assert.equal((await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:data})).status,200);
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  const downloaded=Buffer.from(await (await f.req('/api/content?path=stalled-photo.jpg')).arrayBuffer());
  assert.deepEqual(downloaded,data);
});
test('client SHA256 works without WebCrypto on insecure LAN HTTP',async()=>{
  const source=await fs.readFile(new URL('../public/app.js',import.meta.url),'utf8');
  const fn=source.slice(source.indexOf('function sha256('),source.indexOf('async function fingerprint('));const context=vm.createContext({Uint8Array,Uint32Array,DataView});vm.runInContext(fn,context);
  for(const input of [Buffer.alloc(0),Buffer.from('abc'),randomBytes(196000)])assert.equal(context.sha256(input),createHash('sha256').update(input).digest('hex'));
});
test('password settings persist, remember login across restart, invalidate old sessions',async t=>{
  const f=await fixture(t);const original=f.cookie;
  let r=await f.req('/api/settings',{method:'POST',body:JSON.stringify({password:'새로운-password-2026'})});assert.equal(r.status,200);const remembered=r.headers.get('set-cookie').split(';')[0];assert.match(r.headers.get('set-cookie'),/HttpOnly/);
  assert.equal((await fetch(f.base+'/api/info',{headers:{Cookie:original}})).status,401);
  await f.stop();await f.start();
  assert.equal((await fetch(f.base+'/api/info',{headers:{Cookie:remembered}})).status,200);
  r=await fetch(f.base+'/api/login',{method:'POST',headers:{'X-FileShare':'1'},body:JSON.stringify({password:'새로운-password-2026'})});assert.equal(r.status,200);
  const config=await fs.readFile(path.join(f.dir,'settings.ini'),'utf8');assert.ok(!config.includes('새로운-password-2026'));
});
test('shared folder explorer: mkdir, rename, copy, move, ZIP, delete and conflict safety',async t=>{
  const f=await fixture(t);const root=path.join(f.dir,'shared');await fs.mkdir(path.join(root,'source'));await fs.writeFile(path.join(root,'source','메모.txt'),'original bytes');
  const op=body=>f.req('/api/operations',{method:'POST',body:JSON.stringify(body)});
  assert.equal((await op({action:'mkdir',name:'destination'})).status,200);
  assert.equal((await op({action:'copy',path:'source',destination:'destination'})).status,200);
  assert.equal(await fs.readFile(path.join(root,'destination','source','메모.txt'),'utf8'),'original bytes');
  assert.equal((await op({action:'copy',path:'source',destination:'destination'})).status,409);
  assert.equal((await op({action:'move',path:'source',destination:'source'})).status,409);
  assert.equal((await op({action:'rename',path:'destination/source',name:'renamed'})).status,200);
  assert.equal((await op({action:'move',path:'destination/renamed',destination:''})).status,200);
  let r=await f.req('/api/zip?path=renamed');assert.equal(r.status,200);const zip=Buffer.from(await r.arrayBuffer());assert.equal(zip.subarray(0,2).toString(),'PK');assert.ok(zip.includes(Buffer.from('original bytes')));
  assert.equal((await op({action:'delete',path:'renamed'})).status,200);
  assert.equal((await op({action:'delete',path:''})).status,403);
  for(const unsafe of ['../settings.json','/etc/passwd','C:/Windows','a\\b'])assert.equal((await f.req('/api/content?path='+encodeURIComponent(unsafe))).status,403);
  assert.equal((await op({action:'rename',path:'source',name:'../escape'})).status,400);
});
test('upload to nested shared folder and changing shared root',async t=>{
  const f=await fixture(t);const root=path.join(f.dir,'shared');await fs.mkdir(path.join(root,'album'));
  const payload=Buffer.from('video bytes');let r=await f.req('/api/uploads',{method:'POST',body:JSON.stringify({name:'movie.mp4',size:payload.length,fingerprint:'e'.repeat(64),target:'album'})});const u=await r.json();assert.equal(r.status,201);
  await f.req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':'0'},body:payload});assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  assert.equal((await f.req(`/api/uploads/${u.id}/complete`,{method:'POST'})).status,200);
  assert.deepEqual(await fs.readFile(path.join(root,'album','movie.mp4')),payload);
  const other=path.join(f.dir,'other');await fs.mkdir(other);await fs.writeFile(path.join(other,'existing.txt'),'existing');
  assert.equal((await f.req('/api/settings',{method:'POST',body:JSON.stringify({sharedRoot:other})})).status,200);
  assert.equal((await (await f.req('/api/entries')).json()).entries[0].name,'existing.txt');
  assert.equal((await f.req('/api/settings',{method:'POST',body:JSON.stringify({sharedRoot:f.dir})})).status,400);
});
