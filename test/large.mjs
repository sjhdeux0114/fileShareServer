// Real 21 GiB network upload and full download integrity verification.
import { createApp } from './process-app.mjs';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const dir=path.join(process.env.FILESHARE_LARGE_DIR||os.tmpdir(),'fileshare-large-test-'+Date.now());await fs.mkdir(dir,{recursive:true});
let app,base,cookie;const started=Date.now();let peak=0;let serverPeak=0;
const monitor=setInterval(()=>peak=Math.max(peak,process.memoryUsage().rss),100);
async function start(){app=await createApp({dataDir:dir,pin:'12345678'});await new Promise(r=>app.server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${app.server.address().port}`;const r=await fetch(base+'/api/login',{method:'POST',headers:{'X-FileShare':'1'},body:'{"pin":"12345678"}'});cookie=r.headers.get('set-cookie').split(';')[0];}
async function stop(){app.server.closeAllConnections();await new Promise(r=>app.server.close(r));}
async function req(url,options={}){const r=await fetch(base+url,{...options,headers:{Cookie:cookie,'X-FileShare':'1',...options.headers}});if(!r.ok)throw new Error(`${r.status}: ${await r.text()}`);return r;}
try{
  await start();const size=21*1024**3+123;const chunk=Buffer.alloc(16*1024**2);for(let i=0;i<chunk.length;i++)chunk[i]=(i*31+(i>>>16))%251;
  const body=JSON.stringify({name:'21GiB-대용량-검증.mov',size,fingerprint:'d'.repeat(64)});const u=await (await req('/api/uploads',{method:'POST',body})).json();const expected=createHash('sha256');
  for(let offset=0;offset<size;){const part=chunk.subarray(0,Math.min(chunk.length,size-offset));expected.update(part);const result=await (await req(`/api/uploads/${u.id}`,{method:'PATCH',headers:{'Upload-Offset':String(offset)},body:part})).json();offset=result.offset;if(offset%(1024**3)===0){console.log(`Uploaded ${offset/1024**3} GiB`);if(process.platform==='win32'){const m=spawnSync('powershell.exe',['-NoProfile','-Command',`(Get-Process -Id ${app.pid}).PeakWorkingSet64`],{encoding:'utf8'});serverPeak=Math.max(serverPeak,Number(m.stdout.trim())||0);}}if(offset===5*1024**3){await stop();await start();const resumed=await(await req('/api/uploads',{method:'POST',body})).json();assert.equal(resumed.id,u.id);assert.equal(resumed.offset,offset);console.log('Restart at 5 GiB: resume verified');}}
  await req(`/api/uploads/${u.id}/complete`,{method:'POST'});
  const response=await req('/api/content?path='+encodeURIComponent(u.name));assert.equal(Number(response.headers.get('content-length')),size);const actual=createHash('sha256');let downloaded=0;for await(const bytes of response.body){actual.update(bytes);downloaded+=bytes.length;}assert.equal(downloaded,size);const hash=actual.digest('hex');assert.equal(hash,expected.digest('hex'));
  const result={bytes:size,uploadGiB:21,downloadBytes:downloaded,sha256:hash,restartResumeAtGiB:5,backend:'Go native',serverPeakWorkingSetMiB:Math.round(serverPeak/1024**2),clientPeakRssMiB:Math.round(peak/1024**2),durationSeconds:Math.round((Date.now()-started)/1000),platform:process.platform,node:process.version,passed:true};await fs.mkdir('release',{recursive:true});await fs.writeFile('release/large-file-test.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}finally{clearInterval(monitor);if(app?.server.listening)await stop();await fs.rm(dir,{recursive:true,force:true});}
