import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {loadEngine,fakeServer,taskFor,MiB} from './transfer-support.mjs';

test('a 4.6 MiB photo is read once for all fingerprint samples and upload chunks',async()=>{
 const data=Buffer.alloc(Math.round(4.6*MiB),42),task=taskFor(data),server=fakeServer(data);
 delete task.fingerprint;
 const {engine,reads}=loadEngine();
 assert.equal(await engine.upload(task,{fetch:server.fetch,fingerprint:async source=>{
  for(const start of [0,2*MiB,data.length-65536])assert.deepEqual(Buffer.from(await source.sample(start,start+65536)),data.subarray(start,start+65536));
  return 'd'.repeat(64);
 }}),true);
 assert.deepEqual(reads,[data.length]);
});

test('large videos use bounded 8 MiB reads and small fingerprint samples',async()=>{
 const data=Buffer.alloc(20*MiB+123,53),task=taskFor(data),server=fakeServer(data);
 delete task.fingerprint;
 const {engine,reads}=loadEngine();
 assert.equal(await engine.upload(task,{fetch:server.fetch,fingerprint:async source=>{
  for(const start of [0,10*MiB,data.length-65536])await source.sample(start,start+65536);
  return 'd'.repeat(64);
 }}),true);
 assert.deepEqual(reads,[65536,65536,65536,8*MiB,8*MiB,4*MiB+123]);
 assert.equal(server.offset,data.length);
});

test('pause interrupts native photo preparation without creating a server upload',async()=>{
 let began,reader;
 const ready=new Promise(resolve=>{began=resolve;});
 const {engine}=loadEngine({read:r=>{reader=r;began();return false;}});
 const task=taskFor(Buffer.alloc(MiB));delete task.fingerprint;
 const pending=engine.upload(task,{fetch:()=>assert.fail('must not send before preparation'),fingerprint:async source=>{await source.sample(0,65536);return 'd'.repeat(64);}});
 await ready;task.cancelTransfer();assert.equal(await pending,false);
 assert.equal(reader.aborted,true);assert.equal(task.cancelTransfer,null);
});

test('unavailable native media fails once with a clear preparation error',async()=>{
 const {engine,reads}=loadEngine({read:r=>{queueMicrotask(()=>r.onerror?.());return false;}});
 const task=taskFor(Buffer.alloc(MiB));delete task.fingerprint;
 await assert.rejects(engine.upload(task,{fetch:()=>assert.fail('no request'),fingerprint:async source=>source.sample(0,65536)}),/파일을 읽지 못했습니다/);
 assert.equal(reads.length,1);
});

test('cached photo preparation preserves the existing resume fingerprint',async()=>{
 const app=await fs.readFile(new URL('../public/app.js',import.meta.url),'utf8');
 const code=app.slice(app.indexOf('function sha256('),app.indexOf('async function run('));
 const context=vm.createContext({Uint8Array,Uint32Array,DataView,TextEncoder});
 vm.runInContext(code,context);
 for(const length of [0,100,Math.round(4.6*MiB),10*MiB]){
  const data=Buffer.alloc(length,37),task=taskFor(data),{engine}=loadEngine();
  const source=engine.createSource(task.file,new AbortController().signal);
  const starts=[0,Math.max(0,Math.floor(length/2)-32768),Math.max(0,length-65536)];
  const meta=Buffer.from(JSON.stringify([task.file.name,task.file.size,task.file.lastModified]));
  const expected=createHash('sha256').update(Buffer.concat([meta,...starts.map(start=>data.subarray(start,start+65536))])).digest('hex');
  assert.equal(await context.fingerprint(task,source),expected);
  source.release();
 }
});
