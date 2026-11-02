import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {loadEngine,fakeServer,taskFor,MiB} from './transfer-support.mjs';

test('multiple photos finish directly from POST responses without polling or sleeping',async()=>{
 const {engine}=loadEngine();
 for(const size of [Math.round(4.6*MiB),Math.round(6.2*MiB)]){
  const data=randomBytes(size),task=taskFor(data),server=fakeServer(data);
  assert.equal(await engine.upload(task,{fetch:server.fetch,sleep:()=>assert.fail('successful upload must never sleep')}),true);
  assert.equal(server.offset,size);assert.equal(server.complete,true);
  assert.equal(server.calls.some(c=>c.method==='GET'),false);
  assert.equal(server.calls.length,Math.ceil(size/MiB)+2);
  assert.equal(task.cancelTransfer,null);
 }
});

test('lost responses reconcile the server offset before retry, including completion',async()=>{
 const data=randomBytes(12*MiB+123),task=taskFor(data);
 const failed=new Set();
 const server=fakeServer(data,{fail:async(stage,start)=>{
  const key=`${stage}:${start}`;
  if(((stage==='before'&&start===3*MiB)||(stage==='after'&&start===7*MiB)||stage==='complete')&&!failed.has(key)){
   failed.add(key);throw new Error('connection lost');
  }
 }});
 const {engine}=loadEngine();
 assert.equal(await engine.upload(task,{fetch:server.fetch,sleep:async()=>{}}),true);
 assert.equal(server.complete,true);assert.equal(server.offset,data.length);
 assert.equal(server.written.length,Math.ceil(data.length/MiB));
 assert.equal(server.calls.filter(c=>c.method==='GET').length,3);
});

test('a missing response times out, then resumes without duplicate bytes',async()=>{
 const data=randomBytes(MiB),task=taskFor(data);
 const server=fakeServer(data,{fail:async(stage,start,options)=>{
  if(stage==='after')await new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}));
 }});
 const {engine}=loadEngine({timeout:ms=>ms===120000?20:ms});
 assert.equal(await engine.upload(task,{fetch:server.fetch,sleep:async()=>{}}),true);
 assert.equal(server.written.length,1);assert.equal(server.complete,true);
});

test('pause aborts the active POST and resume checks the last committed offset',async()=>{
 const data=randomBytes(2*MiB),task=taskFor(data);
 let began;
 const ready=new Promise(resolve=>{began=resolve;});
 let stall=true;
 const server=fakeServer(data,{fail:async(stage,start,options)=>{
  if(stage==='before'&&stall){began();await new Promise((_,reject)=>options.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}));}
 }});
 const {engine}=loadEngine();
 const pending=engine.upload(task,{fetch:server.fetch});
 await ready;task.cancelTransfer();assert.equal(await pending,false);
 assert.equal(server.offset,0);assert.equal(task.cancelTransfer,null);
 stall=false;task.pause=false;
 assert.equal(await engine.upload(task,{fetch:server.fetch}),true);
 assert.equal(server.calls.some(c=>c.method==='GET'),true);
 assert.equal(server.complete,true);
});

test('permanent failures do not retry and repeated network failures are bounded',async()=>{
 const {engine}=loadEngine();let attempts=0;
 await assert.rejects(engine.upload(taskFor(Buffer.alloc(1)),{fetch:async()=>{attempts++;return new Response('{"error":"disk full"}',{status:507});}}),/disk full/);
 assert.equal(attempts,1);attempts=0;
 await assert.rejects(engine.upload(taskFor(Buffer.alloc(1)),{fetch:async()=>{attempts++;throw new Error('offline');},sleep:async()=>{}}),/offline/);
 assert.equal(attempts,7);
});

test('empty files finalize without chunk requests; invalid offsets are rejected',async()=>{
 const {engine}=loadEngine(),data=Buffer.alloc(0),server=fakeServer(data);
 assert.equal(await engine.upload(taskFor(data),{fetch:server.fetch}),true);
 assert.equal(server.written.length,0);
 await assert.rejects(engine.upload(taskFor(Buffer.alloc(1)),{fetch:async()=>new Response(JSON.stringify({id:'a'.repeat(32),offset:2}))}),/전송 위치/);
});
