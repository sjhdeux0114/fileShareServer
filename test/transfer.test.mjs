import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
const context = vm.createContext({setTimeout});
vm.runInContext(await fs.readFile(new URL('../public/transfer.js',import.meta.url),'utf8'),context);
const upload = context.FileShareTransfer.upload;

test('64 MiB upload automatically recovers repeated disconnects and lost acknowledgements',async()=>{
 const task={file:{size:64*1024*1024},offset:0,pause:false};
 let offset=0, complete=false, dropped=new Set(), retries=0;
 await upload(task,{
  chunkSize:16*1024*1024,sleep:async()=>{},message:()=>retries++,
  init:async()=>({id:'test',offset}),status:async()=>({offset,complete}),
  send:async(start,end)=>{
   assert.equal(start,offset); assert.ok(end-start<=2*1024*1024);
   // Reproduce a connection failure every ~10 MiB, both before and after commit.
   const boundary=Math.floor(start/(10*1024*1024));
   if(!dropped.has(boundary)){dropped.add(boundary);if(boundary%2===0)offset=end;throw new Error('connection lost');}
   offset=end;return {offset};
  },complete:async()=>{complete=true;throw new Error('completion response lost');}
 });
 assert.equal(offset,task.file.size);assert.equal(complete,true);assert.ok(retries>=7);
});
test('pause during reconnect stops retries, permanent errors are not retried',async()=>{
 const task={file:{size:10},id:'test',offset:0};let calls=0;
 assert.equal(await upload(task,{status:async()=>{calls++;throw new Error('offline');},message:()=>{},sleep:async()=>{task.pause=true;}}),false);
 assert.equal(calls,1);
 task.pause=false;
 await assert.rejects(upload(task,{status:async()=>{throw Object.assign(new Error('no space'),{status:507});},message:()=>{throw new Error('must not retry');}}),/no space/);
});
test('persistent disconnection stops after bounded retries',async()=>{
 const task={file:{size:10},offset:0};let attempts=0;
 await assert.rejects(upload(task,{init:async()=>{attempts++;throw new Error('offline');},message:()=>{},sleep:async()=>{}}),/offline/);
 assert.equal(attempts,13);
});
