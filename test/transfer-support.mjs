import fs from 'node:fs/promises';
import vm from 'node:vm';
export const MiB=1024*1024;
const code=await fs.readFile(new URL('../public/transfer.js',import.meta.url),'utf8');
export function loadEngine({read,timeout}={}){
  const reads=[];
  class FileReader {
    readAsArrayBuffer(blob){
      reads.push(blob.size);
      if(read?.(this,blob)===false)return;
      blob.arrayBuffer().then(result=>{if(!this.aborted){this.result=result;this.onload?.();}},()=>this.onerror?.());
    }
    abort(){this.aborted=true;this.onabort?.();}
  }
  const context=vm.createContext({FileReader,Uint8Array,AbortController,clearTimeout,
    setTimeout:(fn,ms)=>setTimeout(fn,timeout?.(ms)??ms)});
  vm.runInContext(code,context);
  return {engine:context.FileShareTransfer,reads};
}
export function fakeServer(data,{fail}={}){
  let offset=0,complete=false;
  const calls=[],id='a'.repeat(32),written=[];
  const response=(value,status=200)=>new Response(JSON.stringify(value),{status});
  const fetch=async(url,options)=>{
    calls.push({url,method:options.method,offset:Number(options.headers['Upload-Offset']),signal:options.signal});
    if(url==='/api/uploads')return response({id,offset},201);
    if(url.endsWith('/chunks')){
      const start=Number(options.headers['Upload-Offset']);
      await fail?.('before',start,options);
      if(start!==offset)return response({error:'wrong offset'},409);
      const part=Buffer.from(options.body);
      if(!part.equals(data.subarray(start,start+part.length)))throw new Error('corrupt chunk');
      written.push([start,part.length]);offset+=part.length;
      await fail?.('after',start,options);
      return response({offset});
    }
    if(url.endsWith('/complete')){complete=true;await fail?.('complete',offset,options);return response({complete,offset});}
    return response({offset,complete});
  };
  return {fetch,calls,written,get offset(){return offset;},get complete(){return complete;}};
}
export function taskFor(data){return {file:new File([data],'photo.png',{lastModified:1234}),offset:0,pause:false,fingerprint:'d'.repeat(64)};}
