import { spawn } from 'node:child_process';
import path from 'node:path';
// The HTTP integration suite launches the actual native release backend.
export async function createApp(options={}) {
  let child,port;
  const server={listening:false,
    listen(_port,_host,ready){
      child=spawn(path.resolve(process.env.FILESHARE_BINARY||'.local/fileshare-test'+(process.platform==='win32'?'.exe':'')),[],{env:{...process.env,PORT:'0',FILESHARE_DATA:options.dataDir,FILESHARE_PASSWORD:options.pin||'12345678',FILESHARE_NO_BROWSER:'1'},stdio:['ignore','pipe','pipe']});
      let output='';child.stdout.on('data',data=>{output+=data;const m=/READY http:\/\/127\.0\.0\.1:(\d+)/.exec(output);if(m&&!server.listening){port=Number(m[1]);server.listening=true;ready();}});child.stderr.on('data',data=>{if(!server.listening)process.stderr.write(data);});child.on('error',e=>{throw e});
    },address(){return{port};},closeAllConnections(){},close(ready){server.listening=false;if(child.exitCode!==null||child.signalCode!==null){ready();return;}child.once('exit',ready);child.kill();}};
  return {server,pin:options.pin,data:options.dataDir,get pid(){return child?.pid;}};
}
