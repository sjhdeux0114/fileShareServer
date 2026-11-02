const $ = selector => document.querySelector(selector);
const state = { files: [], queue: [], running: false, chunk: 16 * 1024 * 1024, active: null, path: '', clipboard: null };
let noticeTimer;
function notice(text) { $('#notice').textContent = text; $('#notice').hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => $('#notice').hidden = true, 7000); }
function size(n) { if (!n) return '0 B'; const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024))); return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${['B','KiB','MiB','GiB','TiB'][i]}`; }
async function api(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(()=>controller.abort(), url.endsWith('/complete') ? 30*60*1000 : url==='/api/pick-folder' ? 10*60*1000 : 30000);
  try {
    const res = await fetch(url, { ...options, signal:controller.signal, headers: { 'X-FileShare':'1', ...(options.body ? { 'Content-Type':'application/json' } : {}), ...options.headers } });
    const data = await res.json(); if (!res.ok) { if (res.status === 401) showLogin(); throw Object.assign(new Error(data.error || '요청에 실패했습니다.'), {status:res.status}); } return data;
  } finally {clearTimeout(timer);}

}
function showLogin() { $('#login').hidden = false; $('#workspace').hidden = true; }
async function connected() { const info = await api('/api/info'); state.chunk = info.chunkSize; $('#storage').textContent = `남은 공간 ${size(info.freeBytes)}`; $('#login').hidden = true; $('#workspace').hidden = false; $('#settings').hidden = !info.canConfigure; if(info.canConfigure) { document.body.classList.add('desktop-mode'); $('#sharedRoot').value=info.sharedRoot; $('#serverPort').value=info.configuredPort; $('#autoStartLabel').hidden=!info.autoStartSupported; $('#autoStart').checked=info.autoStart; state.autoStartSupported=info.autoStartSupported; $('#dropzone').hidden=info.needsSetup; $('.library').hidden=info.needsSetup; $('#newPassword').required=info.needsSetup; $('#confirmPassword').required=info.needsSetup; $('#setupStatus').textContent=info.needsSetup?'아래 설정을 저장하면 휴대폰에서 접속할 수 있습니다.':'공유 중 · 폴더와 비밀번호를 언제든 변경할 수 있습니다.'; $('#phoneConnection').hidden=info.needsSetup; $('#phoneUrls').replaceChildren(); for(const url of info.phoneUrls||[]){const address=document.createElement('code');address.textContent=url;$('#phoneUrls').append(address);} } state.folderName=info.folderName; await refresh(); }
$('#loginForm').addEventListener('submit', async e => { e.preventDefault(); const button = e.submitter; button.disabled = true; try { await api('/api/login', { method:'POST', body: JSON.stringify({ password:$('#pin').value }) }); $('#pin').value = ''; await connected(); } catch (e) { notice(e.message); } finally { button.disabled = false; } });
$('#logout').onclick = async () => { if (state.running) { notice('진행 중인 전송을 먼저 일시정지하세요.'); return; } try { await api('/api/logout', { method:'POST' }); showLogin(); } catch (e) { notice(e.message); } };
$('#pickFiles').onclick = () => $('#files').click(); $('#pickPhotos').onclick = () => $('#photos').click();
// Retain each native input until its batch finishes; clearing it immediately can
// invalidate iOS temporary media references. Fresh inputs allow selecting the same file again.
function bindPicker(input) {
  input.onchange = () => {
    const files = Array.from(input.files);
    if (!files.length) return;
    const fresh = input.cloneNode(); fresh.value=''; input.removeAttribute('id'); input.after(fresh); bindPicker(fresh);
    enqueue(files, input);
  };
}
for (const selector of ['#files','#photos']) bindPicker($(selector));
$('#dropzone').ondragover = e => { e.preventDefault(); $('#dropzone').classList.add('dragging'); };
$('#dropzone').ondragleave = () => $('#dropzone').classList.remove('dragging');
$('#dropzone').ondrop = e => { e.preventDefault(); $('#dropzone').classList.remove('dragging'); enqueue([...e.dataTransfer.files]); };
$('#clearQueue').onclick = () => { state.queue = state.queue.filter(t => t.status !== 'done'); renderQueue(); };
$('#refresh').onclick = () => refresh().catch(e => notice(e.message)); $('#search').oninput = renderFiles;
function enqueue(files, input = null) {
  const batch = {input, remaining:files.length};
  for (const file of files) state.queue.push({ file, batch, target:state.path, status:'waiting', offset:0, text:'전송 대기', pause:false });
  renderQueue(); $('#queueSection').scrollIntoView({block:'start', behavior:'auto'});
  // Let the upload view paint before reading or hashing media.
  setTimeout(run, 0);
}
function renderQueue() {
  $('#queueSection').hidden = !state.queue.length; $('#queue').replaceChildren();
  for (const t of state.queue) {
    const row = document.createElement('div'); row.className = 'transfer';
    const head = document.createElement('div'); head.className = 'transfer-head'; const name = document.createElement('strong'); name.textContent = t.file.name; head.append(name);
    const button = document.createElement('button'); button.className = 'text-button';
    button.textContent = t.status === 'done' ? '완료 ✓' : ['paused','error'].includes(t.status) ? '이어 올리기' : '일시정지'; button.disabled = t.status === 'done';
    button.onclick = () => { if (['paused','error'].includes(t.status)) { t.pause = false; t.status = 'waiting'; t.text = '이어 올리기 대기'; run(); } else { t.pause = true; if (t.status === 'waiting') { t.status = 'paused'; t.text = '일시정지'; } if (state.active === t) t.xhr?.abort(); } renderQueue(); }; head.append(button);
    const progress = document.createElement('progress'); progress.max = t.file.size || 1; progress.value = t.status === 'done' ? progress.max : t.offset;
    const info = document.createElement('div'); info.className = 'transfer-status'; info.textContent = `${t.text} · ${size(t.offset)} / ${size(t.file.size)}`;
    row.append(head, progress, info); $('#queue').append(row); t.progress = progress; t.info = info;
  }
}
// SHA-256 works on ordinary LAN HTTP too (WebCrypto requires HTTPS).
function sha256(bytes) {
  const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const data = new Uint8Array(Math.ceil((bytes.length + 9) / 64) * 64); data.set(bytes); data[bytes.length] = 128; const view = new DataView(data.buffer); view.setUint32(data.length - 4, bytes.length * 8); const w = new Uint32Array(64); const r = (n,s) => (n >>> s) | (n << (32-s));
  for (let pos=0;pos<data.length;pos+=64) {
    for(let i=0;i<16;i++) w[i]=view.getUint32(pos+i*4);
    for(let i=16;i<64;i++) { const a=w[i-15],b=w[i-2]; w[i]=(r(a,7)^r(a,18)^(a>>>3))+w[i-16]+(r(b,17)^r(b,19)^(b>>>10))+w[i-7]; }
    let [a,b,c,d,e,f,g,j]=h;
    for(let i=0;i<64;i++) { const t=(j+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+K[i]+w[i])|0; const u=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))|0; j=g;g=f;f=e;e=(d+t)|0;d=c;c=b;b=a;a=(t+u)|0; }
    [a,b,c,d,e,f,g,j].forEach((v,i)=>h[i]=(h[i]+v)|0);
  }
  return h.map(n=>(n>>>0).toString(16).padStart(8,'0')).join('');
}
async function fingerprint(file) {
  const meta = new TextEncoder().encode(JSON.stringify([file.name,file.size,file.lastModified]));
  const starts = [0, Math.max(0,Math.floor(file.size/2)-32768), Math.max(0,file.size-65536)];
  const parts = await Promise.all(starts.map(start => file.slice(start,start+65536).arrayBuffer()));
  const bytes = new Uint8Array(meta.length+parts.reduce((sum,p)=>sum+p.byteLength,0)); bytes.set(meta); let at=meta.length; for(const p of parts){bytes.set(new Uint8Array(p),at);at+=p.byteLength;} return sha256(bytes);
}
async function chunk(t, start, end) {
  const bytes = await t.file.slice(start,end).arrayBuffer();
  if(t.pause) throw new Error('일시정지');
  return new Promise((resolve,reject) => {
    const xhr = new XMLHttpRequest(); t.xhr=xhr;
    let watchdog;
    const done = (error, data) => { clearTimeout(watchdog); t.xhr=null; error ? reject(error) : resolve(data); };
    const arm = () => { clearTimeout(watchdog); watchdog=setTimeout(()=>{xhr.abort();}, 90000); };
    xhr.open('PATCH', `/api/uploads/${t.id}`); xhr.setRequestHeader('X-FileShare','1'); xhr.setRequestHeader('Upload-Offset',String(start)); xhr.setRequestHeader('Content-Type','application/octet-stream'); xhr.timeout=30*60*1000;
    xhr.upload.onprogress = e => { arm(); const transferred=start+e.loaded; t.progress.value=transferred; t.info.textContent=`${Math.min(100,transferred/t.file.size*100).toFixed(1)}% · ${size(transferred)} / ${size(t.file.size)}`; };
    xhr.onload=()=>{ let data; try { data=JSON.parse(xhr.responseText); } catch { done(new Error('서버 응답을 확인할 수 없습니다.')); return; } if(xhr.status>=200&&xhr.status<300)done(null,data);else done(Object.assign(new Error(data.error||'전송 실패'),{status:xhr.status})); };
    xhr.onerror=()=>done(new Error('네트워크 연결이 끊겼습니다.'));
    xhr.ontimeout=()=>done(new Error('전송 응답 대기 시간이 초과되었습니다.'));
    xhr.onabort=()=>done(new Error(t.pause?'일시정지':'전송 응답이 없어 다시 연결합니다.'));
    arm(); xhr.send(bytes);
  });
}
async function run() {
  if(state.running)return;state.running=true;
  try {
    for (const t of state.queue) {
      if(t.status!=='waiting')continue; state.active=t;t.status='uploading';t.text='파일 확인 중';renderQueue();
      try {
        t.fingerprint ||= await fingerprint(t.file);
        const finished = await FileShareTransfer.upload(t, {
          chunkSize:state.chunk,
          init:()=>api('/api/uploads',{method:'POST',body:JSON.stringify({name:t.file.name,size:t.file.size,fingerprint:t.fingerprint,target:t.target})}),
          status:()=>api(`/api/uploads/${t.id}`),
          send:(start,end)=>chunk(t,start,end),
          complete:()=>api(`/api/uploads/${t.id}/complete`,{method:'POST'}),
          message:text=>{t.text=text;t.info.textContent=text;}
        });
        if(!finished){t.status='paused';t.text='일시정지';}
        else {t.status='done';t.text='전송 완료';t.file={name:t.file.name,size:t.file.size};if(t.batch&&--t.batch.remaining===0&&t.batch.input){t.batch.input.value='';t.batch.input.remove();t.batch.input=null;}}
      }catch(e){t.status=t.pause?'paused':'error';t.text=e.message;}finally{t.xhr=null;renderQueue();}
    }
    // Refresh once per batch, avoiding thumbnail requests competing with uploads.
    await refresh().catch(()=>{});
  }finally{state.running=false;state.active=null;}
}
async function refresh(){const data=await api('/api/entries?path='+encodeURIComponent(state.path));state.files=data.entries;renderFiles();renderBreadcrumbs();}
function renderFiles(){
  const list=$('#fileList');list.replaceChildren();$('#count').textContent=state.files.length;const query=$('#search').value.toLowerCase();const files=state.files.filter(f=>f.name.toLowerCase().includes(query));
  if(!files.length){const empty=document.createElement('div');empty.className='empty';empty.textContent=query?'검색 결과가 없습니다.':'비어 있는 폴더입니다. 파일을 올리거나 새 폴더를 만드세요.';list.append(empty);return;}
  for(const file of files){
    const row=document.createElement('div');row.className='file';const icon=document.createElement('span');icon.className='file-icon';icon.textContent=file.directory?'▰':/\.(mov|mp4|m4v)$/i.test(file.name)?'▷':/\.(jpg|jpeg|png|heic|gif|webp)$/i.test(file.name)?'▧':'▤';
    if(!file.directory&&/\.(jpg|jpeg|png)$/i.test(file.name)){const thumb=document.createElement('img');thumb.src='/api/thumbnail?path='+encodeURIComponent(file.path);thumb.alt='';thumb.loading='lazy';thumb.width=44;thumb.height=48;thumb.onerror=()=>thumb.remove();icon.append(thumb);}
    const info=document.createElement('div');info.className='file-info';const name=document.createElement(file.directory?'button':'div');name.className=file.directory?'folder-name':'filename';name.textContent=file.name;if(file.directory)name.onclick=()=>navigate(file.path);const meta=document.createElement('div');meta.className='file-meta';meta.textContent=(file.directory?'폴더':size(file.size))+' · '+new Date(file.modified).toLocaleString('ko-KR');info.append(name,meta);
    const actions=document.createElement('div');actions.className='file-actions';
    if(!file.directory){const link=document.createElement('a');link.className='action';link.href='/api/content?path='+encodeURIComponent(file.path);link.textContent='↓ 다운로드';link.setAttribute('download',file.name);actions.append(link);
      if(/\.(jpg|jpeg|png|heic|gif|webp|mov|mp4|m4v|mp3|m4a|wav|ogg)$/i.test(file.name)){const preview=document.createElement('a');preview.className='action';preview.href=link.href+'&preview=1';preview.target='_blank';preview.rel='noopener';preview.textContent='열기 ↗';actions.append(preview);}}
    const more=document.createElement('details');more.className='file-menu';const summary=document.createElement('summary');summary.textContent='작업 ⋯';more.append(summary);const menu=document.createElement('div');
    for(const [action,label] of [['copy','복사'],['move','이동'],['rename','이름 변경'],['delete','삭제']]){const button=document.createElement('button');button.className='text-button';button.textContent=label;button.onclick=async()=>{more.open=false;if(action==='copy'||action==='move'){state.clipboard={action,path:file.path,name:file.name};renderClipboard();notice('대상 폴더로 이동한 뒤 붙여넣기를 누르세요.');return;}if(action==='rename'){const name=await ask('이름 변경','새 이름을 입력하세요.',file.name);if(name&&name!==file.name)await operation({action,path:file.path,name});}else if(await ask('영구 삭제','“'+file.name+'”'+(file.directory?' 폴더와 모든 내용':' 파일')+'을 영구 삭제할까요? 휴지통으로 이동하지 않습니다.'))await operation({action,path:file.path});};menu.append(button);}more.append(menu);actions.append(more);row.append(icon,info,actions);list.append(row);
  }
}
window.addEventListener('beforeunload',e=>{if(state.running){e.preventDefault();e.returnValue='';}});
async function initialize(){const hash=new URLSearchParams(location.hash.slice(1));const key=hash.get('desktop');if(key){history.replaceState(null,'',location.pathname+location.search);try{await api('/api/desktop-session',{method:'POST',body:JSON.stringify({key})});}catch(e){notice(e.message);}}try{await connected();}catch{showLogin();}}
initialize();

async function navigate(relative){const previous=state.path;state.path=relative;$('#search').value='';try{await refresh();}catch(e){state.path=previous;notice(e.message);}}
function renderBreadcrumbs(){$('#folderZip').href='/api/zip?path='+encodeURIComponent(state.path);const nav=$('#breadcrumbs');nav.replaceChildren();const parts=state.path.split('/').filter(Boolean);for(let i=0;i<=parts.length;i++){const button=document.createElement('button');button.className='text-button';button.textContent=i===0?'⌂ '+(state.folderName||'공유 폴더'):parts[i-1];button.onclick=()=>navigate(parts.slice(0,i).join('/'));nav.append(button);if(i<parts.length)nav.append(document.createTextNode('/'));}}
function renderClipboard(){$('#paste').hidden=!state.clipboard;$('#cancelClipboard').hidden=!state.clipboard;$('#clipboardInfo').textContent=state.clipboard?(state.clipboard.action==='copy'?'복사: ':'이동: ')+state.clipboard.name:'';}
async function operation(body){try{await api('/api/operations',{method:'POST',body:JSON.stringify(body)});await refresh();notice('작업을 완료했습니다.');return true;}catch(e){notice(e.message);return false;}}
$('#newFolder').onclick=async()=>{const name=await ask('새 폴더','폴더 이름을 입력하세요.','');if(name)await operation({action:'mkdir',parent:state.path,name});};
$('#paste').onclick=async()=>{if(!state.clipboard)return;const button=$('#paste');button.disabled=true;notice('파일 작업 중입니다. 큰 파일은 시간이 걸릴 수 있습니다.');try{if(await operation({...state.clipboard,destination:state.path})){state.clipboard=null;renderClipboard();}}finally{button.disabled=false;}};
$('#cancelClipboard').onclick=()=>{state.clipboard=null;renderClipboard();};
$('#settingsForm').onsubmit=async e=>{e.preventDefault();if(state.running){notice('전송을 먼저 일시정지하세요.');return;}const password=$('#newPassword').value;if(password!==$('#confirmPassword').value){notice('새 비밀번호가 서로 다릅니다.');return;}const body={sharedRoot:$('#sharedRoot').value,port:Number($('#serverPort').value)};if(password)body.password=password;if(state.autoStartSupported)body.autoStart=$('#autoStart').checked;const button=e.submitter;button.disabled=true;try{await api('/api/settings',{method:'POST',body:JSON.stringify(body)});$('#newPassword').value='';$('#confirmPassword').value='';state.path='';state.clipboard=null;renderClipboard();await connected();notice('설정을 저장했습니다.');}catch(e){notice(e.message);}finally{button.disabled=false;}};

function ask(title,description,value){return new Promise(resolve=>{const dialog=$('#actionDialog');$('#dialogTitle').textContent=title;$('#dialogDescription').textContent=description;const input=$('#dialogInput');input.hidden=value===undefined;$('#dialogLabel').hidden=value===undefined;input.required=value!==undefined;input.value=value||'';dialog.returnValue='';dialog.addEventListener('close',()=>resolve(dialog.returnValue==='ok'?(value===undefined?true:input.value):null),{once:true});dialog.showModal();if(value!==undefined){input.focus();input.select();}});}

$('#chooseFolder').onclick=async()=>{const button=$('#chooseFolder');button.disabled=true;button.textContent='폴더 선택 창 열림…';try{const result=await api('/api/pick-folder',{method:'POST'});if(result.path)$('#sharedRoot').value=result.path;}catch(e){notice(e.message);}finally{button.disabled=false;button.textContent='폴더 선택…';}};
