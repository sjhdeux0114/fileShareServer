// Upload engine v2: one request at a time, one authoritative acknowledgement.
// No XMLHttpRequest upload events or periodic status requests on the success path.
globalThis.FileShareTransfer = (() => {
  const CHUNK = 1024 * 1024, WINDOW = 8 * 1024 * 1024;
  const error = (message, status = 0, retry = true) => Object.assign(new Error(message), {status, retry});
  const retryable = e => e.retry !== false && (!e.status || [408,409,423,429,500,502,503,504].includes(e.status));
  const cancelled = () => error('일시정지', 0, false);

  function delay(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(cancelled()); return; }
      const abort = () => { clearTimeout(timer); reject(cancelled()); };
      const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms);
      signal.addEventListener('abort', abort, {once:true});
    });
  }

  function readBlob(blob, signal) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(cancelled()); return; }
      const reader = new FileReader();
      let finished = false;
      const finish = (err, value) => {
        if (finished) return;
        finished = true; clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        reader.onload = reader.onerror = reader.onabort = null;
        err ? reject(err) : resolve(value);
      };
      const abort = () => { finish(cancelled()); reader.abort(); };
      const timer = setTimeout(() => {
        finish(error('기기에서 파일 준비가 지연됩니다. 원본을 확인한 뒤 다시 선택하세요.', 0, false));
        reader.abort();
      }, 60000);
      signal.addEventListener('abort', abort, {once:true});
      reader.onload = () => {
        if (reader.result?.byteLength !== blob.size) finish(error('파일을 끝까지 읽지 못했습니다.', 0, false));
        else finish(null, new Uint8Array(reader.result));
      };
      reader.onerror = () => finish(error('기기에서 파일을 읽지 못했습니다. 다시 선택하세요.', 0, false));
      reader.onabort = () => finish(cancelled());
      try { reader.readAsArrayBuffer(blob); } catch (e) { finish(error(e.message, 0, false)); }
    });
  }

  function createSource(file, signal) {
    let windowStart = 0, bytes = null;
    const cached = (start, end) => bytes && start >= windowStart && end <= windowStart + bytes.length;
    const view = (start, end) => bytes.subarray(start - windowStart, end - windowStart);
    return {
      async read(start, end) {
        if (signal.aborted) throw cancelled();
        if (start < 0 || end < start || end > file.size || end-start > WINDOW) throw error('잘못된 파일 읽기 범위입니다.', 422, false);
        if (!cached(start,end)) {
          bytes = null;
          const buffer = await readBlob(file.slice(start, Math.min(file.size, start + WINDOW)), signal);
          windowStart = start; bytes = buffer;
        }
        return view(start,end);
      },
      async sample(start, end) {
        // Materialize small photos once for both fingerprinting and transmission.
        if (file.size <= WINDOW) return this.read(start,end);
        if (cached(start,end)) return view(start,end);
        return readBlob(file.slice(start,end), signal);
      },
      release() { bytes = null; }
    };
  }

  async function request(fetcher, url, method, body, signal, timeout, headers = {}) {
    if (signal.aborted) throw cancelled();
    const controller = new AbortController();
    const abort = () => controller.abort();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeout);
    signal.addEventListener('abort', abort, {once:true});
    try {
      const response = await fetcher(url, {method, body, signal:controller.signal, headers:{'X-FileShare':'1', ...headers}});
      let data;
      try { data = await response.json(); }
      catch { throw error('서버 응답을 읽지 못했습니다.', response.ok ? 0 : response.status); }
      if (!response.ok) throw error(data.error || '전송 요청에 실패했습니다.', response.status);
      return data;
    } catch (e) {
      if (signal.aborted) throw cancelled();
      if (timedOut) throw error('서버 응답 시간이 초과되어 저장 위치를 확인합니다.');
      throw e;
    } finally {
      clearTimeout(timer); signal.removeEventListener('abort', abort);
    }
  }

  async function upload(task, options) {
    const controller = new AbortController(), signal = controller.signal;
    const source = createSource(task.file, signal);
    const fetcher = options.fetch || ((...args) => fetch(...args));
    const state = (phase, detail = {}) => options.onState?.(phase, detail);
    const started = Date.now();
    const cancel = () => { task.pause = true; controller.abort(); };
    task.cancelTransfer = cancel;
    task.metrics = {prepareMs:0, uploadMs:0};
    let failures = 0, reconcile = Boolean(task.id), transferStarted;
    const call = (url, method = 'GET', body, timeout = 30000, headers) => request(fetcher,url,method,body,signal,timeout,headers);
    const json = (url, body, timeout) => call(url,'POST',JSON.stringify(body),timeout,{'Content-Type':'application/json'});
    const position = data => {
      if (!Number.isSafeInteger(data.offset) || data.offset < 0 || data.offset > task.file.size) throw error('서버 전송 위치가 올바르지 않습니다.',422,false);
      if (data.offset > task.offset) failures = 0;
      task.offset = data.offset; options.onProgress?.(task.offset);
    };
    try {
      if (task.pause) return false;
      state('preparing');
      task.fingerprint ||= await options.fingerprint(source);
      task.metrics.prepareMs = Date.now() - started;
      transferStarted = Date.now();
      while (!signal.aborted) {
        try {
          if (!task.id) {
            state('starting');
            const u = await json('/api/uploads',{name:task.file.name,size:task.file.size,fingerprint:task.fingerprint,target:task.target || ''});
            if (!/^[a-f0-9]{32}$/.test(u.id)) throw error('전송 식별자가 올바르지 않습니다.',422,false);
            task.id = u.id; position(u);
          } else if (reconcile) {
            state('checking');
            const u = await call(`/api/uploads/${task.id}`); position(u);
            if (u.complete) { state('done'); return true; }
          }
          reconcile = false;
          if (task.offset === task.file.size) {
            state('finalizing');
            const result = await json(`/api/uploads/${task.id}/complete`,{},120000);
            if (!result.complete) throw error('서버의 최종 저장을 확인하지 못했습니다.');
            state('done'); return true;
          }
          const start = task.offset;
          const end = Math.min(task.file.size, start + Math.min(options.chunkSize || CHUNK, CHUNK));
          state('reading');
          const bytes = await source.read(start,end);
          state('sending');
          const result = await call(`/api/uploads/${task.id}/chunks`,'POST',bytes,120000,
            {'Content-Type':'application/octet-stream','Upload-Offset':String(start)});
          if (result.offset !== end) throw error('전송 위치가 달라 저장 위치를 다시 확인합니다.');
          position(result); failures = 0;
        } catch (e) {
          if (signal.aborted) return false;
          if (!retryable(e) || ++failures > 6) throw e;
          reconcile = Boolean(task.id);
          state('retrying',{attempt:failures,message:e.message});
          await (options.sleep || delay)(Math.min(5000,300 * 2 ** (failures-1)),signal);
        }
      }
      return false;
    } catch (e) {
      if (signal.aborted) return false;
      throw e;
    } finally {
      task.metrics.uploadMs = transferStarted ? Date.now()-transferStarted : 0;
      source.release();
      if (task.cancelTransfer === cancel) task.cancelTransfer = null;
    }
  }
  return {upload,createSource,retryable,chunkSize:CHUNK};
})();
