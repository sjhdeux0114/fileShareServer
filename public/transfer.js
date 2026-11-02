// Small, memory-backed requests avoid repeatedly streaming a disk-backed iOS File.
// Always reconcile a failed request with the server before retrying its bytes.
globalThis.FileShareTransfer = (() => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  function retryable(e) {
    return !e.status || [408, 409, 423, 429, 500, 502, 503, 504].includes(e.status);
  }
  async function upload(task, io) {
    let failures = 0;
    let reconcile = Boolean(task.id);
    const wait = io.sleep || sleep;
    while (!task.pause) {
      try {
        if (!task.id) {
          const u = await io.init(); task.id = u.id; task.offset = u.offset;
        } else if (reconcile) {
          const u = await io.status();
          if (u.complete) return true;
          if (!Number.isSafeInteger(u.offset) || u.offset < 0 || u.offset > task.file.size) throw Object.assign(new Error('서버 전송 위치가 올바르지 않습니다.'), {status:422});
          if (u.offset > task.offset) failures = 0;
          task.offset = u.offset;
        }
        reconcile = false;
        if (task.pause) break;
        if (task.offset === task.file.size) {
          io.message('PC에 최종 저장 중…');
          await io.complete(); return true;
        }
        const start = task.offset;
        const end = Math.min(task.file.size, start + Math.min(io.chunkSize, 2 * 1024 * 1024));
        const result = await io.send(start, end);
        if (result.offset !== end) throw new Error('전송 위치를 다시 확인합니다.');
        task.offset = result.offset; failures = 0;
      } catch (e) {
        if (task.pause) break;
        if (!retryable(e) || ++failures > 12) throw e;
        reconcile = Boolean(task.id);
        io.message(`연결 복구 중 · 자동 재시도 ${failures}/12`);
        // Check pause often even during a longer backoff.
        let remaining = Math.min(10000, 500 * 2 ** (failures - 1));
        while (remaining > 0 && !task.pause) { const ms = Math.min(250, remaining); await wait(ms); remaining -= ms; }
      }
    }
    return false;
  }
  return {upload, retryable};
})();
