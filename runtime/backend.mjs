// A fresh upstream backend per caller. Artifact authentication belongs to the
// embedding; it must pass the exact byte snapshots that it verified.
export function proverThreads(requested) {
  if(requested!==undefined&&(!Number.isInteger(requested)||requested<1||requested>2))throw new Error('Prover thread bound');
  const browser=typeof globalThis.window!=='undefined'||typeof globalThis.WorkerGlobalScope!=='undefined';
  if(!browser)return requested??1;
  if(globalThis.crossOriginIsolated!==true||typeof globalThis.SharedArrayBuffer!=='function')return 1;
  return Math.min(requested??2,Math.max(1,globalThis.navigator?.hardwareConcurrency??1));
}
export async function openBackend(artifacts, browserFactory, backendType, verificationOnly=false, threads) {
  const { Barretenberg, BackendType } = await import('@aztec/bb.js');
  const browser = typeof globalThis.window !== 'undefined' || typeof globalThis.WorkerGlobalScope !== 'undefined';
  if(backendType!==undefined&&!['Wasm','NativeUnixSocket'].includes(backendType))throw new Error('Unsupported backend');
  if(browser&&backendType!==undefined&&backendType!=='Wasm')throw new Error('Native backend is unavailable in browsers');
  const options = { backend: browser ? BackendType.WasmWorker : backendType??BackendType.Wasm,
    threads: verificationOnly?1:proverThreads(threads), skipSrsInit: true, memory: { initial: 2048, maximum: artifacts.limits.memoryPages } };
  const api = browser ? await browserFactory(options) : await Barretenberg.new(options);
  try {
    // UltraHonk verification needs the G1 identity and the pinned G2 point, not
    // the prover's entire powers-of-tau table. Keep one complete compressed
    // chunk so bb.js 5's own 4 MiB hash-authentication gate still runs.
    // Upstream: bbapi_srs.cpp and srs/factories/mem_bn254_crs_factory.cpp (v5.0.0).
    const numPoints=verificationOnly?Math.min(131072,artifacts.manifest.numPoints):artifacts.manifest.numPoints;
    await api.srsInitSrs({pointsBuf: artifacts.setup['g1.dat'].subarray(0,numPoints*32), numPoints, g2Point: artifacts.setup['g2.dat']});
    return api;
  } catch(error) { await api.destroy(); throw error; }
}
