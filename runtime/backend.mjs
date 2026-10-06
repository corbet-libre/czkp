// A fresh upstream backend per caller. Artifact authentication belongs to the
// embedding; it must pass the exact byte snapshots that it verified.
export function proverThreads(requested,{background=false,
  browser=typeof globalThis.window!=='undefined'||typeof globalThis.WorkerGlobalScope!=='undefined',
  hardwareConcurrency=globalThis.navigator?.hardwareConcurrency??1,
  isolated=globalThis.crossOriginIsolated===true&&typeof globalThis.SharedArrayBuffer==='function'}={}) {
  if(requested!==undefined&&(!Number.isSafeInteger(requested)||requested<1))throw new Error('Prover thread count');
  const cores=Number.isSafeInteger(hardwareConcurrency)&&hardwareConcurrency>0?hardwareConcurrency:1;
  if(!browser)return requested??cores;
  if(!isolated)return 1;
  return Math.min(requested??(background?Math.max(1,Math.min(cores-1,4)):Math.min(cores,8)),cores);
}
export async function openBackend(artifacts, browserFactory, backendType, verificationOnly=false, threads, background=false) {
  const { Barretenberg, BackendType } = await import('@aztec/bb.js');
  const browser = typeof globalThis.window !== 'undefined' || typeof globalThis.WorkerGlobalScope !== 'undefined';
  if(backendType!==undefined&&!['Wasm','NativeUnixSocket'].includes(backendType))throw new Error('Unsupported backend');
  if(browser&&backendType!==undefined&&backendType!=='Wasm')throw new Error('Native backend is unavailable in browsers');
  const hardwareConcurrency=browser?globalThis.navigator?.hardwareConcurrency:(await import('node:os')).availableParallelism();
  const options = { backend: browser ? BackendType.WasmWorker : backendType??BackendType.Wasm,
    threads: verificationOnly?1:proverThreads(threads,{browser,hardwareConcurrency,background}), skipSrsInit: true, memory: { initial: 2048, maximum: artifacts.limits.memoryPages } };
  const api = browser ? await browserFactory(options) : await Barretenberg.new(options);
  try {
    // UltraHonk verification needs the G1 identity and the pinned G2 point, not
    // the prover's entire powers-of-tau table. Keep one complete compressed
    // chunk so bb.js 5's own 4 MiB hash-authentication gate still runs.
    // Upstream: bbapi_srs.cpp and srs/factories/mem_bn254_crs_factory.cpp (v5.0.0).
    const loaded=artifacts.loadSetup?await artifacts.loadSetup(verificationOnly):{setup:artifacts.setup,numPoints:artifacts.numPoints??artifacts.manifest.numPoints};
    const numPoints=verificationOnly?Math.min(131072,loaded.numPoints):loaded.numPoints;
    await api.srsInitSrs({pointsBuf: loaded.setup['g1.dat'].subarray(0,numPoints*32), numPoints, g2Point: loaded.setup['g2.dat']});
    return api;
  } catch(error) { await api.destroy(); throw error; }
}
