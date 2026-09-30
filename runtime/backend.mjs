// A fresh upstream backend per caller. Artifact authentication belongs to the
// embedding; it must pass the exact byte snapshots that it verified.
export async function openBackend(artifacts, browserFactory) {
  const { Barretenberg, BackendType } = await import('@aztec/bb.js');
  const browser = typeof globalThis.window !== 'undefined' || typeof globalThis.WorkerGlobalScope !== 'undefined';
  const options = { backend: browser ? BackendType.WasmWorker : BackendType.Wasm,
    threads: 1, skipSrsInit: true, memory: { initial: 2048, maximum: artifacts.limits.memoryPages } };
  const api = browser ? await browserFactory(options) : await Barretenberg.new(options);
  try {
    await api.srsInitSrs({pointsBuf: artifacts.setup['g1.dat'], numPoints: artifacts.manifest.numPoints, g2Point: artifacts.setup['g2.dat']});
    return api;
  } catch(error) { await api.destroy(); throw error; }
}
