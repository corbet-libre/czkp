// Authenticated per-circuit compressed SRS prefixes. BB 5 checks complete 4 MiB
// chunks, so dyadic+1 is rounded upwards without bypassing upstream hash pins.
import {hex,sha} from './encoding.mjs';
export const SRS_CHUNK_POINTS=131072;
export function setupPoints(dyadic) {
  if(!Number.isSafeInteger(dyadic)||dyadic<1||dyadic>2**21||!Number.isInteger(Math.log2(dyadic)))throw new Error('Circuit dyadic bound');
  return Math.ceil((dyadic+1)/SRS_CHUNK_POINTS)*SRS_CHUNK_POINTS;
}
export async function loadCircuitSetup(manifest,kind,read,verificationOnly=false) {
  // Archived baseline artifacts remain usable for paired benchmarks only.
  if(manifest.circuitSetup===undefined){
    if(!Number.isSafeInteger(manifest.numPoints)||manifest.numPoints<1||manifest.numPoints>4*1024*1024||manifest.setup?.length!==2)throw new Error('Legacy setup description');
    const setup={};
    for(const item of manifest.setup){
      if(!['g1.dat','g2.dat'].includes(item.name)||Object.hasOwn(setup,item.name)||item.bytes!==(item.name==='g1.dat'?manifest.numPoints*32:128))throw new Error('Legacy setup completeness');
      const bytes=await read(item.name,item.bytes);
      if(!(bytes instanceof Uint8Array)||bytes.length!==item.bytes||hex(await sha(bytes))!==item.sha256)throw new Error('Setup authentication');
      setup[item.name]=bytes;
    }
    return {setup,numPoints:manifest.numPoints};
  }
  const spec=manifest.circuitSetup?.[kind];
  if(!spec||spec.numPoints!==setupPoints(spec.numGatesDyadic)
    ||!Number.isSafeInteger(spec.numGates)||spec.numGates<1||spec.numGates>spec.numGatesDyadic)throw new Error('Circuit setup description');
  const points=verificationOnly?SRS_CHUNK_POINTS:spec.numPoints;
  const name=`g1-${points}.dat`,g1=manifest.setupPrefixes?.[name];
  const g2=manifest.setup?.find(item=>item.name==='g2.dat');
  if(!g1||g1.name!==name||g1.bytes!==points*32||g2?.bytes!==128)throw new Error('Setup prefix completeness');
  const setup={};
  for(const [key,item] of [['g1.dat',g1],['g2.dat',g2]]){
    if(!/^[0-9a-f]{64}$/.test(item.sha256))throw new Error('Setup digest');
    const bytes=await read(item.name,item.bytes);
    if(!(bytes instanceof Uint8Array)||bytes.length!==item.bytes||hex(await sha(bytes))!==item.sha256)throw new Error('Setup authentication');
    setup[key]=bytes;
  }
  return {setup,numPoints:points};
}
