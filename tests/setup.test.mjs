import test from 'node:test';
import assert from 'node:assert/strict';
import {setupPoints,loadCircuitSetup,SRS_CHUNK_POINTS} from '../runtime/setup.mjs';
import {hex,sha} from '../runtime/encoding.mjs';
test('dyadic+1 uses complete upstream authenticated chunks',()=>{
  assert.equal(setupPoints(65536),131072);assert.equal(setupPoints(131072),262144);
  assert.equal(setupPoints(524288),655360);
  for(const value of [0,-1,65537,2**22,NaN])assert.throws(()=>setupPoints(value));
});
test('only selected circuit prefix is read; digest/size/descriptor mutations refuse',async()=>{
  const data=new Uint8Array(SRS_CHUNK_POINTS*32),g2=new Uint8Array(128),name=`g1-${SRS_CHUNK_POINTS}.dat`;
  const manifest={circuitSetup:{wave:{numGates:123,numGatesDyadic:65536,numPoints:SRS_CHUNK_POINTS}},
    setupPrefixes:{[name]:{name,bytes:data.length,sha256:hex(await sha(data))}},setup:[{name:'g2.dat',bytes:128,sha256:hex(await sha(g2))}]};
  const reads=[];const read=async file=>{reads.push(file);return file===name?data:g2;};
  assert.equal((await loadCircuitSetup(manifest,'wave',read)).numPoints,SRS_CHUNK_POINTS);
  assert.deepEqual(reads,[name,'g2.dat']);
  await assert.rejects(loadCircuitSetup(manifest,'outcome',read));
  for(const mutate of [m=>m.circuitSetup.wave.numPoints++,m=>m.circuitSetup.wave.numGatesDyadic++,m=>m.setupPrefixes[name].bytes--,
    m=>m.setupPrefixes[name].sha256='0'.repeat(64),m=>m.setup[0].sha256='0'.repeat(64),m=>m.setupPrefixes[name].name='../g1.dat']){
    const bad=structuredClone(manifest);mutate(bad);await assert.rejects(loadCircuitSetup(bad,'wave',read));
  }
  await assert.rejects(loadCircuitSetup(manifest,'wave',async()=>data.subarray(1)));
});
