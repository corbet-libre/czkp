// Codec vectors, not epoch authentication or proof acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import {recordBytes,recordEpochPublicInputs,recordLeafCommitment,RECORD_EPOCH_DOMAIN} from '../runtime/record.mjs';
const bytes=n=>Array(32).fill(n),scope={circuitDigest:bytes(4),verifyingKeyDigest:bytes(5)},key=Array(64).fill(6);
function record(){return {epoch:{purpose:'cblc.record-epoch.v3',community:bytes(1),policyEpoch:7,epoch:2,startsAt:172800,expiresAt:259200,
  root:bytes(2),issuerKey:bytes(19),proofScope:structuredClone(scope),leafCount:5000,downloadDigest:bytes(3),downloadBytes:4096},owner:bytes(9),
  presentationKey:bytes(10),blindedLeaf:bytes(1),certificate:Array(64).fill(1),shares:null};}
test('injective public leaf field encoding; real cross-runtime hashes run in proof CI',async()=>{
  const leaf={owner:bytes(3),version:4,state:[...Array(31).fill(0),5],requiredInbox:bytes(6),blinding:bytes(7)};
  let encoded;await recordLeafCommitment(bytes(1),2,leaf,async fields=>{encoded=fields;return 1n;});
  const limb=n=>BigInt('0x'+n.toString(16).padStart(2,'0').repeat(16));
  assert.deepEqual(encoded,[RECORD_EPOCH_DOMAIN,1n,limb(1),limb(1),2n,limb(3),limb(3),4n,5n,limb(6),limb(6),limb(7),limb(7)]);
  for(const change of [v=>v.version=Number.MAX_SAFE_INTEGER+1,v=>v.state=bytes(255),v=>v.blinding=bytes(0),v=>v.extra=1]){
    const bad=structuredClone(leaf);change(bad);await assert.rejects(recordLeafCommitment(bytes(1),2,bad));
  }
});
test('public projection binds the issuer certificate but hides the frontier opening',()=>{
  const good=record(),input=recordEpochPublicInputs(good,scope,key);
  for(const name of ['version','state','inbox','required_inbox','path','index','blinding','certificate','descended','challenge','purpose','expires_at'])assert(!Object.hasOwn(input,name));
  assert.deepEqual(input.scope,scope.circuitDigest);assert.deepEqual(input.verification_scope,scope.verifyingKeyDigest);
  assert.equal(input.present,false);good.shares=[3000,3000,4000];assert.equal(recordEpochPublicInputs(good,scope,key).present,true);
  for(const change of [v=>v.state=bytes(1),v=>v.epoch.epoch=3,v=>v.epoch.proofScope.circuitDigest[0]^=1,
    v=>v.epoch.leafCount=2**20+1,v=>v.epoch.root=bytes(0),v=>v.presentationKey=bytes(0),
    v=>v.shares=[1,2,3],v=>v.epoch.downloadBytes=64*1024*1024+1]){
    const bad=record();change(bad);assert.throws(()=>recordEpochPublicInputs(bad,scope,key));
  }
  for(const bad of [null,undefined,[256],Array(32).fill(-1),Array(33).fill(1)])assert.throws(()=>recordBytes(bad));
});
