import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyPublicCertificates,verifyPublicRecordCertificate} from '../runtime/public-checks.mjs';
import {Barretenberg,BackendType} from '@aztec/bb.js';
import {compactMessage} from '../runtime/compact.mjs';
import {fieldBytes,fieldValue} from '../runtime/primitives.mjs';
import {be,cat,canonicalSignature,hex} from '../runtime/encoding.mjs';
let api;test.before(async()=>{api=await Barretenberg.new({backend:BackendType.Wasm,threads:1,skipSrsInit:true});});
test.after(async()=>{if(api)await api.destroy();});
const hash=async fields=>fieldValue((await api.poseidon2Hash({inputs:fields.map(fieldBytes)})).hash);
const byteType=n=>({kind:'array',length:n,type:{kind:'integer',sign:'unsigned',width:8}});
const names=['issuer_key','scope','community','owner','state','version','accepted_at','certificate'];
const sizes=[64,32,32,32,32,1,1,64];
const circuit={abi:{parameters:names.map((name,i)=>({name,visibility:'public',type:sizes[i]===1?{kind:'integer',sign:'unsigned',width:64}:byteType(sizes[i])}))}};
const flatten=fields=>names.flatMap(name=>Array.from(fields[name],BigInt));
async function fixture(){
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const f={issuer_key:new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey)).slice(1),
    scope:new Uint8Array(32).fill(1),community:new Uint8Array(32).fill(2),owner:new Uint8Array(32).fill(3),
    state:new Uint8Array(32).fill(4),version:[2],accepted_at:[17]};
  const message=cat(new TextEncoder().encode('cssr.accepted-state.v1\0'),f.community,f.owner,f.state,f.scope,be(2,8),be(17,8));
  f.certificate=canonicalSignature(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,await compactMessage(message,hash)));
  return f;
}
test('public issuer certificate binds every original field and rejects substitutions',async()=>{
  const f=await fixture();await verifyPublicCertificates(circuit,flatten(f),hash);
  for(const name of names){const bad=structuredClone(f);bad[name][0]^=1;await assert.rejects(verifyPublicCertificates(circuit,flatten(bad),hash),name);}
  for(const half of [0,32]){const bad=structuredClone(f);bad.certificate.fill(0,half,half+32);await assert.rejects(verifyPublicCertificates(circuit,flatten(bad),hash));}
  const bad=structuredClone(f),order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  bad.certificate.set(be(order-BigInt('0x'+hex(bad.certificate.slice(32))),32),32);
  await assert.rejects(verifyPublicCertificates(circuit,flatten(bad),hash));
  await assert.rejects(verifyPublicCertificates(circuit,flatten(f).slice(1),hash));
  await assert.rejects(verifyPublicCertificates(circuit,[...flatten(f),0n],hash));
});
test('hidden certificate is still the circuit verifier responsibility',async()=>{
  const privateCircuit=structuredClone(circuit);privateCircuit.abi.parameters.at(-1).visibility='private';
  await verifyPublicCertificates(privateCircuit,[]);
});

test('R2 native issuer check binds community, epoch, leaf and canonical Ed25519 signature',async()=>{
  const names=['record_issuer_key','community','epoch','blinded_leaf','record_certificate'];
  const lengths=[32,32,1,32,64];
  const relation={abi:{parameters:names.map((name,i)=>({name,visibility:'public',type:lengths[i]===1
    ?{kind:'integer',sign:'unsigned',width:64}:byteType(lengths[i])}))}};
  const flatten=f=>names.flatMap(name=>Array.from(f[name],BigInt));
  const keys=await crypto.subtle.generateKey('Ed25519',false,['sign','verify']);
  const f={record_issuer_key:new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey)),
    community:new Uint8Array(32).fill(1),epoch:[2],blinded_leaf:new Uint8Array(32).fill(2)};
  const transcript=cat(new TextEncoder().encode('cblc.record-leaf.v1\0'),f.community,be(2,8),f.blinded_leaf);
  f.record_certificate=new Uint8Array(await crypto.subtle.sign('Ed25519',keys.privateKey,transcript));
  await verifyPublicRecordCertificate(relation,flatten(f));
  for(const name of names){const bad=structuredClone(f);bad[name][0]^=1;
    await assert.rejects(verifyPublicRecordCertificate(relation,flatten(bad)),name);}
  for(const change of [v=>v.record_certificate.fill(0),v=>v.record_certificate.fill(255,32),
    v=>v.record_issuer_key.fill(0),v=>v.record_certificate.fill(0,0,32)]){
    const bad=structuredClone(f);change(bad);await assert.rejects(verifyPublicRecordCertificate(relation,flatten(bad)));
  }
  await assert.rejects(verifyPublicRecordCertificate(relation,flatten(f).slice(1)));
  await assert.rejects(verifyPublicRecordCertificate(relation,[...flatten(f),0n]));
});
