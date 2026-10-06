// Repackage genuine maintained account proofs as a generic suite; no accepting worker.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir,copyFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {verify} from '../runtime/node-verifier.mjs';
const source=resolve(process.env.CVFY_FIXTURE_SOURCE??'fixture-source');
const original=join(source,'.proof-test'),directory=join(source,'.neutral-suite');
await mkdir(join(directory,'setup'),{recursive:true});
const {validateStatement}=await import(pathToFileURL(join(source,'runtime/accounting/statement.mjs')));
const sha=b=>createHash('sha256').update(b).digest('hex');
const circuit=JSON.parse(await readFile(join(original,'circuit.json'))),vk=await readFile(join(original,'vk.bin'));
const manifest=JSON.parse(await readFile(join(original,'manifest.json')));
const circuits=Buffer.from(JSON.stringify({account:circuit})),keys=Buffer.from(JSON.stringify({account:vk.toString('hex')}));
manifest.circuitSha256=sha(circuits);manifest.vkSha256=sha(keys);
for(const name of ['g1.dat','g2.dat'])await copyFile(join(original,'setup',name),join(directory,'setup',name));
const manifestBytes=Buffer.from(JSON.stringify(manifest));
await writeFile(join(directory,'circuits.json'),circuits);await writeFile(join(directory,'keys.json'),keys);await writeFile(join(directory,'manifest.json'),manifestBytes);
const config=join(directory,'config.json');await writeFile(config,JSON.stringify({directory,manifestSha256:sha(manifestBytes)}));
const scope={circuitDigest:Array.from(Buffer.from(manifest.circuitSha256,'hex')),verifyingKeyDigest:Array.from(Buffer.from(manifest.vkSha256,'hex'))};
for(const fixture of JSON.parse(await readFile(join(original,'records.json')))){
  const flat=await validateStatement(fixture.statement);let at=0;
  function shape(t){
    if(t.kind==='array')return Array.from({length:t.length},()=>shape(t.type));
    if(t.kind==='struct')return Object.fromEntries(t.fields.map(f=>[f.name,shape(f.type)]));
    const v=flat[at++];return t.kind==='boolean'?v!==0n:v.toString();
  }
  const input=Object.fromEntries(circuit.abi.parameters.filter(p=>p.visibility==='public').map(p=>[p.name,shape(p.type)]));
  assert.equal(at,flat.length);
  const record={statement:{circuit:'account',input},proof:fixture.proof,proofScope:scope};
  assert.equal((await verify(record,config)).verified,true);
  const bad=structuredClone(record);bad.statement.input.community[0]=(Number(bad.statement.input.community[0])^1).toString();
  await assert.rejects(verify(bad,config));
  const corrupt=structuredClone(record);corrupt.proof=(record.proof.startsWith('00')?'01':'00')+record.proof.slice(2);
  await assert.rejects(verify(corrupt,config));
  const wrong=structuredClone(record);wrong.proofScope.verifyingKeyDigest[0]^=1;
  await assert.rejects(verify(wrong,config));
}
console.log('Generic suite verified real account proofs and refused tampering');
