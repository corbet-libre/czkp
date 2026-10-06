// Bounded generic public-proof worker. No private witness enters this process.
import {readFile,stat,realpath} from 'node:fs/promises';
import {resolve,isAbsolute} from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {publicInputs} from './abi.mjs';
import {createVerifier} from './verify.mjs';
import {unhex} from './encoding.mjs';
import {loadCircuitSetup} from './setup.mjs';
import {updateCircuit} from './update.mjs';
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===k.length&&k.every(x=>Object.hasOwn(v,x));
const sha=b=>createHash('sha256').update(b).digest('hex');
const equal=(a,b)=>Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&a.every((v,i)=>v===b[i]);
async function bounded(path,max){if((await stat(path)).size>max)throw new Error('Artifact limit');const bytes=await readFile(path);if(bytes.length>max)throw new Error('Artifact limit');return bytes;}
export async function verify(record,path){
  if(!isAbsolute(path))throw new Error('Trusted absolute configuration required');
  const config=JSON.parse(await bounded(path,65536));
  if(!isAbsolute(config.directory))throw new Error('Trusted artifact directory required');
  const manifestBytes=await bounded(resolve(config.directory,'manifest.json'),65536);
  if(sha(manifestBytes)!==config.manifestSha256)throw new Error('Manifest authentication');
  const manifest=JSON.parse(manifestBytes);
  if(manifest.version!==1||manifest.compiler!=='1.0.0-beta.26'||manifest.backend!=='5.0.0'||manifest.verifierTarget!=='noir-recursive'
    ||!Number.isSafeInteger(manifest.numPoints)||manifest.numPoints<=0||manifest.numPoints>4*1024*1024
    ||!Array.isArray(manifest.setup)||manifest.setup.length!==2)throw new Error('Unsupported proof artifacts');
  const circuitsBytes=await bounded(resolve(config.directory,'circuits.json'),64*1024*1024),keysBytes=await bounded(resolve(config.directory,'keys.json'),1024*1024);
  if(sha(circuitsBytes)!==manifest.circuitSha256||sha(keysBytes)!==manifest.vkSha256)throw new Error('Suite authentication');
  const scope={circuitDigest:Array.from(unhex(manifest.circuitSha256)),verifyingKeyDigest:Array.from(unhex(manifest.vkSha256))};
  if(!exact(record,['statement','proof','proofScope'])||!exact(record.proofScope,['circuitDigest','verifyingKeyDigest'])
    ||!equal(record.proofScope.circuitDigest,scope.circuitDigest)||!equal(record.proofScope.verifyingKeyDigest,scope.verifyingKeyDigest)
    ||!exact(record.statement,['circuit','input']))throw new Error('Public proof scope');
  const circuits=JSON.parse(circuitsBytes),keys=JSON.parse(keysBytes),kind=record.statement.circuit;
  if(typeof kind!=='string'||!Object.hasOwn(circuits,kind)||!Object.hasOwn(keys,kind))throw new Error('Unknown suite circuit');
  if(kind.startsWith('update_')&&kind!==updateCircuit(record.statement.input))throw new Error('Wrong update verification key');
  if(kind==='update'&&manifest.circuitSetup?.update_genesis)throw new Error('Monolithic update is benchmark-only');
  const loadSetup=verificationOnly=>loadCircuitSetup(manifest,kind,(name,max)=>bounded(resolve(config.directory,'setup',name),max),verificationOnly);
  const circuit=circuits[kind];
  if(!exact(record.statement.input,circuit.abi.parameters.filter(p=>p.visibility==='public').map(p=>p.name)))throw new Error('Exact public ABI required');
  const verifier=await createVerifier({artifacts:{manifest,circuit,verificationKey:unhex(keys[kind]),loadSetup,limits:{memoryPages:65536,maxProofBytes:1024*1024}},
    publicInputs:input=>publicInputs(circuit,input)});
  try{return await verifier.verify({...record,statement:record.statement.input});}finally{await verifier.destroy();}
}
// Node resolves an ESM entry's module URL through package symlinks. Compare the
// same canonical file identity so direct execution through an npm alias cannot
// silently skip verification and exit successfully without a verdict.
const entry=process.argv[1]?await realpath(resolve(process.argv[1])).catch(()=>null):null;
if(entry&&entry===await realpath(fileURLToPath(import.meta.url))){
  console.log=()=>{};
  try{
    if(process.argv.length!==3)throw new Error('Trusted configuration required');
    const parts=[];let size=0;for await(const part of process.stdin){size+=part.length;if(size>3*1024*1024)throw new Error('Public input limit');parts.push(part);}
    const result=await verify(JSON.parse(Buffer.concat(parts)),process.argv[2]);process.stdout.write(JSON.stringify(result)+'\n');
  }catch{process.exitCode=1;}
}
