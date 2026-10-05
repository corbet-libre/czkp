// Public certificate verification complements the authenticated circuit relation.
// The signed bytes and key are reconstructed from the exact public ABI inputs;
// a caller's separate statement object cannot substitute different values.
import {be,cat,hex} from './encoding.mjs';
import {compactMessage} from './compact.mjs';

function width(type) {
  if(type.kind==='array')return type.length*width(type.type);
  if(type.kind==='struct')return type.fields.reduce((n,f)=>n+width(f.type),0);
  return 1;
}
export function publicFields(circuit, inputs) {
  const fields={};let offset=0;
  for(const p of circuit.abi.parameters.filter(p=>p.visibility==='public')){
    const size=width(p.type);
    fields[p.name]=inputs.slice(offset,offset+size).map(BigInt);offset+=size;
  }
  if(offset!==inputs.length)throw new Error('Public input count');
  return fields;
}
function bytes(fields,name,length) {
  const value=fields[name];
  if(!value||value.length!==length||value.some(n=>n<0n||n>255n))throw new Error('Public certificate bytes');
  return Uint8Array.from(value,Number);
}
function u64(fields,name) {
  const value=fields[name];
  if(!value||value.length!==1)throw new Error('Public certificate integer');
  return be(value[0],8);
}
export async function verifyPublicCertificates(circuit,inputs,hash) {
  // Hidden certificates (deposit, R1 ancestry) remain entirely in their circuit.
  if(!circuit.abi.parameters.some(p=>p.name==='certificate'&&p.visibility==='public'))return;
  const fields=publicFields(circuit,inputs);
  const signature=bytes(fields,'certificate',64),key=bytes(fields,'issuer_key',64);
  const order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const r=BigInt('0x'+hex(signature.subarray(0,32))),s=BigInt('0x'+hex(signature.subarray(32)));
  // Match the circuit/native issuer's canonical P1363 low-S requirement.
  if(r===0n||r>=order||s===0n||s>order/2n)throw new Error('Noncanonical issuer signature');
  const transcript=cat(new TextEncoder().encode('cssr.accepted-state.v1\0'),
    bytes(fields,'community',32),bytes(fields,'owner',32),bytes(fields,'state',32),
    bytes(fields,'scope',32),u64(fields,'version'),u64(fields,'accepted_at'));
  const imported=await crypto.subtle.importKey('raw',cat([4],key),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,signature,await compactMessage(transcript,hash)))throw new Error('Invalid public issuer certificate');
}

export async function verifyPublicRecordCertificate(circuit,inputs){
  if(!circuit.abi.parameters.some(p=>p.name==='record_certificate'&&p.visibility==='public'))return;
  const fields=publicFields(circuit,inputs);
  const key=bytes(fields,'record_issuer_key',32),leaf=bytes(fields,'blinded_leaf',32);
  const transcript=cat(new TextEncoder().encode('cblc.record-leaf.v1\0'),bytes(fields,'community',32),u64(fields,'epoch'),leaf);
  const imported=await crypto.subtle.importKey('raw',key,'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',imported,bytes(fields,'record_certificate',64),transcript))throw new Error('Invalid blinded leaf certificate');
}
