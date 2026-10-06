// Hashes of entirely public policy inputs, bound to the circuit's public ABI.
import {be,cat,sha} from './encoding.mjs';
import {publicFields} from './public-checks.mjs';
export const ACCOUNT_TREE_DEPTH=20;
const fields=[['initial_credit',4],['maximum_available',4],['outgoing_reservation',4],['incoming_reservation',4],
  ['policy_revision',8],['policy_valid_from',8],['policy_valid_until',8],['newcomer_period',8],['rate_window',8],
  ['newcomer_admissions',4],['maximum_admissions',4],['refill_period',8],['refill_units',4],['abandon_after',8]];
export async function verifyPublicPolicy(circuit,inputs){
  const names=circuit.abi.parameters.filter(p=>p.visibility==='public').map(p=>p.name);
  if(!names.includes('genesis')||!names.includes('state_policy'))return;
  const f=publicFields(circuit,inputs);
  const bytes=name=>{
    if(f[name]?.length!==32||f[name].some(n=>n<0n||n>255n))throw new Error('Public policy bytes');
    return Uint8Array.from(f[name],Number);
  };
  const encoded=cat(new TextEncoder().encode('cfrm.account-policy.v2\0'),bytes('community'),
    ...fields.map(([name,size])=>{if(f[name]?.length!==1)throw new Error('Policy integer');return be(f[name][0],size);}),[ACCOUNT_TREE_DEPTH]);
  const stable=cat(new TextEncoder().encode('cfrm.account-state-policy.v1\0'),bytes('community'),encoded.slice(55,131),[ACCOUNT_TREE_DEPTH]);
  for(const [name,message] of [['policy_digest',encoded],['state_policy',stable]]){
    const expected=bytes(name),actual=await sha(message);
    if(!actual.every((n,i)=>n===expected[i]))throw new Error('Public policy digest');
  }
}
