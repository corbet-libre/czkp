// Canonical record-epoch codecs only. Callers authenticate the descriptor and
// enforce current policy/time independently; decoding is never authorization.
import {cat,be,sha} from './encoding.mjs';
import {fieldValue} from './primitives.mjs';
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
export function recordBytes(v,size=32) {
  if(!(Array.isArray(v)||v instanceof Uint8Array)||v.length!==size||Array.from(v).some(b=>!Number.isInteger(b)||b<0||b>255))throw new Error('Record byte width');
  return Array.from(v);
}
const same=(a,b)=>{a=recordBytes(a);b=recordBytes(b);return a.every((v,i)=>v===b[i]);};
const safe=(v,positive=false)=>{if(!Number.isSafeInteger(v)||v<(positive?1:0))throw new Error('Record integer');return v;};

export function recordEpochPublicInputs(record,scope,issuerKey) {
  if(!exact(record,['epoch','owner','context','shares']))throw new Error('Record epoch public shape');
  const e=record.epoch,c=record.context;
  if(!exact(e,['purpose','community','policyEpoch','epoch','startsAt','expiresAt','root','proofScope','leafCount','downloadDigest','downloadBytes'])
    ||e.purpose!=='cblc.record-epoch.v1'||!exact(e.proofScope,['circuitDigest','verifyingKeyDigest'])
    ||!exact(scope,['circuitDigest','verifyingKeyDigest'])
    ||!same(e.proofScope.circuitDigest,scope.circuitDigest)||!same(e.proofScope.verifyingKeyDigest,scope.verifyingKeyDigest))throw new Error('Record epoch scope');
  const period=safe(e.expiresAt,true)-safe(e.startsAt,true);
  if(period<=0||BigInt(safe(e.epoch,true))*BigInt(period)!==BigInt(e.startsAt)
    ||safe(e.policyEpoch,true)===0||safe(e.leafCount,true)>100000
    ||safe(e.downloadBytes,true)>64*1024*1024)throw new Error('Record epoch bounds');
  for(const v of [e.community,e.root,e.downloadDigest,scope.circuitDigest,scope.verifyingKeyDigest,record.owner])
    if(!recordBytes(v).some(Boolean))throw new Error('Zero record binding');
  if(!exact(c,['purpose','challenge','expiresAt'])||!['firstContact','forumListing'].includes(c.purpose)
    ||!recordBytes(c.challenge).some(Boolean)||safe(c.expiresAt,true)<=e.startsAt||c.expiresAt>e.expiresAt)throw new Error('Record context');
  const shares=record.shares;
  if(shares!==null&&(!Array.isArray(shares)||shares.length!==3||shares.some(v=>!Number.isInteger(v)||v<0||v>10000)||shares.reduce((a,b)=>a+b,0)!==10000))throw new Error('Record shares');
  return {issuer_key:recordBytes(issuerKey,64),scope:recordBytes(scope.circuitDigest),verification_scope:recordBytes(scope.verifyingKeyDigest),
    community:recordBytes(e.community),owner:recordBytes(record.owner),epoch:e.epoch,epoch_start:e.startsAt,epoch_end:e.expiresAt,
    epoch_root:recordBytes(e.root),leaf_count:e.leafCount,purpose:c.purpose==='firstContact'?0:1,challenge:recordBytes(c.challenge),
    expires_at:c.expiresAt,present:shares!==null,shares:shares??[0,0,0]};
}

export async function recordLeafCommitment(community,epoch,leaf) {
  if(!exact(leaf,['owner','version','state','requiredInbox','blinding']))throw new Error('Frozen leaf shape');
  const state=recordBytes(leaf.state),blinding=recordBytes(leaf.blinding);
  if(fieldValue(Uint8Array.from(state))===0n||!blinding.some(Boolean))throw new Error('Frozen leaf bounds');
  return sha(cat(new TextEncoder().encode('cblc.record-frontier.v1\0'),recordBytes(community),be(safe(epoch,true),8),
    recordBytes(leaf.owner),be(safe(leaf.version),8),state,recordBytes(leaf.requiredInbox),blinding));
}
