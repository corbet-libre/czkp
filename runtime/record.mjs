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
  if(!exact(record,['epoch','owner','presentationKeyCommitment','shares']))throw new Error('Record epoch public shape');
  const e=record.epoch;
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
  if(!recordBytes(record.presentationKeyCommitment).some(Boolean))throw new Error('Record presentation key');
  const shares=record.shares;
  if(shares!==null&&(!Array.isArray(shares)||shares.length!==3||shares.some(v=>!Number.isInteger(v)||v<0||v>10000)||shares.reduce((a,b)=>a+b,0)!==10000))throw new Error('Record shares');
  return {issuer_key:recordBytes(issuerKey,64),scope:recordBytes(scope.circuitDigest),verification_scope:recordBytes(scope.verifyingKeyDigest),
    community:recordBytes(e.community),owner:recordBytes(record.owner),epoch:e.epoch,epoch_start:e.startsAt,epoch_end:e.expiresAt,
    epoch_root:recordBytes(e.root),leaf_count:e.leafCount,presentation_key_commitment:recordBytes(record.presentationKeyCommitment),
    present:shares!==null,shares:shares??[0,0,0]};
}

// Fixed-width, domain-separated Ed25519 message. Both purpose and expiry are
// signed with the challenge; the proof's complete public record is bound too.
export function recordPresentationBytes(record,context) {
  const e=record.epoch;
  recordEpochPublicInputs(record,e.proofScope,Array(64).fill(1));
  if(!exact(context,['purpose','challenge','expiresAt'])||!['firstContact','forumListing'].includes(context.purpose)
    ||!recordBytes(context.challenge).some(Boolean)||safe(context.expiresAt,true)<=e.startsAt||context.expiresAt>e.expiresAt)throw new Error('Record context');
  return cat(new TextEncoder().encode('cblc.record-presentation.v1\0'),e.community,be(e.policyEpoch,8),be(e.epoch,8),
    be(e.startsAt,8),be(e.expiresAt,8),e.root,e.proofScope.circuitDigest,e.proofScope.verifyingKeyDigest,
    be(e.leafCount,4),e.downloadDigest,be(e.downloadBytes,8),record.owner,record.presentationKeyCommitment,
    [record.shares===null?0:1],...(record.shares??[0,0,0]).map(n=>be(n,2)),
    [context.purpose==='firstContact'?0:1],context.challenge,be(context.expiresAt,8));
}

// Signature and context check only. Always verify the cached ZK proof as well,
// against the independently authenticated latest epoch, before consuming the
// relying party's one-use challenge. A decoded record grants no authority.
export async function verifyRecordPresentation(presentation,expected,epoch,owner,now) {
  if(!exact(presentation,['record','context','publicKey','signature','proof'])||typeof presentation.proof!=='string'||!presentation.proof.length)throw new Error('Missing record proof');
  const {record,context}=presentation;
  const equal=(a,b)=>recordBytes(a).every((n,i)=>n===recordBytes(b)[i]);
  if(!Number.isSafeInteger(now)||now<epoch.startsAt||now>=epoch.expiresAt||now>=context.expiresAt)throw new Error('Expired record');
  // Field-order independent equality via the already validated canonical bytes.
  const canonical=recordPresentationBytes(record,context);
  const trusted=recordPresentationBytes({...record,epoch,owner},expected);
  if(canonical.length!==trusted.length||!canonical.every((n,i)=>n===trusted[i]))throw new Error('Wrong epoch, owner or challenge');
  const publicKey=recordBytes(presentation.publicKey);
  if(!equal(await sha(Uint8Array.from(publicKey)),record.presentationKeyCommitment))throw new Error('Wrong presentation key');
  const key=await crypto.subtle.importKey('raw',Uint8Array.from(publicKey),'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',key,Uint8Array.from(recordBytes(presentation.signature,64)),canonical))throw new Error('Invalid presentation signature');
}

export async function recordLeafCommitment(community,epoch,leaf) {
  if(!exact(leaf,['owner','version','state','requiredInbox','blinding']))throw new Error('Frozen leaf shape');
  const state=recordBytes(leaf.state),blinding=recordBytes(leaf.blinding);
  if(fieldValue(Uint8Array.from(state))===0n||!blinding.some(Boolean))throw new Error('Frozen leaf bounds');
  return sha(cat(new TextEncoder().encode('cblc.record-frontier.v1\0'),recordBytes(community),be(safe(epoch,true),8),
    recordBytes(leaf.owner),be(safe(leaf.version),8),state,recordBytes(leaf.requiredInbox),blinding));
}
