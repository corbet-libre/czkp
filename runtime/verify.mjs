// Verification-only import: no holder state or witness enters this module.
import { openBackend } from './backend.mjs';
import { verifyPublicCertificates,verifyPublicRecordCertificate } from './public-checks.mjs';
import { verifyPublicPolicy } from './public-policy.mjs';
import { fieldBytes,fieldValue } from './primitives.mjs';
import { OPTIONS, unhex } from './encoding.mjs';
const exact = (value, keys) => value && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const equal = (a,b) => a.length===b.length && a.every((v,i)=>v===b[i]);
export async function createVerifier({ artifacts, publicInputs, browserFactory }) {
  const api = await openBackend(artifacts, browserFactory, undefined, true);
  try {
    const { UltraHonkVerifierBackend } = await import('@aztec/bb.js');
    const verifier = new UltraHonkVerifierBackend(api);
    const scope = Object.freeze({circuitDigest:Object.freeze(Array.from(unhex(artifacts.manifest.circuitSha256))),
      verifyingKeyDigest:Object.freeze(Array.from(unhex(artifacts.manifest.vkSha256)))});
    let busy=false, destroyed=false;
    return Object.freeze({scope,
      async verify(record) {
        if(busy||destroyed) throw new Error('Verifier busy or closed');
        busy=true;
        try {
          if(!exact(record,['statement','proof','proofScope'])||!exact(record.proofScope,['circuitDigest','verifyingKeyDigest'])
            ||!equal(record.proofScope.circuitDigest,scope.circuitDigest)||!equal(record.proofScope.verifyingKeyDigest,scope.verifyingKeyDigest)
            ||typeof record.proof!=='string'||record.proof.length===0||record.proof.length>artifacts.limits.maxProofBytes*2) throw new Error('Proof scope/size');
          const inputs=await publicInputs(record.statement);
          await verifyPublicCertificates(artifacts.circuit,inputs,async fields=>fieldValue((await api.poseidon2Hash({inputs:fields.map(fieldBytes)})).hash));
          await verifyPublicPolicy(artifacts.circuit,inputs);
          await verifyPublicRecordCertificate(artifacts.circuit,inputs);
          if(!await verifier.verifyProof({proof:unhex(record.proof),publicInputs:inputs.map(n=>'0x'+n.toString(16).padStart(64,'0')),
            verificationKey:artifacts.verificationKey},OPTIONS)) throw new Error('Invalid proof');
          return {verified:true,proofScope:scope};
        } finally {busy=false;}
      },
      async destroy() {if(busy) throw new Error('Verifier busy');if(!destroyed){destroyed=true;await api.destroy();}}
    });
  } catch(error){await api.destroy();throw error;}
}
