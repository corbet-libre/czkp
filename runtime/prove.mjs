// Holder-only import. Witnesses are consumed transiently, never recorded or logged.
// The embedding validates policy inputs and keeps the resulting openings itself.
import { openBackend } from './backend.mjs';
import { OPTIONS } from './encoding.mjs';
export async function createProver({artifacts, browserFactory}) {
  const api=await openBackend(artifacts,browserFactory);
  try {
    const { Noir }=await import('@noir-lang/noir_js');
    const { UltraHonkBackend, UltraHonkVerifierBackend }=await import('@aztec/bb.js');
    const noir=new Noir(artifacts.circuit),backend=new UltraHonkBackend(artifacts.circuit.bytecode,api),verifier=new UltraHonkVerifierBackend(api);
    let busy=false,destroyed=false;
    return Object.freeze({
      async prove(witnessInputs,expectedPublicInputs) {
        if(busy||destroyed) throw new Error('Prover busy or closed');busy=true;
        try {
          const executed=await noir.execute(witnessInputs);
          const proof=await backend.generateProof(executed.witness,OPTIONS);
          if(proof.proof.length>artifacts.limits.maxProofBytes||proof.publicInputs.length!==expectedPublicInputs.length
            ||!proof.publicInputs.every((v,i)=>BigInt(v)===BigInt(expectedPublicInputs[i]))) throw new Error('Public input mismatch');
          if(!await verifier.verifyProof({...proof,verificationKey:artifacts.verificationKey},OPTIONS)) throw new Error('Invalid generated proof');
          return proof;
        } finally {busy=false;}
      },
      async destroy(){if(busy)throw new Error('Prover busy');if(!destroyed){destroyed=true;await api.destroy();}}
    });
  } catch(error){await api.destroy();throw error;}
}
