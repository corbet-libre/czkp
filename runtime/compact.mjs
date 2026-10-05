// Versioned byte packing for maintained Poseidon2, followed by WebCrypto's
// ordinary P-256 SHA-256 signing. Original transcript domains/fields are retained.
import {cat} from './encoding.mjs';
import {fieldBytes} from './primitives.mjs';
export const COMPACT_DOMAIN=0x63626c632e636f6d706163742e7631n;
export function compactFields(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.length>65536)throw new Error('Compact transcript bound');
  const fields=[COMPACT_DOMAIN,BigInt(bytes.length)];
  for(let at=0;at<bytes.length;at+=31){let field=0n;for(let i=0;i<31;i++)field=field*256n+BigInt(bytes[at+i]??0);fields.push(field);}
  return fields;
}
export async function compactHash(bytes,hash){
  if(typeof hash!=='function')throw new Error('Maintained Poseidon2 backend required');
  return fieldBytes(await hash(compactFields(bytes)));
}
export async function compactMessage(bytes,hash){
  return cat(new TextEncoder().encode('cblc.compact.v1\0'),await compactHash(bytes,hash));
}
