import test from 'node:test';
import assert from 'node:assert/strict';
import {compactFields,COMPACT_DOMAIN} from '../runtime/compact.mjs';
test('compact encoding preserves domains, leading/trailing zeros and chunk boundaries',()=>{
  assert.deepEqual(compactFields(new Uint8Array()),[COMPACT_DOMAIN,0n]);
  assert.deepEqual(compactFields(Uint8Array.of(1)),[COMPACT_DOMAIN,1n,1n<<240n]);
  assert.notDeepEqual(compactFields(Uint8Array.of(1)),compactFields(Uint8Array.of(1,0)));
  const input=Uint8Array.from({length:63},(_,i)=>i);
  const fields=compactFields(input);assert.equal(fields.length,5);assert.equal(fields[1],63n);
  assert(fields.slice(2).every(n=>n<1n<<248n));
  for(let i=0;i<input.length;i++){const bad=input.slice();bad[i]^=1;assert.notDeepEqual(compactFields(bad),fields);}
  assert.throws(()=>compactFields(new Uint8Array(65537)));
});
