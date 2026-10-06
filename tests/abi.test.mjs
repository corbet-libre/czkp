import test from 'node:test';
import assert from 'node:assert/strict';
import {publicInputs,witnessInputs} from '../runtime/abi.mjs';
const circuit={abi:{parameters:[
  {name:'context',visibility:'public',type:{kind:'struct',fields:[
    {name:'bytes',type:{kind:'array',length:2,type:{kind:'integer',sign:'unsigned',width:8}}},
    {name:'present',type:{kind:'boolean'}}]}},
  {name:'secret',visibility:'private',type:{kind:'field'}},
]}};
test('ABI preserves declared public ordering without leaking private witness fields',()=>{
  const values={secret:7n,context:{present:true,bytes:new Uint8Array([12,34])}};
  assert.deepEqual(publicInputs(circuit,values),[12n,34n,1n]);
  assert.deepEqual(witnessInputs(circuit,values),{context:{bytes:['12','34'],present:true},secret:'7'});
});
test('noncanonical input cannot truncate into an honest public statement',()=>{
  for(const bytes of [[256,0],[-1,0],[1,2,3],[1.5,2],[1,'01']])
    assert.throws(()=>publicInputs(circuit,{context:{present:true,bytes}}));
  for(const secret of [-1n,'21888242871839275222246405745257275088548364400416034343698204186575808495617',NaN])
    assert.throws(()=>witnessInputs(circuit,{context:{present:true,bytes:[1,2]},secret}));
  assert.throws(()=>publicInputs(circuit,{context:{present:1,bytes:[1,2]}}));
  assert.throws(()=>witnessInputs(circuit,{context:{present:true,bytes:[1,2]},secret:1,extra:0}));
});

// Candidate public certificate refusals share the existing CI test entry.
import "./public-checks.test.mjs";

import "./setup.test.mjs";

import "./update.test.mjs";

import "./compact.test.mjs";

import './backend.test.mjs';
