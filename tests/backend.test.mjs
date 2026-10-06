import test from 'node:test';
import assert from 'node:assert/strict';
import {proverThreads} from '../runtime/backend.mjs';
test('all available native cores and explicit 1/4/8 remain selectable',()=>{
  assert.equal(proverThreads(undefined,{browser:false,hardwareConcurrency:24}),24);
  for(const threads of [1,4,8,24])assert.equal(proverThreads(threads,{browser:false,hardwareConcurrency:24}),threads);
  for(const threads of [0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1])assert.throws(()=>proverThreads(threads));
});
test('framed browser proving requires actual isolation and leaves background headroom',()=>{
  for(const hardwareConcurrency of [1,2,8,24]){
    const env={browser:true,hardwareConcurrency,isolated:false};
    assert.equal(proverThreads(8,env),1);
    assert.equal(proverThreads(undefined,{...env,isolated:true}),Math.min(hardwareConcurrency,8));
    assert.equal(proverThreads(undefined,{...env,isolated:true,background:true}),Math.max(1,Math.min(hardwareConcurrency-1,4)));
  }
  for(const threads of [1,2,4,8])assert.equal(proverThreads(threads,{browser:true,hardwareConcurrency:8,isolated:true}),threads);
});
