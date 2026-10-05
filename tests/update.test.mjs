import test from 'node:test';
import assert from 'node:assert/strict';
import {updateCircuit,UPDATE_CIRCUITS} from '../runtime/update.mjs';
test('update verification key depends only on the already-public class bits',()=>{
  for(const genesis of [false,true])for(const consume_only of [false,true])for(const change of [false,true])for(const marker of [false,true]){
    const input={genesis,consume_only,change_binding:Array(32).fill(change?1:0),settlement_marker:Array(32).fill(marker?1:0)};
    assert.equal(updateCircuit(input),UPDATE_CIRCUITS[genesis?0:consume_only?1:change?2:marker?3:4]);
    for(const action of [1,2,3,4,5,6,7,8,9,10,11])assert.equal(updateCircuit({...input,action}),updateCircuit(input));
  }
  for(const mutate of [i=>i.genesis=0,i=>i.consume_only='false',i=>i.change_binding.pop(),i=>i.settlement_marker[0]=256]){
    const i={genesis:false,consume_only:false,change_binding:Array(32).fill(0),settlement_marker:Array(32).fill(0)};mutate(i);assert.throws(()=>updateCircuit(i));
  }
});
