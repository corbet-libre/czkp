// Exactly the classes already revealed by the public update statement.
export const UPDATE_CIRCUITS=Object.freeze(['update_genesis','update_consume','update_change','update_settlement','update_regular']);
export function updateCircuit(input){
  if(typeof input.genesis!=='boolean'||typeof input.consume_only!=='boolean')throw new Error('Update class boolean');
  const nonzero=value=>{
    if(!(Array.isArray(value)||value instanceof Uint8Array)||value.length!==32||Array.from(value).some(n=>!Number.isInteger(n)||n<0||n>255))throw new Error('Update class bytes');
    return value.some(n=>n!==0);
  };
  const change=nonzero(input.change_binding),marker=nonzero(input.settlement_marker);
  return UPDATE_CIRCUITS[input.genesis?0:input.consume_only?1:change?2:marker?3:4];
}
