// Canonical witness/public-input encoding driven by the authenticated Noir ABI.
// No account policy or application state lives in this core.
function scalar(value) {
  if(typeof value==='number'&&!Number.isSafeInteger(value)) throw new Error('Unsafe ABI integer');
  if(!['string','number','bigint'].includes(typeof value)) throw new Error('ABI scalar');
  if(typeof value==='string'&&!/^(0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)) throw new Error('ABI integer encoding');
  return BigInt(value);
}
const modulus=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export function encode(type,value) {
  switch(type.kind) {
    case 'field': {const n=scalar(value);if(n<0n||n>=modulus)throw new Error('Noncanonical field');return n.toString();}
    case 'integer': {const n=scalar(value);if(type.sign!=='unsigned'||n<0n||n>=1n<<BigInt(type.width))throw new Error('ABI integer range');return n.toString();}
    case 'boolean': if(typeof value!=='boolean')throw new Error('ABI boolean');return value;
    case 'array': if(!(Array.isArray(value)||value instanceof Uint8Array)||value.length!==type.length)throw new Error('ABI array');return Array.from(value,v=>encode(type.type,v));
    case 'struct': {
      if(!value||Array.isArray(value)||Object.keys(value).length!==type.fields.length||!type.fields.every(f=>Object.hasOwn(value,f.name)))throw new Error('ABI struct');
      return Object.fromEntries(type.fields.map(f=>[f.name,encode(f.type,value[f.name])]));
    }
    default: throw new Error('Unsupported Noir ABI type');
  }
}
function flatten(type,value) {
  if(type.kind==='array')return value.flatMap(v=>flatten(type.type,v));
  if(type.kind==='struct')return type.fields.flatMap(f=>flatten(f.type,value[f.name]));
  return [type.kind==='boolean'?(value?1n:0n):BigInt(value)];
}
/** Build the complete witness. It is private data; never log or transmit it. */
export function witnessInputs(circuit,values) {
  if(Object.keys(values).length!==circuit.abi.parameters.length)throw new Error('Exact witness parameters required');
  return Object.fromEntries(circuit.abi.parameters.map(p=>[p.name,encode(p.type,values[p.name])]));
}
/** Bind all public fields in declared ABI order, including nested structures. */
export function publicInputs(circuit,values) {
  return circuit.abi.parameters.filter(p=>p.visibility==='public').flatMap(p=>flatten(p.type,encode(p.type,values[p.name])));
}
