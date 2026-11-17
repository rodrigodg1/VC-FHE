// Diagnostic only. This module never retries a request or requests a result.
import http2 from 'node:http2';
export function varint(value){
  let n=BigInt(value);if(n<0n)throw Error('negative protobuf diagnostic value');
  const out=[];do{let b=Number(n&127n);n>>=7n;out.push(b|(n?128:0));}while(n);
  return Buffer.from(out);
}
function bytes(number,value){
  const body=typeof value==='string'?Buffer.from(value):Buffer.from(value??[]);
  return Buffer.concat([varint(number*8+2),varint(body.length),body]);
}
function integer(number,value){return Buffer.concat([varint(number*8),varint(value)]);}
function id(value){return bytes(1,value.request_id);}
function domain(v){
  const out=[bytes(1,v.name),bytes(2,v.version),bytes(3,v.chain_id),bytes(4,v.verifying_contract)];
  if(v.salt!==null&&v.salt!==undefined)out.push(bytes(5,v.salt));
  return Buffer.concat(out);
}
function ciphertext(v){return Buffer.concat([bytes(1,v.ciphertext),integer(2,v.fhe_type),
  bytes(3,v.external_handle),integer(4,v.ciphertext_format)]);}
export function requestBytes(v){
  const parts=[bytes(1,id(v.request_id)),...v.typed_ciphertexts.map(x=>bytes(2,ciphertext(x))),
    bytes(3,id(v.key_id)),bytes(4,v.client_address),bytes(5,v.enc_key),bytes(6,domain(v.domain)),bytes(7,v.extra_data)];
  if(v.context_id)parts.push(bytes(8,id(v.context_id)));
  if(v.epoch_id)parts.push(bytes(9,id(v.epoch_id)));
  return Buffer.concat(parts);
}
export async function deniedOnce(address,payload,{timeoutMs=30000}={}){
  const connection=http2.connect(address);
  try{return await new Promise((resolve,reject)=>{
    let done=false;const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(value);};
    const timer=setTimeout(()=>finish(Error('diagnostic connection deadline exceeded')),timeoutMs);
    connection.once('error',e=>finish(e));
    const stream=connection.request({':method':'POST',':path':'/kms_service.v1.CoreServiceEndpoint/UserDecrypt',
      'content-type':'application/grpc','te':'trailers'});
    let status,message;
    const headers=h=>{if(h['grpc-status']!==undefined)status=Number(h['grpc-status']);
      if(h['grpc-message']!==undefined)message=decodeURIComponent(h['grpc-message']);};
    stream.on('response',headers);stream.on('trailers',headers);stream.on('data',()=>{});
    stream.once('error',e=>finish(e));stream.once('end',()=>finish(null,{grpcStatus:status,message}));
    const prefix=Buffer.alloc(5);prefix.writeUInt32BE(payload.length,1);stream.end(Buffer.concat([prefix,payload]));
  });}finally{connection.destroy();}
}
