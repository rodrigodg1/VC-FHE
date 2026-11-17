import test from 'node:test';
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import {varint,requestBytes,deniedOnce} from './grpc-denial.mjs';
test('protobuf varints and exact pinned request field layout',()=>{
  assert.equal(varint(300).toString('hex'),'ac02');
  assert.throws(()=>varint(-1));
  const value={request_id:{request_id:'r'},typed_ciphertexts:[],key_id:{request_id:'k'},
    client_address:'a',enc_key:[1],domain:{name:'n',version:'v',chain_id:[2],verifying_contract:'c'},extra_data:[3]};
  assert.equal(requestBytes(value).toString('hex'),'0a030a01721a030a016b2201612a0101320c0a016e1201761a01022201633a0103');
});
for(const grpcStatus of [7,14,0])test(`single connection retains actual gRPC status ${grpcStatus}`,async()=>{
  let calls=0;const server=http2.createServer();
  server.on('stream',(stream,headers)=>{calls++;assert.equal(headers[':path'],'/kms_service.v1.CoreServiceEndpoint/UserDecrypt');
    stream.resume();stream.respond({':status':200,'content-type':'application/grpc','grpc-status':String(grpcStatus),'grpc-message':'diagnostic'});stream.end();});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{const result=await deniedOnce(`http://127.0.0.1:${server.address().port}`,Buffer.from([1]));
    assert.equal(result.grpcStatus,grpcStatus);assert.equal(calls,1);
  }finally{await new Promise(r=>server.close(r));}
});
