import {configuration,rpc} from './client.mjs';
const cfg=await configuration(),deadline=Date.now()+600000;
for(const peer of cfg.peers){
  while(true){
    try{const r=await rpc(peer.node,'public-manifest',{paths:['/keyset/ready.json']},{timeoutMs:5000});
      if(!r.ready)throw Error('keyset not ready');break;}
    catch(error){if(Date.now()>deadline)throw error;await new Promise(r=>setTimeout(r,2000));}
  }
}
console.log('All participant endpoints authenticated and public keysets available');
