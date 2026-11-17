import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
export const {ethers}=createRequire(new URL('../../fhe-pod/package.json',import.meta.url))('ethers');
export const json=async p=>JSON.parse(await fs.readFile(p,'utf8'));
export async function atomic(file,value){const tmp=file+'.'+randomUUID()+'.pending';await fs.writeFile(tmp,JSON.stringify(value),{flag:'wx',mode:0o600});await fs.rename(tmp,file);}
let cancelled;
export function cancelPending(reason){cancelled=Error('campaign interrupted: '+reason);}
export async function waitFile(file,seconds=14400){const deadline=Date.now()+seconds*1000;while(true){if(cancelled)throw cancelled;try{return await json(file);}catch(e){if(e.code!=='ENOENT')throw e;}if(Date.now()>deadline)throw Error('timeout waiting for '+path.basename(file));await new Promise(r=>setTimeout(r,200));}}
export async function ownerRpc(body){const id=randomUUID();await atomic(`/owner-rpc/${id}.request`,body);const result=await waitFile(`/owner-rpc/${id}.response`);if(result.error)throw Error(result.error);return result.value;}
export async function ownerTransaction(tx){
  // AbstractSigner passes an ethers Transaction, whose fields are getters,
  // not enumerable own properties. resolveProperties(Transaction) loses them.
  const value=tx instanceof ethers.Transaction?tx.toJSON():await ethers.resolveProperties(tx);
  if(value.chainId==null)throw Error('owner transaction requires an explicit chain ID');
  const plain=JSON.parse(JSON.stringify(value,(_,v)=>typeof v==='bigint'?v.toString():v));
  delete plain.sig;
  return plain;
}
export class OwnerSigner extends ethers.AbstractSigner {
  constructor(address,index,provider,caseName){super(provider);Object.assign(this,{address,index,caseName});}
  getAddress(){return Promise.resolve(this.address);}
  connect(provider){return new OwnerSigner(this.address,this.index,provider,this.caseName);}
  signMessage(){throw Error('owners sign structured approved policy bodies only');}
  signTypedData(){throw Error('unapproved typed signature');}
  async signTransaction(tx){return ownerRpc({action:'transaction',caseName:this.caseName,index:this.index,transaction:await ownerTransaction(tx)});}
}
