import fs from 'node:fs';
import {createRequire} from 'node:module';
const {ethers}=createRequire('/app/fhe-pod/package.json')('ethers');
// The orchestration helper can initialize each identity, but no application
// container mounts this complete provisioning directory afterwards. Release
// authorization is recorded by the adminless on-chain policy registry, so
// there is deliberately no gateway signing identity.
for(const role of ['recipient','setup']) {
  const file=`/provision/${role}/signing.hex`;
  if(!fs.existsSync(file))fs.writeFileSync(file,ethers.Wallet.createRandom().privateKey.slice(2),{flag:'wx',mode:0o600});
  const wallet=new ethers.Wallet('0x'+fs.readFileSync(file,'utf8').trim());
  fs.writeFileSync(`/provision/config/${role}-address.txt`,wallet.address);
  if(role==='setup')fs.writeFileSync(`/provision/config/${role}-public.hex`,wallet.signingKey.compressedPublicKey.slice(2));
}
const allowNew=process.env.VCFHE_ALLOW_NEW_POLICY_LINEAGE==='1';
if(!fs.existsSync('/provision/owner/identities.json')){
  if(!allowNew)throw Error('owner identities required for cumulative-policy continuity');
  const owners=Array.from({length:4},()=>ethers.Wallet.createRandom().privateKey);
  fs.writeFileSync('/provision/owner/identities.json',JSON.stringify(owners),{flag:'wx',mode:0o600});
}
const owners=JSON.parse(fs.readFileSync('/provision/owner/identities.json','utf8'));
if(!Array.isArray(owners)||owners.length!==4||new Set(owners.map(key=>new ethers.Wallet(key).address.toLowerCase())).size!==4)
  throw Error('invalid owner identity set');
fs.writeFileSync('/provision/config/owners.json',JSON.stringify(owners.map(k=>new ethers.Wallet(k).address)));
