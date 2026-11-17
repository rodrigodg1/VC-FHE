// Run once in a role container on its assigned host. Export public.json only.
import fs from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {X509Certificate,createHash} from 'node:crypto';
const {ethers}=createRequire('/app/fhe-pod/package.json')('ethers');
const cfg=JSON.parse(await fs.readFile('/config/enrollment.json','utf8'));
if(!/^(validator|kms|owner|operator|auditor|adjudicator|recipient|coordinator)-[1-4]$/.test(cfg.node))throw Error('invalid role');
if(!/^10\.\d+\.\d+\.\d+$/.test(cfg.private_ip))throw Error('invalid private address');
await fs.mkdir('/identity',{recursive:true,mode:0o700});
try{await fs.access('/identity/public.json');throw Error('identity already enrolled. Preserve it instead of creating another');}
catch(e){if(e.code!=='ENOENT')throw e;}
const wallet=ethers.Wallet.createRandom();
const unprefixed=cfg.node.startsWith('recipient-');
await fs.writeFile('/identity/signing.hex',unprefixed?wallet.privateKey.slice(2):wallet.privateKey,{flag:'wx',mode:0o600});
if(cfg.node.startsWith('validator-'))await fs.writeFile('/identity/nodekey',wallet.privateKey.slice(2),{flag:'wx',mode:0o600});
execFileSync('openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
  '-keyout','/identity/tls.key','-out','/identity/tls.crt','-days','30','-subj','/CN='+cfg.node,
  '-addext',`subjectAltName=DNS:${cfg.node},IP:${cfg.private_ip}`,
  '-addext','extendedKeyUsage=serverAuth,clientAuth'],{stdio:['ignore','ignore','ignore']});
await fs.chmod('/identity/tls.key',0o600);
const certificate=await fs.readFile('/identity/tls.crt','utf8');
const publicInfo={schema:'vcfhe-public-role-identity-v1',node:cfg.node,host:cfg.host,address:wallet.address,
  publicKey:wallet.signingKey.publicKey,certificate,fingerprint256:new X509Certificate(certificate).fingerprint256,
  binarySha256:createHash('sha256').update(await fs.readFile('/usr/local/bin/kms-campaign')).digest('hex')};
if(cfg.node==='coordinator-1'){
  const setup=ethers.Wallet.createRandom();
  await fs.mkdir('/identity/setup',{mode:0o700});
  await fs.writeFile('/identity/setup/signing.hex',setup.privateKey.slice(2),{flag:'wx',mode:0o600});
  publicInfo.setupPublicKey=setup.signingKey.compressedPublicKey.slice(2);
}
await fs.writeFile('/identity/public.json',JSON.stringify(publicInfo,null,2),{flag:'wx',mode:0o644});
process.stdout.write(JSON.stringify(publicInfo));
