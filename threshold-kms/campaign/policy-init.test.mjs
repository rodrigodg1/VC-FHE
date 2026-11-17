import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';

const directory=path.dirname(fileURLToPath(import.meta.url));
const appRoot=path.resolve(directory,'../..');
const require=createRequire(path.join(appRoot,'threshold-kms/package.json'));
const ganache=require('ganache');
const mnemonic='test test test test test test test test test test test junk';
const owners=[
  '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
  '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
  '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc',
  '0x90f79bf6eb2c4f870365e785982e1f101e93b906'
];

function runPolicy(env){
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[path.join(directory,'policy-init.mjs')],{env:{...process.env,...env}});
    let stdout='',stderr='';
    child.stdout.on('data',chunk=>stdout+=chunk);
    child.stderr.on('data',chunk=>stderr+=chunk);
    child.on('error',reject);
    child.on('close',code=>resolve({code,stdout,stderr}));
  });
}

test('policy initialization pins and rechecks the chain lineage',async t=>{
  const server=ganache.server({logging:{quiet:true},chain:{chainId:46853,hardfork:'london'},
    wallet:{mnemonic,totalAccounts:10}});
  await server.listen(0);
  t.after(async()=>server.close());
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-policy-init-'));
  t.after(async()=>fs.rm(root,{recursive:true,force:true}));
  const state=path.join(root,'state'),config=path.join(root,'config');
  await fs.mkdir(state);await fs.mkdir(config);
  await fs.writeFile(path.join(config,'owners.json'),JSON.stringify(owners));
  const env={VCFHE_APP_ROOT:appRoot,VCFHE_POLICY_STATE_DIR:state,VCFHE_POLICY_CONFIG_DIR:config,
    VCFHE_POLICY_RPC_URL:`http://127.0.0.1:${server.address().port}`,VCFHE_EXPECTED_CHAIN_ID:'46853',
    VCFHE_POLICY_VERSION:'3',VCFHE_ALLOW_NEW_POLICY_LINEAGE:'1',VCFHE_MNEMONIC:mnemonic};

  for(let attempt=0;attempt<2;attempt++){
    const result=await runPolicy(env);
    assert.equal(result.code,0,result.stderr);
    assert.equal(JSON.parse(result.stdout).status,'verified');
  }
  const stateFile=path.join(state,'deployment.json');
  const persisted=JSON.parse(await fs.readFile(stateFile,'utf8'));
  assert.equal(persisted.schema,'vcfhe-release-policy-deployment-v3');
  for(const field of ['genesisBlockHash','deploymentBlockHash','lastVerifiedBlockHash'])
    assert.match(persisted[field],/^0x[0-9a-f]{64}$/i,field);
  assert.ok(Number.isSafeInteger(persisted.deploymentBlock));
  assert.ok(Number.isSafeInteger(persisted.lastVerifiedBlockNumber));

  const refreshEnv={...env,VCFHE_ALLOW_NEW_POLICY_LINEAGE:'0',VCFHE_REQUIRE_EXISTING_POLICY:'1'};
  const nonceBeforeRefresh=await server.provider.request({method:'eth_getTransactionCount',
    params:[owners[0],'latest']});
  const refresh=await runPolicy(refreshEnv);
  assert.equal(refresh.code,0,refresh.stderr);
  const nonceAfterRefresh=await server.provider.request({method:'eth_getTransactionCount',
    params:[owners[0],'latest']});
  assert.equal(nonceAfterRefresh,nonceBeforeRefresh,'existing-policy refresh sent an on-chain transaction');
  const refreshConfig=JSON.parse(await fs.readFile(path.join(config,'release-policy.json'),'utf8'));
  assert.equal(refreshConfig.ownersSha256,persisted.legacyMigrationInput.ownersSha256);

  await fs.writeFile(path.join(config,'owners.json'),JSON.stringify([...owners].reverse()));
  const changedOwners=await runPolicy(refreshEnv);
  assert.notEqual(changedOwners.code,0,'changed owner identity ordering was accepted');
  assert.match(changedOwners.stderr,/owner identity set changed/);
  await fs.writeFile(path.join(config,'owners.json'),JSON.stringify(owners));

  const current=JSON.parse(await fs.readFile(stateFile,'utf8'));
  await fs.writeFile(stateFile,JSON.stringify({...current,status:'pending'}));
  const pending=await runPolicy(refreshEnv);
  assert.notEqual(pending.code,0,'pending policy was accepted as an existing deployed lineage');
  assert.match(pending.stderr,/already deployed policy/);
  await fs.writeFile(stateFile,JSON.stringify(current));

  const emptyState=path.join(root,'empty-state'),emptyConfig=path.join(root,'empty-config');
  await fs.mkdir(emptyState);await fs.mkdir(emptyConfig);
  await fs.writeFile(path.join(emptyConfig,'owners.json'),JSON.stringify(owners));
  const absent=await runPolicy({...refreshEnv,VCFHE_POLICY_STATE_DIR:emptyState,
    VCFHE_POLICY_CONFIG_DIR:emptyConfig});
  assert.notEqual(absent.code,0,'refresh deployed a missing policy');
  assert.match(absent.stderr,/already deployed policy/);
  await assert.rejects(fs.access(path.join(emptyState,'deployment.json')));

  persisted.deploymentBlockHash='0x'+'00'.repeat(32);
  await fs.writeFile(stateFile,JSON.stringify(persisted));
  const tampered=await runPolicy(env);
  assert.notEqual(tampered.code,0,'tampered deployment anchor was accepted');
  assert.match(tampered.stderr,/deployment receipt changed or disappeared/);
});
