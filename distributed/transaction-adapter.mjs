// Operator/auditor identities stay in their role containers. Only deployments
// of the pinned contracts, created by this campaign's requester, may receive a
// transaction. Owner approvals and adjudicator certificates use other adapters.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const {ethers}=createRequire('/app/fhe-pod/package.json')('ethers');
const allowed={
  operator:{CanonicalBountyFHEDisputeGame:['registerOperator','createTask','submitOperatorChildren','respondToChallenge','submitOperatorLeaf'],
    BountyTraceAvailability:['publishTraceBatch','publishDisputedTraceBatch'],
    GroupedLinearVerification:['depositStake','submitResultBound']},
  auditor:{CanonicalBountyFHEDisputeGame:['registerAuditor','submitSealedAudit','proveAuditDiligence','openChallenge',
    'submitChallengerChildren','submitChallengerLeaf','claimAuditBond','withdraw'],BountyTraceAvailability:['requestTraceDisclosure']},
};
export async function transactionAdapter(cfg){
  assert.ok(allowed[cfg.role]);
  const provider=new ethers.JsonRpcProvider(cfg.rpcUrl,undefined,{cacheTimeout:-1});
  const wallet=new ethers.Wallet((await fs.readFile('/identity/signing.hex','utf8')).trim(),provider);
  assert.equal(wallet.address,cfg.identities[cfg.node]);
  const root='/transport/contracts';await fs.mkdir(root,{recursive:true});
  const {compileContracts}=await import('/app/threshold-kms/campaign/runtime/scripts/evm-lib.mjs');
  const artifacts=await compileContracts();
  if(cfg.role==='operator'){
    const solc=createRequire('/app/BN254-Signatures/package.json')('solc'),sources={};
    for(const [name,file] of [['GroupedLinearVerification.sol','/app/threshold-kms/contracts/GroupedLinearVerification.sol'],
      ['MKLHS-Verification.sol','/app/BN254-Signatures/contract/MKLHS-Verification.sol']])
      sources[name]={content:await fs.readFile(file,'utf8')};
    const result=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,
      settings:{optimizer:{enabled:false},evmVersion:'london',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
    assert.deepEqual((result.errors??[]).filter(e=>e.severity==='error'),[]);
    const a=result.contracts['GroupedLinearVerification.sol'].GroupedLinearVerification;
    artifacts.GroupedLinearVerification={abi:a.abi,bytecode:'0x'+a.evm.bytecode.object};
  }
  async function chain(){
    assert.equal(String((await provider.getNetwork()).chainId),String(cfg.chainId));
    assert.equal((await provider.getBlock(0)).hash,cfg.genesisHash,'campaign chain changed');
  }
  return {
    bind:async({name,transactionHash,artifact})=>{
      await chain();assert.ok(allowed[cfg.role][name],'contract not used by this role');
      assert.ok(artifacts[name],'contract bytecode is not locally available');
      assert.equal(artifact,undefined,'caller cannot supply trusted contract code');
      const [tx,r]=await Promise.all([provider.getTransaction(transactionHash),provider.getTransactionReceipt(transactionHash)]);
      assert.ok(tx&&r&&r.status===1&&tx.to===null&&r.contractAddress);
      assert.equal(tx.from.toLowerCase(),cfg.identities['coordinator-1'].toLowerCase());
      const a=artifacts[name],bytecode=a.bytecode.startsWith('0x')?a.bytecode:'0x'+a.bytecode;
      assert.ok(tx.data.startsWith(bytecode),'deployment code differs from pinned contract');
      const iface=new ethers.Interface(a.abi);
      const encoded='0x'+tx.data.slice(bytecode.length);
      const args=ethers.AbiCoder.defaultAbiCoder().decode(iface.deploy.inputs,encoded);
      assert.equal(ethers.AbiCoder.defaultAbiCoder().encode(iface.deploy.inputs,args),encoded,'noncanonical constructor arguments');
      const code=await provider.getCode(r.contractAddress);assert.notEqual(code,'0x');
      const value={name,address:r.contractAddress,transactionHash,codeHash:ethers.keccak256(code),abi:a.abi};
      const file=root+'/'+r.contractAddress.toLowerCase()+'.json';
      try{await fs.writeFile(file,JSON.stringify(value),{flag:'wx',mode:0o600});}
      catch(e){if(e.code!=='EEXIST')throw e;assert.deepEqual(JSON.parse(await fs.readFile(file)),value);}
      return {address:r.contractAddress,codeHash:value.codeHash};
    },
    sign:async({transaction})=>{
      await chain();const tx=ethers.Transaction.from(transaction);
      assert.equal(String(tx.chainId),String(cfg.chainId));assert.ok(tx.to&&tx.signature===null);
      const entry=JSON.parse(await fs.readFile(root+'/'+tx.to.toLowerCase()+'.json','utf8'));
      assert.equal(ethers.keccak256(await provider.getCode(tx.to)),entry.codeHash);
      const decoded=new ethers.Interface(entry.abi).parseTransaction({data:tx.data,value:tx.value});
      assert.ok(decoded&&allowed[cfg.role][entry.name].includes(decoded.name),'unapproved role action');
      if(decoded.name==='submitSealedAudit'){
        const decision=JSON.parse(await fs.readFile('/transport/audit-commitments/'+decoded.args[0]+'.json','utf8'));
        assert.equal(decision.game.toLowerCase(),tx.to.toLowerCase());
        assert.equal(decision.commitment,decoded.args[1],'audit commitment not prepared by this participant');
      }
      if(decoded.name==='withdraw')assert.equal(decoded.args[1].toLowerCase(),cfg.identities['coordinator-1'].toLowerCase());
      assert.ok(tx.value<=ethers.parseEther('10'),'role deposit exceeds campaign limit');
      assert.equal(tx.nonce,await provider.getTransactionCount(wallet.address,'pending'),'stale participant nonce');
      return wallet.signTransaction(tx);
    }
  };
}
