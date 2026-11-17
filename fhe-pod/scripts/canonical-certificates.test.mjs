import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import ganache from 'ganache';
import solc from 'solc';
import { ethers } from 'ethers';
import { canonicalDomain, CONTEXT_TYPES, RESULT_TYPES } from './canonical-chain.mjs';

test('canonical certificates reject wrong purpose, chain, deployment, task, profile, leaf and quorum', async () => {
  const source=await fs.readFile(new URL('../contracts/src/CanonicalLeafVerifier.sol',import.meta.url),'utf8');
  const build=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'Verifier.sol':{content:source}},
    settings:{evmVersion:'paris',viaIR:true,optimizer:{enabled:true,runs:1},outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
  assert.equal((build.errors??[]).filter(e=>e.severity==='error').length,0,JSON.stringify(build.errors));
  const artifact=build.contracts['Verifier.sol'].CanonicalLeafVerifier;
  const backend=ganache.provider({logging:{quiet:true},chain:{chainId:31337}});
  const provider=new ethers.BrowserProvider(backend);provider.pollingInterval=10;
  try {
    const game=await provider.getSigner(0), outsider=await provider.getSigner(1);
    const signers=Array.from({length:3},()=>ethers.Wallet.createRandom()), profile=ethers.id('profile');
    const factory=new ethers.ContractFactory(artifact.abi,artifact.evm.bytecode.object,game);
    const verifier=await factory.deploy(await game.getAddress(),profile,signers.map(s=>s.address),2);await verifier.waitForDeployment();
    const domain=canonicalDomain(31337,verifier.target),task=ethers.id('task'),context=ethers.id('context');
    const contextSigs=await Promise.all(signers.slice(0,2).map(w=>w.signTypedData(domain,CONTEXT_TYPES,{taskId:task,contextDigest:context})));
    await assert.rejects(verifier.registerContext(ethers.id('other-task'),context,contextSigs));
    await assert.rejects(verifier.registerContext(task,context,[contextSigs[0],contextSigs[0]]));
    await (await verifier.registerContext(task,context,contextSigs)).wait();
    await assert.rejects(verifier.registerContext(task,ethers.id('replacement'),contextSigs));
    const abi=ethers.AbiCoder.defaultAbiCoder(),result=ethers.id('expected'),wrong=ethers.id('incorrect');
    const bind=(changes={})=>{const b={tag:ethers.id('FHE_POD_LEAF_DECISION_V1'),game:game.address,chain:31337,task,index:2,opcode:1,...changes};
      return abi.encode(['bytes32','address','uint256','bytes32','uint32','uint8'],Object.values(b));};
    const binding=bind(),body={profileDigest:profile,contextDigest:context,leafBinding:ethers.keccak256(binding),resultHandle:result};
    const sign=(d=domain,b=body)=>Promise.all(signers.slice(0,2).map(w=>w.signTypedData(d,RESULT_TYPES,b)));
    const sigs=await sign(),proof=(ss=sigs,bb=binding)=>abi.encode(['bytes[]','bytes'],[[result,...ss],bb]);
    const decisions=abi.encode(['bool','bool'],[false,true]);
    const verify=(pp=proof(),dd=decisions,contract=verifier)=>contract.verifyDecryptionEIP712KMSSignatures([wrong,result],dd,pp);
    assert.equal(await verify(),true);
    for(const ss of [[sigs[0]],[sigs[0],sigs[0]],['0x1234'],
      await sign({...domain,chainId:31338}),await sign({...domain,name:'VCFHE-Full-Execution'}),
      await sign(domain,{...body,profileDigest:ethers.id('other-profile')}),
      await sign(domain,{...body,contextDigest:ethers.id('other-context')}),
      await sign(domain,{...body,resultHandle:wrong})]) {
        try{assert.equal(await verify(proof(ss)),false);}catch(e){if(e.code!=='CALL_EXCEPTION')throw e;}
    }
    assert.equal(await verify(proof(),abi.encode(['bool','bool'],[true,true])),false);
    assert.equal(await verify(proof(sigs,bind({index:3}))),false);
    assert.equal(await verify(proof(sigs,bind({opcode:2}))),false);
    for(const change of [{chain:1},{game:outsider.address},{task:ethers.id('unknown')},{tag:ethers.id('wrong-purpose')}])
      await assert.rejects(verify(proof(sigs,bind(change))));
    await assert.rejects(verify(proof(),decisions,verifier.connect(outsider)));
    const clone=await factory.deploy(game.address,profile,signers.map(s=>s.address),2);await clone.waitForDeployment();
    await assert.rejects(clone.registerContext(task,context,contextSigs));
  } finally {provider.destroy();await backend.disconnect();}
});
