#!/usr/bin/env python3
"""Guarded edits in an isolated image tree. Never edit the local measured source.

The image adapter retains original owner authorization and canonical attester
validation. A changed source anchor fails the build instead of omitting a guard.
"""
import argparse
import hashlib
import json
from pathlib import Path

def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('distributed adapter source drift: '+old[:100])
    return source.replace(old,new)

def adapt(app):
    app=Path(app)
    campaign=app/'threshold-kms/campaign'
    changes={}
    def edit(rel, replacements, prefix=''):
        file=campaign/rel
        original=file.read_text()
        source=original
        for old,new in replacements: source=once(source,old,new)
        source=prefix+source
        key=str(file.relative_to(app))
        changes[key]={'sourceSha256':changes.get(key,{}).get('sourceSha256',hashlib.sha256(original.encode()).hexdigest()),
            'adaptedSha256':hashlib.sha256(source.encode()).hexdigest()}
        file.write_text(source)

    edit('common.mjs',[("export async function ownerRpc(body){const id=randomUUID();await atomic(`/owner-rpc/${id}.request`,body);const result=await waitFile(`/owner-rpc/${id}.response`);if(result.error)throw Error(result.error);return result.value;}",
        "export async function ownerRpc(body){return (await import('/app/distributed/hooks.mjs')).ownerRequest(body);}"),
        ('await fs.rename(tmp,file);}',
         "await fs.rename(tmp,file);if(file==='/exchange/complete.json')await (await import('/app/distributed/hooks.mjs')).completeRecipient();}"),
        ('export async function waitFile(file,seconds=14400){const deadline=',
         "export async function waitFile(file,seconds=14400){await (await import('/app/distributed/hooks.mjs')).waitRemoteFile(file,seconds);const deadline=")])
    edit('paired-linear.mjs',[
        ('export function prepareLinearBenchmark({inputs,...domain}){',
         'export function prepareLinearBenchmark({inputs,selectedIndices,...domain}){'),
        ('const admissions=vectors.map((vector,index)=>{',
         'const admissions=vectors.map((vector,index)=>{\n  if(selectedIndices && !selectedIndices.includes(index))return null;')])
    owner=(campaign/'owner.mjs').read_text()
    linear_refs='const recordReferences=linearRecordIds(selected,query),itemOwners=recordReferences.map(id=>owners[recordOwner(id)]);'
    nonlinear_refs='const recordReferences=qoeRecordIds(rows),itemOwners=recordReferences.map(id=>owners[recordOwner(id)]);'
    edit('owner.mjs',[
        ("import {runPublicWorker} from '../scripts/kms-public-worker.mjs';",
         "import {distributedEncrypt as runPublicWorker} from '/app/distributed/owner-fragments.mjs';\nimport {configuration} from '/app/distributed/client.mjs';\nconst localRole=await configuration();"),
        ("const wallets=(await json('/owner-identity/identities.json')).map((key,index)=>new ethers.Wallet(key,providers[index]));",
         "const wallets=Array.from({length:4},(_,index)=>index===localRole.ownerIndex?\n new ethers.Wallet(localRoleSigningKey,providers[index]):new ethers.VoidSigner(localRole.identities[`owner-${index+1}`],providers[index]));"),
        (linear_refs,''),
        ("const start=performance.now();\n   await runPublicWorker(binary,{action:'prepare',publicKey,evaluationKey,plan,values},'/owner/'+name);",
         linear_refs+"\n   const start=performance.now();\n   await runPublicWorker(binary,{action:'prepare',publicKey,evaluationKey,plan,values},'/owner/'+name,recordReferences.map(recordOwner));"),
        (nonlinear_refs,''),
        ("const start=performance.now(),publicDir=dir+'/public';",
         nonlinear_refs+"\n   const start=performance.now(),publicDir=dir+'/public';"),
        ("keyset:{keyId:keys.keyId,keyEpoch:keys.keyEpoch,mpcContext:keys.mpcContext,keysetDigest:keys.keysetDigest,...keys.keyDescriptor}},'/owner/'+name);",
         "keyset:{keyId:keys.keyId,keyEpoch:keys.keyEpoch,mpcContext:keys.mpcContext,keysetDigest:keys.keysetDigest,...keys.keyDescriptor}},'/owner/'+name,values.map((_,i)=>recordOwner(recordReferences[i%n])));"),
        ('async function handle(r){','async function handle(r){\n assert.equal(r.index,localRole.ownerIndex,"request addressed to another owner");'),
        ("assert.ok(cfg.pocPlan&&item.half==='linear');assert.equal(r.index,0);",
         "assert.ok(cfg.pocPlan&&item.half==='linear');assert.equal(r.index,localRole.ownerIndex);"),
        ('const signed=prepareLinearBenchmark({inputs,caseName:item.name,keysetDigest:keys.keysetDigest,chainId:cfg.chainId});',
         'const selectedIndices=item.owners.flatMap((address,i)=>address.toLowerCase()===wallet.address.toLowerCase()?[i]:[]);\n  const signed=prepareLinearBenchmark({inputs,selectedIndices,caseName:item.name,keysetDigest:keys.keysetDigest,chainId:cfg.chainId});'),
        ('await atomic(`/fixtures/${item.name}/benchmark-admissions.json`,signed);',
         'await atomic(`/fixtures/${item.name}/benchmark-owner-${localRole.ownerIndex}.json`,signed);'),
        ('return {path:`/fixtures/${item.name}/benchmark-admissions.json`};',
         'return {path:`/fixtures/${item.name}/benchmark-owner-${localRole.ownerIndex}.json`};')
    ],prefix="const localRoleSigningKey=(await (await import('node:fs/promises')).readFile('/identity/signing.hex','utf8')).trim();\n")
    edit('evaluate.mjs',[
        ("const mnemonic='test test test test test test test test test test test junk';\nconst signers=Array.from({length:8},(_,i)=>ethers.HDNodeWallet.fromPhrase(mnemonic,undefined,`m/44'/60'/0'/0/${i}`).connect(provider));",
         "const signers=await distributedSigners(provider);"),
        ("const result=await measuredJsonCommand({command,args,input,\n    outputDir,measurementId,role,purpose,executionScope:'controller-only-remote-fhe-excluded',\n    env:{...process.env,VCFHE_PUBLIC_WORKER_METRICS_FILE:publicMetricsFile}});",
         "const result=await participantMeasurement({role,purpose,input,outputDir,measurementId,game:game.game,taskId});")
    ],prefix="import {signers as distributedSigners,participantMeasurement} from '/app/distributed/hooks.mjs';\n")
    edit('policy-init.mjs',[("const wallet=ethers.HDNodeWallet.fromPhrase(mnemonic).connect(provider);",
        "const wallet=new ethers.Wallet(fs.readFileSync('/identity/signing.hex','utf8').trim(),provider);")])
    # The exact original compiler runs once at image build. Each core still
    # verifies deployed bytecode, constructor arguments and the fixed quorum.
    # The immutable cache has no request-controlled path or cold fallback.
    edit('workflow-auth.mjs',[("export function compileCanonicalWorkflowArtifacts(){\n if(!compiledPromise)compiledPromise=compileCanonicalWorkflowArtifactsOnce().catch(error=>{\n  compiledPromise=undefined;throw error;\n });\n return compiledPromise;\n}",
        "export function compileCanonicalWorkflowArtifacts(){\n if(!compiledPromise)compiledPromise=loadWorkflowArtifactCache({appRoot:vcFheRoot,\n  compilerVersions:{linear:linearSolc.version(),nonlinear:nonlinearSolc.version()},\n  resolveImport:resolveNonlinearSolidityImport}).catch(error=>{\n  compiledPromise=undefined;throw error;\n });\n return compiledPromise;\n}\nexport {compileCanonicalWorkflowArtifactsOnce as compileWorkflowArtifactsForImageBuild,\n resolveNonlinearSolidityImport as resolveWorkflowCompilerImport};")],
        prefix="import {loadWorkflowArtifactCache} from '/app/distributed/workflow-artifact-cache.mjs';\n")
    edit('poc_evidence.py',[("design = plan(cfg['half'])",
        "design = (distributed_plan(cfg['half']) if cfg.get('executionProfile') == 'gcp-four-hosts-role-local-v1' and cfg.get('distributedPlan') == 'distributed-three-full-v1' else plan(cfg['half']))")],
        prefix="import sys\nsys.path.insert(0, '/app/distributed')\nfrom experiment_plan import plan as distributed_plan\n")
    edit('paired.mjs',[
        ("import {createExecutionContext,runCanonicalBinary,detectCanonicalFault,hashJson} from './runtime/scripts/canonical-protocol.mjs';",
         "import {createExecutionContext,hashJson} from './runtime/scripts/canonical-protocol.mjs';\nimport {canonicalExecute as runCanonicalBinary,canonicalAudit as detectCanonicalFault,pairedLinear,linearAggregate} from '/app/distributed/hooks.mjs';\nimport {admitWork} from '/app/distributed/admission.mjs';"),
        ('for(const job of cfg.pocPlan.jobs){','for(const job of cfg.pocPlan.jobs){\n  await admitWork({phase:"paired",ordinal:job.ordinal});'),
        ('const gens=generators(signed.dimension),t=performance.now(),aggregate=aggregateVectors(vectors);operatorMs=performance.now()-t;',
         "const t=performance.now(),operatorResult=await linearAggregate(dir+'/coordinates.json');\n   const aggregate=operatorResult.aggregate.map(BigInt);operatorMs=performance.now()-t;"),
        ('const args={...signed,vectors,aggregate,generators:gens};\n   variants={proposed:()=>verifyProposal(args),baseline:()=>verifyBaseline(args)};',
         "const args={coordinates:dir+'/coordinates.json',admissions:dir+'/benchmark-admissions.json',aggregate};\n   variants={proposed:()=>pairedLinear('proposed',args),baseline:()=>pairedLinear('baseline',args)};")])
    linear=(campaign/'linear.mjs').read_text()
    start=linear.index('  let start=performance.now();const aggregate=Array(dimension).fill(0n);')
    end=linear.index("  await receipt('operator-stake'",start)
    edit('linear.mjs',[
        ("import {runPublicWorker} from './public-worker.mjs';",
         "import {normalizePublic as runPublicWorker,linearAggregate,pairedLinear,bindContract} from '/app/distributed/hooks.mjs';"),
        ("const deploymentReceipt=await receipt('linear-deploy',contract.deploymentTransaction());const tag=await contract.datasetTag();",
         "const deploymentReceipt=await receipt('linear-deploy',contract.deploymentTransaction());\n await bindContract('GroupedLinearVerification',deploymentReceipt.hash);const tag=await contract.datasetTag();"),
        (linear[start:end],"""  let start=performance.now();
  const computed=await linearAggregate(dir+'/coordinates.json',aggregateFile);
  const aggregate=computed.aggregate.map(BigInt),commitment=L.G1.fromAffine({x:BigInt(computed.commitment[0]),y:BigInt(computed.commitment[1])});
  aggregateDigest=computed.aggregateDigest;metrics.aggregateMs=performance.now()-start;
  await fs.writeFile(dir+'/full-admissions.json',JSON.stringify({datasetTag:tag,dimension,admissions}),{flag:'wx'});
  start=performance.now();
  await pairedLinear('baseline',{coordinates:dir+'/coordinates.json',admissions:dir+'/full-admissions.json',aggregate});
  metrics.fullReaggregationMs=performance.now()-start;
"""),
        ("await fs.writeFile(aggregateFile,Buffer.concat(aggregate.map(L.be32)),{flag:'wx'});",
         "assert.deepEqual(await fs.readFile(aggregateFile),Buffer.concat(aggregate.map(L.be32)));")])
    edit('runtime/scripts/canonical-game-driver.mjs',[
        ('const identities = Array.from({ length: 3 }, () => ethers.Wallet.createRandom());',
         'const identities = await distributedAdjudicators();'),
        ('const created = new Map();',
         'const created = new Map();\n  const prepareSealedBountyAudit = args => distributedPrepareAudit({...args,context,publicDir,\n    operatorDir:created.get(args.taskId).operatorDir,caseName:path.basename(workDir)});'),
        ('await fs.writeFile(f, identities[i].privateKey, { mode: 0o600, flag: "wx" }); identityFiles.push(f);',
         'identityFiles.push(`role:adjudicator-${i+1}`);'),
        ('await record(`deploy:${name}`, c.deploymentTransaction()); return c;',
         'await record(`deploy:${name}`, c.deploymentTransaction());\n    await distributedBindContract(name,c.deploymentTransaction().hash); return c;'),
        ('const challenger = byAddress(auditors, (await game.getAssignedAuditorsForLeaf(taskId, index))[0]);',
         'const challenger = byAddress(auditors, (await game.getAssignedAuditors(taskId))[0]);\n    assert.ok(await game.isAuditorAssignedToLeaf(taskId, challenger.address, index));')
    ],prefix="import {adjudicators as distributedAdjudicators,bindContract as distributedBindContract,prepareAudit as distributedPrepareAudit} from '/app/distributed/hooks.mjs';\n")
    # Admission runs between complete cases, never inside a dispute or release.
    edit('evaluate.mjs',[
        ('if(cfg.pocPlan)await runPairs(cfg,prepared);',
         "await (await import('/app/distributed/admission.mjs')).verifyBytes(cfg,prepared);\n if(cfg.pocPlan)await runPairs(cfg,prepared);"),
        ('for(const item of prepared.cases.filter(c=>!casePlan||c.fullCase)){',
         "for(const item of prepared.cases.filter(c=>!casePlan||c.fullCase)){\n  await (await import('/app/distributed/admission.mjs')).admitWork({phase:'full',caseName:item.name});")])
    # Each participant has its own public FHE worker and filesystem queue.
    # The Rust worker is a sibling process, outside the measured JS controller's
    # descendants. This retains the existing disjoint CPU accounting exactly.
    target=campaign/'runtime/scripts/canonical-protocol.mjs'
    source=target.read_text()
    old="/app/threshold-kms/campaign/public-worker.mjs"
    if old not in source: raise ValueError('canonical worker import drift')
    original=source
    target.write_text(source)
    changes[str(target.relative_to(app))]={'sourceSha256':hashlib.sha256(original.encode()).hexdigest(),
        'adaptedSha256':hashlib.sha256(source.encode()).hexdigest()}
    mapping=campaign/'runtime/source-map.json'
    value=json.loads(mapping.read_text())
    for name in ('canonical-protocol.mjs','canonical-game-driver.mjs'):
        value[name]['compiledViewSha256']=hashlib.sha256((campaign/'runtime/scripts'/name).read_bytes()).hexdigest()
    mapping.write_text(json.dumps(value,indent=2)+'\n')
    record={'schema':'vcfhe-distributed-runtime-adapter-v1','files':changes,
        'protocolRulesChanged':False,'localSourceEdited':False,'requiresExecutionValidation':True}
    (campaign/'distributed-adapter.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app',type=Path,required=True)
    print(json.dumps(adapt(p.parse_args().app),indent=2))
