// Image-build reuse of the original Solidity compiler outputs. No RPC inputs
// select a cache, alter its closure or request a compilation fallback.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {constants as fsConstants} from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const SCHEMA='vcfhe-immutable-workflow-artifacts-v1';
const CACHE='distributed/workflow-artifacts.json';
const SEAL=CACHE+'.seal.json';
const EVIDENCE='threshold-kms/campaign/build-evidence';
const OWN_DIRS=['BN254-Signatures/contract','threshold-kms/contracts','fhe-pod/contracts/src'];
const FIXED=['threshold-kms/campaign/workflow-auth.mjs','threshold-kms/campaign/nonlinear-profile.mjs',
  'distributed/workflow-artifact-cache.mjs','BN254-Signatures/package.json',
  'BN254-Signatures/package-lock.json','fhe-pod/package.json','fhe-pod/package-lock.json'];
const CONTRACTS=['GroupedLinearVerification','ObjectiveMicroVerifier','CanonicalBountyFHEDisputeGame',
  'BountyTraceAvailability','CanonicalFHEDisputeGame','AuthenticatedTraceAvailability',
  'CanonicalLeafVerifier','ReleasePolicyRegistry'];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const exec=promisify(execFile);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const fail=message=>{throw Error('immutable workflow artifact cache: '+message);};
function relative(root,file){
  const name=path.relative(root,path.resolve(file)).split(path.sep).join('/');
  if(!name||name.startsWith('../')||path.isAbsolute(name)||name.includes('\0'))fail('input outside image source closure');
  return name;
}
function inputPath(root,name){
  if(typeof name!=='string'||path.posix.normalize(name)!==name||name.startsWith('/')||
    name==='..'||name.startsWith('../')||name.includes('\0'))fail('invalid input path');
  return path.join(root,name);
}
async function plainFile(file){
  const s=await fs.lstat(file);
  if(!s.isFile()||s.isSymbolicLink()||await fs.realpath(file)!==path.resolve(file))fail('input is not a regular image file');
  return fs.readFile(file);
}
async function ownSolidity(root){
  const result=[];
  async function visit(file){
    for(const entry of (await fs.readdir(file,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){
      const child=path.join(file,entry.name);
      if(entry.isDirectory())await visit(child);
      else if(entry.name.endsWith('.sol')){
        if(!entry.isFile())fail('Solidity source is not a regular image file');
        result.push(relative(root,child));
      }
    }
  }
  for(const name of OWN_DIRS)await visit(inputPath(root,name));
  return result.sort();
}
function compilers(root){
  const linear=createRequire(path.join(root,'BN254-Signatures/package.json'));
  const nonlinear=createRequire(path.join(root,'fhe-pod/package.json'));
  return {linear:linear('solc'),nonlinear:nonlinear('solc'),require:linear,
    entries:[linear.resolve('solc'),nonlinear.resolve('solc')],
    files:[linear.resolve('solc/package.json'),nonlinear.resolve('solc/package.json'),
      linear.resolve('solc'),nonlinear.resolve('solc'),
      linear.resolve('solc/soljson.js'),nonlinear.resolve('solc/soljson.js')]};
}
function compilerDependencies(c,root){
  const found=new Set(),visited=new Set();
  function visit(module){
    if(!module||visited.has(module))return;
    visited.add(module);
    if(module.filename&&path.isAbsolute(module.filename))found.add(relative(root,module.filename));
    for(const child of module.children??[])visit(child);
  }
  for(const entry of c.entries){
    const module=c.require.cache[entry];
    if(!module)fail('compiler module graph unavailable');
    visit(module);
  }
  return [...found].sort();
}
function versions(c){return {linear:c.linear.version(),nonlinear:c.nonlinear.version()};}
function freeze(value){
  if(object(value)||Array.isArray(value)){for(const child of Object.values(value))freeze(child);Object.freeze(value);}
  return value;
}
function checkArtifacts(artifacts,compilerVersions){
  if(!object(artifacts)||JSON.stringify(Object.keys(artifacts).sort())!==JSON.stringify([...CONTRACTS,'NonlinearSourceNames'].sort()))fail('unexpected artifact set');
  if(!Array.isArray(artifacts.NonlinearSourceNames)||!artifacts.NonlinearSourceNames.length||
    artifacts.NonlinearSourceNames.some(n=>typeof n!=='string'||!n.endsWith('.sol')))fail('invalid Solidity source names');
  for(const name of CONTRACTS){
    const a=artifacts[name],expected=['GroupedLinearVerification','ReleasePolicyRegistry'].includes(name)?compilerVersions.linear:compilerVersions.nonlinear;
    if(!object(a)||a.contractName!==name||typeof a.sourceName!=='string'||a.compilerVersion!==expected||
      !object(a.settings)||!Array.isArray(a.abi)||!object(a.immutableReferences)||
      !/^0x(?:[a-fA-F0-9]{2})+$/.test(a.bytecode)||!/^0x(?:[a-fA-F0-9]{2})+$/.test(a.deployedBytecode))fail('invalid compiler artifact: '+name);
  }
}

export async function loadWorkflowArtifactCache({appRoot,compilerVersions,resolveImport}){
  const root=await fs.realpath(appRoot),cacheFile=inputPath(root,CACHE),sealFile=inputPath(root,SEAL);
  const [bytes,sealBytes]=await Promise.all([plainFile(cacheFile),plainFile(sealFile)]);
  for(const file of [cacheFile,sealFile])if((await fs.stat(file)).mode&0o222)fail('cache anchor must be read-only');
  const seal=JSON.parse(sealBytes);
  if(!object(seal)||JSON.stringify(Object.keys(seal).sort())!==JSON.stringify(['cacheSha256','schema'])||
    seal.schema!==SCHEMA+'-seal'||!digest(seal.cacheSha256)||sha(bytes)!==seal.cacheSha256)fail('cache seal mismatch');
  const cache=JSON.parse(bytes);
  if(!object(cache)||cache.schema!==SCHEMA||!object(cache.compilerVersions)||
    JSON.stringify(cache.compilerVersions)!==JSON.stringify(compilerVersions)||!object(cache.sourceFiles)||
    !Array.isArray(cache.ownSolidityFiles)||!object(cache.transitiveImports))fail('invalid cache or compiler version mismatch');
  if(JSON.stringify(Object.keys(cache).sort())!==JSON.stringify(['schema','compilerVersions','sourceFiles','ownSolidityFiles','transitiveImports','artifacts'].sort()))fail('unexpected cache fields');
  const c=compilers(root);
  if(JSON.stringify(versions(c))!==JSON.stringify(compilerVersions))fail('installed compiler version changed');
  const actual=await ownSolidity(root);
  if(JSON.stringify(actual)!==JSON.stringify(cache.ownSolidityFiles))fail('Solidity source inventory changed');
  const dependencies=compilerDependencies(c,root);
  const mandatory=[...FIXED,...actual,...c.files.map(p=>relative(root,p)),...dependencies];
  if(mandatory.some(name=>!Object.hasOwn(cache.sourceFiles,name)))fail('incomplete source/compiler closure');
  for(const [name,expected] of Object.entries(cache.sourceFiles)){
    if(!digest(expected)||sha(await plainFile(inputPath(root,name)))!==expected)fail('source/compiler input changed: '+name);
  }
  for(const [name,expected] of Object.entries(cache.transitiveImports)){
    if(typeof name!=='string'||!name||name.includes('\0')||!digest(expected))fail('invalid import closure');
    const value=resolveImport(name);
    if(typeof value?.contents!=='string'||sha(value.contents)!==expected)fail('Solidity import changed: '+name);
  }
  checkArtifacts(cache.artifacts,compilerVersions);
  return freeze(cache.artifacts);
}

export async function buildWorkflowArtifactCache(appRoot){
  const root=await fs.realpath(appRoot),c=compilers(root);
  const module=await import(pathToFileURL(path.join(root,'threshold-kms/campaign/workflow-auth.mjs')));
  if(typeof module.compileWorkflowArtifactsForImageBuild!=='function'||typeof module.resolveWorkflowCompilerImport!=='function')fail('missing guarded image-build exports');
  const imports={},restore=[];
  // Observe the exact original compiler calls. Inputs, settings, callbacks and
  // return values are not replaced or synthesized.
  for(const compiler of new Set([c.linear,c.nonlinear])){
    const original=compiler.compile;
    compiler.compile=function(input,callbacks){
      const callback=callbacks?.import;
      const observed=callback?{...callbacks,import:name=>{
        const value=callback(name);
        if(typeof value?.contents==='string'){
          const h=sha(value.contents);if(imports[name]&&imports[name]!==h)fail('import changed during compilation');imports[name]=h;
        }
        return value;
      }}:callbacks;
      return original.call(this,input,observed);
    };
    restore.push(()=>{compiler.compile=original;});
  }
  let artifacts;
  try{artifacts=await module.compileWorkflowArtifactsForImageBuild();}
  finally{for(const original of restore)original();}
  const compilerVersions=versions(c);checkArtifacts(artifacts,compilerVersions);
  const ownSolidityFiles=await ownSolidity(root);
  const dependencies=compilerDependencies(c,root);
  const names=[...new Set([...FIXED,...ownSolidityFiles,...dependencies,...c.files.map(p=>relative(root,p))])].sort();
  const sourceFiles={};for(const name of names)sourceFiles[name]=sha(await plainFile(inputPath(root,name)));
  const cache={schema:SCHEMA,compilerVersions,ownSolidityFiles,sourceFiles,transitiveImports:imports,artifacts};
  const bytes=Buffer.from(JSON.stringify(cache)+'\n'),cacheSha256=sha(bytes);
  await fs.mkdir(path.dirname(inputPath(root,CACHE)),{recursive:true});
  await fs.writeFile(inputPath(root,CACHE),bytes,{flag:'wx',mode:0o444});
  await fs.writeFile(inputPath(root,SEAL),JSON.stringify({schema:SCHEMA+'-seal',cacheSha256})+'\n',{flag:'wx',mode:0o444});
  // The installed-file inventory hashes the runtime copies. Preserve identical
  // copies in the existing evidence directory collected and sealed by the run.
  await fs.mkdir(inputPath(root,EVIDENCE),{recursive:true});
  for(const name of [CACHE,SEAL]){
    const target=path.join(inputPath(root,EVIDENCE),path.basename(name));
    await fs.copyFile(inputPath(root,name),target,fsConstants.COPYFILE_EXCL);
    await fs.chmod(target,0o444);
  }
  const loaded=await loadWorkflowArtifactCache({appRoot:root,compilerVersions,resolveImport:module.resolveWorkflowCompilerImport});
  assert.deepStrictEqual(loaded,artifacts,'cached artifacts differ from the original compiler result');
  // A fresh process imports the actual runtime wrapper. This catches a closure
  // that only succeeds because the build process already loaded dependencies.
  const check=`import {compileCanonicalWorkflowArtifacts} from ${JSON.stringify(pathToFileURL(path.join(root,'threshold-kms/campaign/workflow-auth.mjs')).href)};`+
    `import {createHash} from 'node:crypto';const value=await compileCanonicalWorkflowArtifacts();`+
    `process.stdout.write(createHash('sha256').update(JSON.stringify(value)).digest('hex'));`;
  const fresh=await exec(process.execPath,['--input-type=module','-e',check],{timeout:120_000,maxBuffer:64*1024});
  assert.equal(fresh.stdout,sha(JSON.stringify(artifacts)),'fresh-process cached artifacts differ from the original compiler result');
  return {schema:SCHEMA,cacheSha256,artifactCount:CONTRACTS.length,sourceFileCount:names.length,
    transitiveImportCount:Object.keys(imports).length,freshProcessValidated:true};
}
