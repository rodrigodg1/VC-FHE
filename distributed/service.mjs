// Participant lifetime. Persistent private state is never reset on restart.
import fs from 'node:fs/promises';
import {spawn} from 'node:child_process';
const cfg=JSON.parse(await fs.readFile('/config/role.json','utf8'));
if(['operator','auditor','adjudicator','coordinator'].includes(cfg.role)){
  // Pin contract artifacts locally before timed tasks. A certificate worker
  // reads these files and still verifies the actual deployment on chain.
  await (await import('/app/threshold-kms/campaign/runtime/scripts/evm-lib.mjs')).compileContracts();
}
const children=new Set();
function start(command,args){
  const child=spawn(command,args,{stdio:'inherit',env:process.env});children.add(child);
  child.completion=new Promise(resolve=>child.once('close',(code,signal)=>resolve([code,signal])));
  child.on('error',error=>{console.error(error);process.exitCode=1;});
  child.on('exit',code=>{children.delete(child);if(code)process.exitCode=code;});
  return child;
}
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{
  for(const child of children)child.kill(signal);
  process.exitCode=1;
});
const agent=start(process.execPath,['/app/distributed/agent.mjs']);
agent.completion.then(()=>{for(const child of children)child.kill('SIGTERM');});
if(['operator','auditor','adjudicator'].includes(cfg.role)){
  const worker=start(process.execPath,['/app/threshold-kms/campaign/worker.mjs']);
  worker.completion.then(()=>{agent.kill('SIGTERM');process.exitCode=1;});
}
if(['owner','recipient','coordinator'].includes(cfg.role)){
  const deadline=Date.now()+cfg.timeoutSeconds*1000;
  while(true){
    try{await fs.access('/config/start-role.json');break;}
    catch(e){if(e.code!=='ENOENT')throw e;}
    if(agent.exitCode!==null||Date.now()>deadline)throw Error('participant start gate unavailable');
    await new Promise(r=>setTimeout(r,1000));
  }
  const role=cfg.role==='coordinator'?'evaluate':cfg.role;
  const application=start('python3',['/app/threshold-kms/campaign/container.py',role]);
  const [code]=await application.completion;
  await fs.writeFile('/reports/participant-exit.json',JSON.stringify({node:cfg.node,role:cfg.role,exitCode:code}),{flag:'wx'});
  // Keep the public endpoint alive for read-only evidence collection. Do not
  // automatically restart computation, key setup, or release requests.
}
await agent.completion;
