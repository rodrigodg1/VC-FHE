// Bounded retries of an absent latest-block READ only. Never replay transactions,
// MPC or output releases, invent a timestamp, or move a protocol deadline.
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const validBlock=b=>b&&Number.isSafeInteger(b.number)&&b.number>=0&&
 Number.isSafeInteger(b.timestamp)&&b.timestamp>=0;

export async function readLatestBlock(query,{maxAttempts=20,retryDelayMs=250,timeoutMs=5000,
 now=()=>performance.now(),sleep=delay,onRetry=()=>{}}={}){
 if(!Number.isSafeInteger(maxAttempts)||maxAttempts<1||!Number.isFinite(timeoutMs)||timeoutMs<=0||
    !Number.isFinite(retryDelayMs)||retryDelayMs<0)throw new Error('invalid latest-block read limits');
 const deadline=now()+timeoutMs;
 for(let attempt=1;attempt<=maxAttempts;attempt++){
  const remaining=deadline-now();if(remaining<=0)break;
  let timer;
  const block=await Promise.race([Promise.resolve().then(query),new Promise((_,reject)=>{
   timer=setTimeout(()=>reject(new Error('latest-block read timed out; no transaction retried')),remaining);
  })]).finally(()=>clearTimeout(timer));
  if(now()>deadline)throw new Error('latest-block read timed out; no transaction retried');
  if(block!==null){if(!validBlock(block))throw new Error('malformed latest-block response');return block;}
  onRetry({attempt,reason:'null-latest-block'});
  if(attempt<maxAttempts&&now()<deadline)await sleep(Math.min(retryDelayMs,deadline-now()));
 }
 throw new Error('latest block unavailable within bounded read retries; no transaction retried');
}

export async function waitForChainSeconds(readBlock,seconds,{pollMs=1000,stallTimeoutMs=60000,
 now=()=>performance.now(),sleep=delay}={}){
 if(!Number.isSafeInteger(seconds)||seconds<0||!Number.isFinite(pollMs)||pollMs<=0||
    !Number.isFinite(stallTimeoutMs)||stallTimeoutMs<=0)throw new Error('invalid chain wait limits');
 const start=await readBlock();if(!validBlock(start))throw new Error('invalid initial chain block');
 const target=start.timestamp+seconds;let previous=start,lastProgress=now();
 if(!Number.isSafeInteger(target))throw new Error('invalid chain timestamp target');
 while(true){
  const block=await readBlock();if(!validBlock(block))throw new Error('invalid chain block');
  if(block.number<previous.number||block.timestamp<previous.timestamp)throw new Error('chain regressed during wait');
  if(block.timestamp>target)return {startBlock:start.number,targetTimestamp:target,observedBlock:block.number,observedTimestamp:block.timestamp};
  if(block.timestamp>previous.timestamp)lastProgress=now();
  if(now()-lastProgress>=stallTimeoutMs)throw new Error('chain timestamp stalled; no deadline extended');
  previous=block;await sleep(pollMs);
 }
}

export async function waitForChainTimestamp(readBlock,targetTimestamp,{pollMs=1000,stallTimeoutMs=60000,
 now=()=>performance.now(),sleep=delay}={}){
 if(!Number.isSafeInteger(targetTimestamp)||targetTimestamp<0||!Number.isFinite(pollMs)||pollMs<=0||
    !Number.isFinite(stallTimeoutMs)||stallTimeoutMs<=0)throw new Error('invalid absolute chain wait limits');
 const start=await readBlock();if(!validBlock(start))throw new Error('invalid initial chain block');
 let previous=start,lastProgress=now();
 if(start.timestamp>=targetTimestamp)return {startBlock:start.number,targetTimestamp,
  observedBlock:start.number,observedTimestamp:start.timestamp};
 while(true){
  const block=await readBlock();if(!validBlock(block))throw new Error('invalid chain block');
  if(block.number<previous.number||block.timestamp<previous.timestamp)throw new Error('chain regressed during wait');
  if(block.timestamp>=targetTimestamp)return {startBlock:start.number,targetTimestamp,
   observedBlock:block.number,observedTimestamp:block.timestamp};
  if(block.timestamp>previous.timestamp)lastProgress=now();
  if(now()-lastProgress>=stallTimeoutMs)throw new Error('chain timestamp stalled; no deadline extended');
  previous=block;await sleep(pollMs);
 }
}
