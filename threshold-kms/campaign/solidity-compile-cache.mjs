// Reuse only compilation output, never deployments or protocol execution.
// Callers must reread their sources before supplying this self-contained input.
export function createSolidityCompileCache(compiler) {
 if(typeof compiler?.compile!=='function'||typeof compiler?.version!=='function')
  throw Error('a Solidity compiler and its version are required');
 let cachedKey,cachedOutput;
 return input=>{
  if(!input?.sources||!Object.values(input.sources).every(source=>
   typeof source?.content==='string'&&!Object.hasOwn(source,'urls')))
   throw Error('cached Solidity compilation requires inline source contents');
  const encoded=JSON.stringify(input),key=JSON.stringify([compiler.version(),encoded]);
  if(key===cachedKey)return JSON.parse(cachedOutput);
  const output=compiler.compile(encoded),parsed=JSON.parse(output);
  const errors=(parsed.errors??[]).filter(error=>error.severity==='error');
  if(errors.length)throw Error(`solc failed:\n${errors.map(error=>error.formattedMessage??error.message).join('\n')}`);
  // Strings are immutable. Parsing on a hit prevents a caller's mutations
  // from changing the ABI or bytecode returned for the following deployment.
  cachedKey=key;cachedOutput=output;
  return parsed;
 };
}
