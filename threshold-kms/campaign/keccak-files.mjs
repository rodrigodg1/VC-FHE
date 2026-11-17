#!/usr/bin/env node
// Hash an explicit JSON list of files with Ethereum Keccak-256.  The Python
// evidence gate verifies path containment and the SHA-256 seal before calling
// this helper; this process exists only to avoid the prohibitively slow pure
// Python permutation on the large KMS keys and campaign binary.
import fs from 'node:fs/promises';
import {createRequire} from 'node:module';

const require=createRequire(new URL('../../fhe-pod/package.json',import.meta.url));
const {ethers}=require('ethers');
let text='';
for await(const chunk of process.stdin)text+=chunk;
const paths=JSON.parse(text);
if(!Array.isArray(paths)||paths.some(value=>typeof value!=='string'))throw Error('expected a JSON file-name array');
const result=[];
for(const file of paths)result.push(ethers.keccak256(await fs.readFile(file)));
process.stdout.write(JSON.stringify(result));
