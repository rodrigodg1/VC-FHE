import test from "node:test";
import assert from "node:assert/strict";
import {admitLinearBounds} from "./linear-output-policy.mjs";
test("linear admission enforces the unsigned decoder and aggregate noise regime",()=>{
 assert.deepEqual(admitLinearBounds(0,Array.from({length:33},()=>({min:"1",max:"5"}))),{minimum:33n,maximum:165n});
 assert.throws(()=>admitLinearBounds(0,Array.from({length:34},()=>({min:"1",max:"5"}))),/regime/);
 assert.throws(()=>admitLinearBounds(1,[{min:"1",max:"5"},{min:"1",max:"5"}]),/unsigned/);
 assert.deepEqual(admitLinearBounds(1,[{min:"20",max:"20"},{min:"3",max:"5"}]),{minimum:15n,maximum:17n});
 assert.throws(()=>admitLinearBounds(0,[{min:"500",max:"500"},{min:"12",max:"12"}]),/regime/);
});
