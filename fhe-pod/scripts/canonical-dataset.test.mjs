import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const source=bs=>{
  const lines=fs.readFileSync(new URL(`../../data/MOS_${bs}_Driver_PRB_10.csv`,import.meta.url),'utf8').trim().split(/\r?\n/);
  const names=lines.shift().split(',');
  return lines.map((line,i)=>{
    const row=Object.fromEntries(line.split(',').map((value,j)=>[names[j],value]));
    const mos=Math.round(Number(row.MOS_3000kbps)*1000),lat=Number(row.Latitude),lon=Number(row.Longitude);
    return{row:i+1,mos,cell:Math.floor((lat+90)/0.01)*36000+Math.floor((lon+180)/0.01)};
  }).filter(r=>Number.isFinite(r.mos)&&r.mos>0);
};
test('all 32 selected panel records match independently parsed MOS and geographic source rows',()=>{
  const f=JSON.parse(fs.readFileSync(new URL('./regulatory-fixtures.json',import.meta.url),'utf8'));
  const bs1=source('BS_1'),bs4=source('BS_4');
  assert.equal(bs1.length,f.dataset.validRows);assert.equal(bs4.length,f.dataset.validRowsBs4);
  const global=f.panels.bs1_3000kbps_compliance_16;
  for(let i=0;i<16;i++){
    const r=bs1[i*Math.floor(bs1.length/16)];
    assert.equal(global.rowNumbers[i],r.row);assert.equal(global.valuesMilli[i],r.mos);
  }
  const regional=f.panels.bs1_bs4_3000kbps_regional_16;
  for(let i=0;i<16;i++){
    const src=i<8?bs1:bs4,r=src[(i%8)*Math.floor(src.length/8)],actual=regional.sessions[i];
    assert.equal(actual.rowNumber,r.row);assert.equal(actual.mosMilli,r.mos);assert.equal(actual.cellIndex,r.cell);
  }
});
