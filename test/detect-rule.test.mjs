import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const START=Date.UTC(2026,9,1);
const observe={action:'observe'};
const proposal={action:'propose_revocation',reasonCode:'burst_read',subject:'learner_fixture',deviceId:'0123456789abcdef'};
function reads(count,{owner='learner_fixture',network='unusual',source='judge_fixture',interval=2000,method='GET',
  deviceId='0123456789abcdef',registered=true}={}) {
  return Array.from({length:count},(_,i)=>({at:new Date(START+i*interval).toISOString(),
    method,identity:{sub:owner},signals:{source,network},deviceId,deviceRegistered:registered}));
}

test('suspicion requires both unusual-network evidence and excessive reads',()=>{
  assert.deepEqual(detect(reads(200,{network:'usual'})),observe);
  assert.deepEqual(detect(reads(30)),observe);
  assert.deepEqual(detect(reads(121)),proposal);
  assert.deepEqual(detect(reads(200).map(e=>({...e,signals:{region:'other_fixture_region'}}))),observe);
});

test('120 is normal; 121 within an inclusive ten-minute window is suspicious',()=>{
  assert.deepEqual(detect(reads(120)),observe);
  assert.deepEqual(detect(reads(121,{interval:5000})),proposal);
  assert.deepEqual(detect(reads(121,{interval:5001})),observe);
  assert.deepEqual(detect(reads(200,{interval:7000})),observe);
});

test('unordered events and a later burst are checked with sliding windows',()=>{
  assert.deepEqual(detect(reads(121).reverse()),proposal);
  const early=reads(20,{interval:7000});
  const later=reads(121).map(e=>({...e,at:new Date(Date.parse(e.at)+20*60*1000).toISOString()}));
  assert.deepEqual(detect([...early,...later].reverse()),proposal);
});

test('users and usual-network reads never inflate the unusual-network count',()=>{
  assert.deepEqual(detect([...reads(100),...reads(100,{owner:'other_fixture'})]),observe);
  assert.deepEqual(detect([...reads(120),...reads(100,{network:'usual'})]),observe);
  const other=reads(121,{owner:'other_fixture'});
  assert.deepEqual(detect(other),{...proposal,subject:'other_fixture'});
});

test('missing, unknown or unverified network evidence cannot become suspicious',()=>{
  for(const signals of [undefined,{network:'unusual'},{source:'judge_fixture'},
    {source:'none',network:'unusual'},{source:'judge_fixture',network:'unknown'}]) {
    const input=reads(200).map(e=>{
      const {signals:unused,...basic}=e;
      return signals===undefined?basic:{...basic,signals};
    });
    assert.deepEqual(detect(input),observe);
  }
  const input=reads(200,{network:'usual'}).map(e=>({...e,
    network:'unusual',headers:{network:'unusual',source:'judge_fixture'}}));
  assert.deepEqual(detect(input),observe);
});

test('only GET requests are counted and calls do not retain prior events',()=>{
  assert.deepEqual(detect(reads(200,{method:'POST'})),observe);
  assert.deepEqual(detect(reads(60)),observe);
  assert.deepEqual(detect(reads(60)),observe);
  assert.deepEqual(detect(reads(120)),observe);
});

test('network input is copied selectively; region and private fields are never read',()=>{
  let accessed=0;
  const unused=()=>{accessed++;throw Error('unexpected_private_field_read');};
  const input=reads(121);
  for(const e of input) {
    for(const key of ['token','body','name'])Object.defineProperty(e,key,{enumerable:true,get:unused});
    for(const key of ['region','token','body','name'])Object.defineProperty(e.signals,key,{enumerable:true,get:unused});
    Object.freeze(e.identity);Object.freeze(e.signals);Object.freeze(e);
  }
  const selected=readDetectionEvents(input);
  assert.equal(selected.length,121);
  assert.deepEqual(selected[0].signals,{source:'judge_fixture',network:'unusual'});
  assert.deepEqual(detect(input),proposal);
  assert.equal(accessed,0);
});

test('invalid signals produce only the fixed input error',()=>{
  for(const signals of [null,[],{source:'client_header',network:'unusual'},
    {source:'judge_fixture',network:{value:'unusual'}}])
    assert.throws(()=>detect([{...reads(1)[0],signals}]),
      {name:'TypeError',message:'invalid_detection_events'});
});

test('a proposal targets exactly one independently suspicious confirmed device',()=>{
  const otherDevice='fedcba9876543210';
  const normal=reads(30,{deviceId:otherDevice,network:'usual'});
  const output=detect([...normal,...reads(121)]);
  assert.deepEqual(output,proposal);
  assert.equal(typeof output.deviceId,'string');
  assert.deepEqual(Object.keys(output).sort(),['action','deviceId','reasonCode','subject']);
  const both=detect([...reads(121),...reads(121,{deviceId:otherDevice})]);
  assert.equal(both.action,'propose_revocation');assert.equal(typeof both.deviceId,'string');
  assert.ok(['0123456789abcdef',otherDevice].includes(both.deviceId));
});

test('unknown or unconfirmed devices preserve suspicion but cannot trigger a proposal',()=>{
  const alert={action:'alert',reasonCode:'burst_read',subject:'learner_fixture'};
  for(const field of ['deviceId','deviceRegistered']) {
    const inputs=reads(121).map(e=>{const selected={...e};delete selected[field];return selected;});
    assert.deepEqual(detect(inputs),alert);
  }
  assert.deepEqual(detect(reads(121,{registered:false})),alert);
  const forged=reads(121).map(({deviceRegistered,...e})=>({...e,headers:{deviceRegistered:true}}));
  assert.deepEqual(detect(forged),alert);
});

test('different devices cannot be combined into a single revocation target',()=>{
  assert.deepEqual(detect([...reads(80),...reads(80,{deviceId:'fedcba9876543210'})]),
    {action:'alert',reasonCode:'burst_read',subject:'learner_fixture'});
  const mixed=[...reads(120),...reads(100,{registered:false})];
  assert.equal(detect(mixed).action,'alert');
});
