import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const event = () => ({at:'2026-10-01T00:00:00.000Z',method:'GET',identity:{sub:'learner_fixture'}});

test('reads only the supplied event contract and does not mutate its input', () => {
  const original=event();
  Object.freeze(original.identity);Object.freeze(original);
  const result=readDetectionEvents([original]);
  assert.deepEqual(result,[event()]);
  assert.notEqual(result[0],original);assert.notEqual(result[0].identity,original.identity);
  result[0].identity.sub='other_fixture';
  assert.equal(original.identity.sub,'learner_fixture');
  assert.deepEqual(readDetectionEvents([]),[]);
});

test('reads pseudonymous subject, device, request type and verdict when supplied', () => {
  for(const decision of ['allow','deny','step_up']) {
    const input={...event(),deviceId:'0123456789abcdef',decision};
    assert.deepEqual(readDetectionEvents([input]),[input]);
    assert.deepEqual(detect([input]),{action:'observe'});
  }
});

test('missing device/verdict stay absent and client or inherited fields cannot supply them', () => {
  const input={...event(),headers:{deviceId:'0123456789abcdef',decision:'allow'},
    device:{id:'0123456789abcdef'},role:'instructor'};
  Object.setPrototypeOf(input,{deviceId:'0123456789abcdef',decision:'allow'});
  const [selected]=readDetectionEvents([input]);
  assert.deepEqual(selected,event());
  assert.equal(Object.hasOwn(selected,'deviceId'),false);
  assert.equal(Object.hasOwn(selected,'decision'),false);
});

test('never reads or copies content, credentials or names', () => {
  const input={...event(),deviceId:'0123456789abcdef',decision:'deny'};let touched=0;
  const unused=()=>{touched++;throw new Error('unexpected_private_field_read');};
  for(const key of ['body','content','token','password','name','realName','headers','owner_id'])
    Object.defineProperty(input,key,{enumerable:true,get:unused});
  for(const key of ['token','name','email','role','userId'])
    Object.defineProperty(input.identity,key,{enumerable:true,get:unused});
  assert.deepEqual(readDetectionEvents([input]),[{...event(),deviceId:'0123456789abcdef',decision:'deny'}]);
  assert.deepEqual(detect([input]),{action:'observe'});
  assert.equal(touched,0);
});

test('invalid optional metadata is rejected without coercion or fallback', () => {
  for(const deviceId of [null,undefined,123,'','0123456789ABCDEF','fixture_device',{}])
    assert.throws(()=>readDetectionEvents([{...event(),deviceId}]),
      {name:'TypeError',message:'invalid_detection_events'});
  for(const decision of [null,undefined,true,'ALLOW','block','approved',{}])
    assert.throws(()=>readDetectionEvents([{...event(),decision}]),
      {name:'TypeError',message:'invalid_detection_events'});
  for(const deviceRegistered of [null,undefined,'true',1,{}])
    assert.throws(()=>readDetectionEvents([{...event(),deviceRegistered}]),
      {name:'TypeError',message:'invalid_detection_events'});
});

test('rejects missing/invalid metadata without echoing an input value', () => {
  const invalid=[null,{},[null],[{}],Array(1),
    [{...event(),at:'2026-02-30T00:00:00.000Z'}],
    [{...event(),at:'invalid'}],[{...event(),method:'get'}],
    [{...event(),identity:{name:'fixture_name'}}],
    [{...event(),identity:{sub:'fixture@example.invalid'}}],
    [{...event(),identity:{sub:'fixture name'}}],
    [{...event(),identity:{sub:'가상 이름'}}],
    [{...event(),identity:{sub:'sb_'+'secret_'+'fixture'}}],
    [Object.create(event())]];
  for(const input of invalid)for(const read of [readDetectionEvents,detect])
    assert.throws(()=>read(input),{name:'TypeError',message:'invalid_detection_events'});
  const input=event();
  Object.defineProperty(input,'at',{get(){throw new Error('untrusted_accessor_message');}});
  assert.throws(()=>readDetectionEvents([input]),{name:'TypeError',message:'invalid_detection_events'});
});

test('events without network evidence remain observe even at high volume', () => {
  const inputs=Array.from({length:200},event);
  assert.equal(readDetectionEvents(inputs).length,200);
  assert.deepEqual(detect(inputs),{action:'observe'});
});

test('the input module still loads alone and performs no input logging', async () => {
  const source=readFileSync(new URL('../src/detect.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/^\s*import\b/m);
  assert.doesNotMatch(source,/\bconsole\s*\.|\b(?:writeFile|appendFile|fetch)\s*\(/);
  const standalone=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
  assert.deepEqual(standalone.readDetectionEvents([event()]),[event()]);
  const enriched={...event(),deviceId:'0123456789abcdef',decision:'allow'};
  assert.deepEqual(standalone.readDetectionEvents([enriched]),[enriched]);
  assert.deepEqual(standalone.detect([event()]),{action:'observe'});
});
