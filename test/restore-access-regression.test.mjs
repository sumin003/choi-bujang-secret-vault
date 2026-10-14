import test from 'node:test';
import assert from 'node:assert/strict';
import {runRestoreAccessChecks} from '../scripts/restore-access-check.mjs';

test('자료·정책 복원 뒤 자기 요청은 허용되고 이전에 거부된 다른 소유자 요청은 다시 거부한다',async()=>{
  const result=await runRestoreAccessChecks();
  assert.deepEqual(result.data,{aOwnAllowed:true,bToADenied:true,bOwnRestoredReadable:true});
  assert.equal(result.policy.aOwnAllowed,true);
  assert.equal(result.policy.bToADenied,true);
  assert.equal(result.policy.itemsRestored,true);
});
