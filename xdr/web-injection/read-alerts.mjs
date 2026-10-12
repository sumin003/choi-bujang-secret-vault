import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const redacted = '[REDACTED]';

// Discard the whole field if it may contain credentials; never print raw alerts.
function safeText(value) {
  if (typeof value !== 'string') return null;
  const suspicious = /(?:sb_(?:secret|publishable)_|(?:sk|pk)_(?:live|test)_|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN[^\n]*PRIVATE KEY|\bBearer\s+\S+|(?:password|passwd|pwd|secret|token|api[_ -]?key|비밀번호|비밀키|토큰)\s*["']?\s*[:=]\s*\S+|https?:\/\/[^\s/]+:[^\s/]+@|[A-Za-z0-9_+/=-]{32,})/i;
  return suspicious.test(value) ? redacted : value.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('웹 주입 경보 형식이 올바르지 않습니다.');
  }
  return fixture.alerts.map(alert => {
    const timestamp = alert?.timestamp;
    const srcip = alert?.data?.srcip;
    const level = alert?.rule?.level;
    return {
      timestamp: typeof timestamp === 'string'
        && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(timestamp)
        && Number.isFinite(Date.parse(timestamp)) ? timestamp : null,
      srcip: typeof srcip === 'string' && isIP(srcip) ? srcip : null,
      srcuser: safeText(alert?.data?.srcuser),
      level: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
      description: safeText(alert?.rule?.description),
    };
  });
}

export async function readAlerts() {
  let fixture;
  try {
    fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  } catch {
    // Parser errors can contain the original text, so do not expose them.
    throw new Error('경보 파일을 읽을 수 없습니다.');
  }
  return extractAlerts(fixture);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await readAlerts(), null, 2));
  } catch {
    console.error('경보를 읽거나 추출하지 못했습니다.');
    process.exitCode = 1;
  }
}
