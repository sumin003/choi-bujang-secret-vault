const form = document.querySelector('#login-form');
const email = document.querySelector('#login-email');
const password = document.querySelector('#login-password');
const loginButton = document.querySelector('#login-button');
const logoutButton = document.querySelector('#logout-button');
const state = document.querySelector('#auth-state');
const message = document.querySelector('#auth-message');
const connectionStatus = document.querySelector('#connection-status');
const devicePanel = document.querySelector('#device-panel');
const deviceStatus = document.querySelector('#device-approval-status');
const deviceMessage = document.querySelector('#device-message');
const registerDevice = document.querySelector('#register-device');
const requestDevice = document.querySelector('#request-device');
const checkDeviceButton = document.querySelector('#check-device');
const vault = document.querySelector('#protected-vault');
let deviceVersion = 0;
let deviceRequestId = null;
let deviceBusy = false;
let busy = false;
let signedIn = false;
const list = document.querySelector('#notes');
let notesVersion = 0;

const editor = document.querySelector('#note-editor');
const noteForm = document.querySelector('#note-form');
const noteId = document.querySelector('#note-id');
const noteTitle = document.querySelector('#note-title');
const noteBody = document.querySelector('#note-body');
const noteMessage = document.querySelector('#note-message');
const saveNote = document.querySelector('#save-note');
const newNote = document.querySelector('#new-note');
const loadNote = document.querySelector('#load-note');
const refreshNotes = document.querySelector('#refresh-notes');
let currentSession = null;
let editingId = null;
let writing = false;

function lockVault(label = '기기 승인 상태: 미확인. 로그인 후 서버에서 확인합니다.') {
  ++deviceVersion;
  ++notesVersion;
  vault.hidden = true;
  editor.hidden = true;
  resetEditor();
  const item = document.createElement('li');
  item.textContent = '기기 승인 후 자료를 확인할 수 있습니다.';
  list.replaceChildren(item);
  deviceStatus.textContent = label;
}

async function deviceFetch(body) {
  const token = currentSession?.access_token;
  if (!token) throw new Error('로그인 후 이용해 주세요.');
  const headers = { Authorization: 'Bearer ' + token };
  if (deviceRequestId) headers['X-Device-Request-Id'] = deviceRequestId;
  if (body) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/device', { method: body ? 'POST' : 'GET', headers,
    body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
  if (token !== currentSession?.access_token) throw new Error('로그인 상태가 변경되었습니다.');
  const result = await response.json();
  if (!response.ok) {
    if (result?.error === 'DEVICE_BOUND_KEY_REQUIRED')
      throw new Error('다른 기기에도 동기화되는 패스키는 사용할 수 없습니다. 기기에 묶인 인증 수단을 사용해 주세요.');
    throw new Error('기기 확인을 완료하지 못했습니다. 서버 설정과 연결을 확인해 주세요.');
  }
  return result;
}

async function refreshDeviceStatus(session) {
  const version = deviceVersion;
  try {
    const result = await deviceFetch();
    if (version !== deviceVersion || session !== currentSession) return;
    if (result.status === 'approved') {
      deviceStatus.textContent = '기기 승인 상태: 서버 확인 완료.';
      deviceMessage.textContent = '승인된 기기로 확인했습니다. 자료실을 열었습니다.';
      vault.hidden = false;
      editor.hidden = false;
      void loadNotes(session);
    } else {
      deviceStatus.textContent = result.status === 'pending'
        ? '기기 승인 상태: 승인 대기 중.'
        : result.status === 'approved_needs_verification'
          ? '기기 승인 상태: 승인됨. 인증 수단으로 다시 확인해 주세요.'
          : result.status === 'rejected' ? '기기 승인 상태: 거부됨.'
            : '기기 승인 상태: 미확인. 승인 요청을 진행해 주세요.';
    }
  } catch (error) {
    if (version === deviceVersion && session === currentSession)
      deviceStatus.textContent = '기기 승인 상태: 서버에서 확인할 수 없습니다. 자료 접근을 중단했습니다.';
  }
}

function decodeBase64Url(value) {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  let binary = '';
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function proveDevice() {
  if (deviceBusy || !currentSession) return;
  deviceBusy = true;
  requestDevice.disabled = true;
  checkDeviceButton.disabled = true;
  deviceMessage.textContent = '기기 인증 수단을 확인하는 중입니다.';
  try {
    if (!window.PublicKeyCredential || !navigator.credentials?.get)
      throw new Error('이 브라우저에서는 기기 인증 수단을 사용할 수 없습니다.');
    const started = await deviceFetch({ action: 'start' });
    const options = started.options;
    const publicKey = { ...options, challenge: decodeBase64Url(options.challenge),
      userVerification: 'required' };
    if (options.allowCredentials) publicKey.allowCredentials = options.allowCredentials.map(item => ({
      ...item, id: decodeBase64Url(item.id),
    }));
    const signed = await navigator.credentials.get({ publicKey });
    if (!signed || signed.type !== 'public-key') throw new Error('기기 확인이 취소되었습니다.');
    const id = encodeBase64Url(signed.rawId);
    const credential = { id, rawId: id, type: 'public-key',
      response: {
        authenticatorData: encodeBase64Url(signed.response.authenticatorData),
        clientDataJSON: encodeBase64Url(signed.response.clientDataJSON),
        signature: encodeBase64Url(signed.response.signature),
        userHandle: signed.response.userHandle ? encodeBase64Url(signed.response.userHandle) : null,
      }, clientExtensionResults: signed.getClientExtensionResults(),
    };
    const result = await deviceFetch({ action: 'verify', challengeId: started.challengeId, credential });
    deviceRequestId = result.requestId;
    if (result.status === 'approved') {
      deviceMessage.textContent = '서버가 승인된 기기를 확인했습니다.';
    } else if (result.status === 'pending') {
      deviceMessage.textContent = '승인 요청이 접수되었습니다. 요청 번호: '
        + result.requestId.slice(0, 12) + '. 승인 뒤 “승인 결과 확인”을 눌러 주세요.';
    } else {
      deviceMessage.textContent = '승인 요청이 거부되었습니다.';
    }
    lockVault();
    await refreshDeviceStatus(currentSession);
  } catch (error) {
    deviceMessage.textContent = error.message || '기기 인증을 완료하지 못했습니다.';
  } finally {
    deviceBusy = false;
    requestDevice.disabled = false;
    checkDeviceButton.disabled = false;
  }
}

function renderConnectionStatus() {
  if (!connectionStatus) return;
  connectionStatus.textContent = navigator.onLine
    ? '네트워크가 온라인으로 표시됩니다. 서버 접속 여부는 요청 결과로 확인합니다.'
    : '네트워크가 오프라인으로 표시됩니다. 다시 연결한 뒤 요청해 주세요.';
}

window.addEventListener('online', renderConnectionStatus);
window.addEventListener('offline', renderConnectionStatus);
renderConnectionStatus();

function noteReason(status) {
  return ({ 400: 'UUID와 제목·내용을 확인해 주세요.', 401: '다시 로그인해 주세요.',
    404: '메모가 없거나 이미 삭제되었습니다.', 409: '이미 사용 중인 UUID입니다.',
    415: '요청 형식이 올바르지 않습니다.' })[status]
    ?? '메모 요청을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.';
}

function resetEditor() {
  editingId = null;
  noteForm.reset();
  saveNote.textContent = '메모 추가';
}

async function requestNote(path, method = 'GET', input) {
  const token = currentSession?.access_token;
  if (!token) throw new Error('로그인 후 이용해 주세요.');
  const headers = { Authorization: 'Bearer ' + token };
  if (input) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { method, headers, cache: 'no-store',
    body: input ? JSON.stringify(input) : undefined });
  if (token !== currentSession?.access_token) throw new Error('로그인 상태가 변경되었습니다.');
  if (!response.ok) {
    if (response.status === 403) {
      const details = await response.clone().json().catch(() => null);
      if (details?.error === 'DEVICE_APPROVAL_REQUIRED') {
        lockVault('기기 승인 상태: 다시 확인이 필요합니다.');
        throw new Error('기기 승인을 다시 확인해 주세요.');
      }
    }
    throw new Error(noteReason(response.status));
  }
  return response.status === 204 ? null : response.json();
}

async function editNote(id) {
  try {
    const note = await requestNote('/api/notes/' + encodeURIComponent(id));
    editingId = note.id;
    noteId.value = note.id;
    noteTitle.value = note.title;
    noteBody.value = note.body;
    saveNote.textContent = '수정 저장';
    noteMessage.textContent = '메모를 불러왔습니다.';
    noteTitle.focus();
  } catch (error) { noteMessage.textContent = error.message; }
}

async function deleteNote(id) {
  if (writing || !confirm('이 가상 메모를 삭제할까요?')) return;
  writing = true;
  try {
    await requestNote('/api/notes/' + encodeURIComponent(id), 'DELETE');
    if (editingId === id) resetEditor();
    noteMessage.textContent = '삭제했습니다.';
    await loadNotes(currentSession);
  } catch (error) { noteMessage.textContent = error.message; }
  finally { writing = false; }
}

async function loadNotes(session) {
  const version = ++notesVersion;
  const show = text => {
    const item = document.createElement('li');
    item.textContent = text;
    list.replaceChildren(item);
  };
  show(session ? '가상 자료를 불러오는 중입니다.' : '로그인 후 자료를 확인할 수 있습니다.');
  if (!session?.access_token) return;
  try {
    const notes = await requestNote('/api/notes');
    if (version !== notesVersion) return;
    if (!Array.isArray(notes)) throw new Error('자료 형식이 올바르지 않습니다.');
    if (!notes.length) { show('내 메모가 없습니다. 새 가상 메모를 추가해 주세요.'); return; }
    list.replaceChildren(...notes.map(note => {
      const item = document.createElement('li');
      const title = document.createElement('strong');
      const content = document.createElement('span');
      const id = document.createElement('small');
      const actions = document.createElement('div');
      title.textContent = note.title;
      content.textContent = note.body;
      id.textContent = 'ID: ' + note.id;
      actions.className = 'note-actions';
      for (const [label, action] of [['수정', () => editNote(note.id)], ['삭제', () => deleteNote(note.id)]]) {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = label;
        button.addEventListener('click', action);
        actions.append(button);
      }
      item.append(title, content, id, actions);
      return item;
    }));
  } catch (error) {
    if (version === notesVersion) show(error.message);
  }
}

noteForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (writing) return;
  writing = true;
  saveNote.disabled = true;
  try {
    const input = { title: noteTitle.value, body: noteBody.value };
    if (!editingId && noteId.value.trim()) input.id = noteId.value.trim();
    const result = await requestNote(editingId ? '/api/notes/' + encodeURIComponent(editingId) : '/api/notes',
      editingId ? 'PUT' : 'POST', input);
    noteMessage.textContent = (editingId ? '수정했습니다. ID: ' : '추가했습니다. ID: ') + result.id;
    resetEditor();
    await loadNotes(currentSession);
  } catch (error) { noteMessage.textContent = error.message; }
  finally { writing = false; saveNote.disabled = false; }
});
newNote.addEventListener('click', () => {
  resetEditor(); noteMessage.textContent = ''; noteTitle.focus();
});
loadNote.addEventListener('click', () => {
  if (!writing) void editNote(noteId.value.trim());
});
refreshNotes.addEventListener('click', () => void loadNotes(currentSession));

function render(session) {
  currentSession = session;
  signedIn = Boolean(session?.user);
  lockVault(signedIn ? '기기 승인 상태: 서버에서 확인하는 중입니다.'
    : '기기 승인 상태: 미확인. 로그인 후 서버에서 확인합니다.');
  if (!signedIn) { deviceRequestId = null; deviceMessage.textContent = ''; noteMessage.textContent = ''; }
  state.textContent = signedIn ? '로그인되어 있습니다.' : '로그아웃 상태입니다.';
  form.hidden = signedIn;
  logoutButton.hidden = !signedIn;
  devicePanel.hidden = !signedIn;
  loginButton.disabled = busy;
  logoutButton.disabled = busy;
  if (signedIn) password.value = '';
  if (signedIn) void refreshDeviceStatus(session);
}

function reason(error) {
  const reasons = {
    invalid_credentials: '이메일 또는 비밀번호가 올바르지 않습니다.',
    email_not_confirmed: '이메일 인증을 완료한 뒤 로그인해 주세요.',
    user_banned: '이 계정은 로그인이 제한되어 있습니다.',
    over_request_rate_limit: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',
    over_email_send_rate_limit: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',
    provider_disabled: '이메일·비밀번호 로그인이 비활성화되어 있습니다.',
    email_provider_disabled: '이메일 로그인이 비활성화되어 있습니다.',
    unexpected_failure: '인증 서버 오류입니다. 잠시 후 다시 시도해 주세요.',
  };
  if (reasons[error?.code]) return reasons[error.code];
  if (error?.status === 429) return '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.';
  return '인증 요청을 완료하지 못했습니다. 네트워크와 Supabase 인증 설정을 확인해 주세요.';
}

try {
  const { createClient } = await import('https://esm.sh/@supabase/supabase-js@2.117.2');
  const supabase = createClient(location.origin, 'server-auth-relay', {
    auth: { storageKey: 'sb-cysbomadvuwrqsteohuq-auth-token', experimental: { passkey: true } },
    global: {
      fetch: (input, init) => {
        const url = new URL(typeof input === 'string' ? input : input.url ?? String(input));
        const action = url.pathname.replace('/auth/v1/', '');
        if (url.origin !== location.origin || !['token', 'logout', 'user',
          'passkeys/registration/options', 'passkeys/registration/verify'].includes(action))
          throw new Error('지원하지 않는 인증 요청입니다.');
        const target = new URL('/api/auth', location.origin);
        target.searchParams.set('action', action);
        if (url.searchParams.has('grant_type'))
          target.searchParams.set('grant_type', url.searchParams.get('grant_type'));
        const headers = new Headers(init?.headers);
        headers.delete('apikey');
        if (headers.get('Authorization') === 'Bearer server-auth-relay')
          headers.delete('Authorization');
        return fetch(target, { ...init, headers, cache: 'no-store', redirect: 'error' });
      },
    },
  });
  registerDevice.addEventListener('click', async () => {
    if (deviceBusy || !currentSession) return;
    deviceBusy = true;
    registerDevice.disabled = true;
    deviceMessage.textContent = '기기용 패스키를 등록하는 중입니다.';
    try {
      if (!window.PublicKeyCredential) throw new Error('이 브라우저에서는 패스키를 사용할 수 없습니다.');
      const { error } = await supabase.auth.registerPasskey();
      if (error) throw new Error('패스키 등록을 완료하지 못했습니다. 인증 서버의 패스키 설정을 확인해 주세요.');
      deviceMessage.textContent = '패스키를 등록했습니다. 이제 기기 승인을 요청해 주세요.';
    } catch (error) { deviceMessage.textContent = error.message || '패스키 등록을 완료하지 못했습니다.'; }
    finally { deviceBusy = false; registerDevice.disabled = false; }
  });
  requestDevice.addEventListener('click', proveDevice);
  checkDeviceButton.addEventListener('click', proveDevice);
  // The SDK manages credentials, sessions and refresh tokens.
  // The server verifies the SDK token before returning any notes.
  supabase.auth.onAuthStateChange((_event, session) => render(session));
  const { data, error } = await supabase.auth.getSession();
  if (error) message.textContent = reason(error);
  render(data?.session ?? null);

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    loginButton.disabled = true;
    message.textContent = '로그인 중입니다.';
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: email.value.trim(),
        password: password.value,
      });
      if (error) {
        message.textContent = reason(error);
      } else {
        render(data.session);
        message.textContent = '로그인했습니다.';
        logoutButton.focus();
      }
    } catch {
      message.textContent = '서버에 연결할 수 없습니다. 네트워크 상태를 확인해 주세요.';
    } finally {
      password.value = '';
      busy = false;
      loginButton.disabled = false;
      logoutButton.disabled = false;
    }
  });

  logoutButton.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    logoutButton.disabled = true;
    message.textContent = '로그아웃 중입니다.';
    try {
      const { error } = await supabase.auth.signOut({ scope: 'local' });
      if (error) message.textContent = reason(error);
      else {
        render(null);
        message.textContent = '로그아웃했습니다.';
        email.focus();
      }
    } catch {
      message.textContent = '로그아웃 요청을 완료하지 못했습니다. 네트워크 상태를 확인해 주세요.';
    } finally {
      busy = false;
      loginButton.disabled = false;
      logoutButton.disabled = false;
    }
  });
} catch {
  state.textContent = '로그인 기능을 불러오지 못했습니다.';
  message.textContent = '네트워크 상태를 확인한 뒤 새로고침해 주세요.';
  loginButton.disabled = true;
  logoutButton.disabled = true;
}
