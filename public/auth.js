const form = document.querySelector('#login-form');
const email = document.querySelector('#login-email');
const password = document.querySelector('#login-password');
const loginButton = document.querySelector('#login-button');
const logoutButton = document.querySelector('#logout-button');
const state = document.querySelector('#auth-state');
const message = document.querySelector('#auth-message');
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
  if (!response.ok) throw new Error(noteReason(response.status));
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
  editor.hidden = !signedIn;
  if (!signedIn) { resetEditor(); noteMessage.textContent = ''; }
  state.textContent = signedIn ? '로그인되어 있습니다.' : '로그아웃 상태입니다.';
  form.hidden = signedIn;
  logoutButton.hidden = !signedIn;
  loginButton.disabled = busy;
  logoutButton.disabled = busy;
  if (signedIn) password.value = '';
  void loadNotes(session);
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
    auth: { storageKey: 'sb-cysbomadvuwrqsteohuq-auth-token' },
    global: {
      fetch: (input, init) => {
        const url = new URL(typeof input === 'string' ? input : input.url ?? String(input));
        const action = url.pathname.replace('/auth/v1/', '');
        if (url.origin !== location.origin || !['token', 'logout', 'user'].includes(action))
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
