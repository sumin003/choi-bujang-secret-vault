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
    const response = await fetch('/api/notes', {
      cache: 'no-store',
      headers: { Authorization: 'Bearer ' + session.access_token },
    });
    if (version !== notesVersion) return;
    if (response.status === 401) {
      show('로그인 인증에 실패했습니다. 다시 로그인해 주세요.');
      return;
    }
    if (!response.ok) throw new Error();
    const data = await response.json();
    if (version !== notesVersion) return;
    if (!Array.isArray(data.notes)) throw new Error();
    list.replaceChildren(...data.notes.map(note => {
      const item = document.createElement('li');
      const title = document.createElement('strong');
      const content = document.createElement('span');
      title.textContent = note.title;
      content.textContent = note.content;
      item.append(title, content);
      return item;
    }));
  } catch {
    if (version === notesVersion) show('가상 자료를 읽을 수 없습니다. 잠시 후 다시 시도해 주세요.');
  }
}

function render(session) {
  signedIn = Boolean(session?.user);
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
  const supabase = createClient(
    'https://cysbomadvuwrqsteohuq.supabase.co',
    'sb_publishable_gs5uFk92hjznNpp4O8VoOQ_qeLgPeMb',
  );
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
