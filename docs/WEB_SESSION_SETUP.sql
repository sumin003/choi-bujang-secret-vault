-- Server-only, encrypted Supabase tokens and hashes of opaque session cookies.
create table if not exists public.learning_web_sessions (
  session_hash text primary key check (session_hash ~ '^[a-f0-9]{64}$'),
  user_id uuid not null references auth.users(id) on delete cascade,
  sealed_tokens text not null check (length(sealed_tokens) <= 32768),
  expires_at timestamptz not null,
  version integer not null default 1 check (version > 0)
);
create index if not exists learning_web_sessions_expires_idx
  on public.learning_web_sessions(expires_at);
alter table public.learning_web_sessions enable row level security;
revoke all on table public.learning_web_sessions from public, anon, authenticated, service_role;
grant select, insert, update, delete on table public.learning_web_sessions to service_role;
