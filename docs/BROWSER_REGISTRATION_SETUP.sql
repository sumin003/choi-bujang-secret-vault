-- Browser registrations only; no device private keys, JWTs or raw cookies.
create table public.learning_browser_registrations (
  browser_hash text primary key check (browser_hash ~ '^[a-f0-9]{64}$'),
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null check (status in ('pending','approved','rejected')),
  requested_at timestamptz not null,
  expires_at timestamptz not null,
  approved_at timestamptz,
  reason text not null check (reason in ('requested','verified_recent_password_login','revoked')),
  check (expires_at > requested_at),
  check (status <> 'approved' or approved_at is not null)
);
alter table public.learning_browser_registrations enable row level security;
revoke all on table public.learning_browser_registrations from public, anon, authenticated, service_role;
grant select on table public.learning_browser_registrations to service_role;
-- Next run BROWSER_OPERATOR_APPROVAL.sql. Do not deploy before that upgrade.
