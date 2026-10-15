-- Run in the learning project's Supabase SQL Editor before deploying the
-- device-gated API. No browser role may read or change approval records.
create table if not exists public.learning_device_approvals (
  credential_hash text primary key check (credential_hash ~ '^[a-f0-9]{64}$'),
  user_id uuid not null references auth.users (id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  constraint approved_after_review check (status <> 'approved' or reviewed_at is not null)
);

create index if not exists learning_device_approvals_user_idx
  on public.learning_device_approvals (user_id);

alter table public.learning_device_approvals enable row level security;
revoke all on table public.learning_device_approvals from public, anon, authenticated;
grant select, insert, update on table public.learning_device_approvals to service_role;

-- Review a pending request in the official SQL Editor. Verify the account and
-- request through an independent trusted channel before running an UPDATE:
-- select user_id, left(credential_hash, 12) as request_number, requested_at
--   from public.learning_device_approvals where status = 'pending';
-- update public.learning_device_approvals
--   set status = 'approved', reviewed_at = now()
--   where user_id = '<verified user UUID>'
--     and credential_hash = '<the pending request hash>' and status = 'pending';
-- The browser can submit a request, but it cannot perform this review.
