-- Upgrade existing browser requests; preserve records, notes and prior audit data.
alter table public.learning_browser_registrations
  add column if not exists request_id uuid not null default gen_random_uuid(),
  add column if not exists operator_reviewed_at timestamptz;
create unique index if not exists learning_browser_registration_request_id
  on public.learning_browser_registrations(request_id);
alter table public.learning_browser_registrations
  drop constraint if exists learning_browser_registrations_reason_check;
alter table public.learning_browser_registrations
  add constraint learning_browser_registrations_reason_check
  check (reason in ('requested','verified_recent_password_login','revoked','operator_approved','operator_rejected'));

create table if not exists public.learning_browser_registration_audit (
  id bigint generated always as identity primary key,
  request_id uuid not null references public.learning_browser_registrations(request_id),
  previous_status text not null,
  next_status text not null,
  reviewed_at timestamptz not null,
  actor text not null
);
alter table public.learning_browser_registration_audit enable row level security;
revoke all on table public.learning_browser_registration_audit from public, anon, authenticated, service_role;
revoke all on sequence public.learning_browser_registration_audit_id_seq from public, anon, authenticated, service_role;

alter table public.learning_browser_registrations alter column status set default 'pending';
alter table public.learning_browser_registrations alter column reason set default 'requested';

-- The application cannot specify approval status, reason or review timestamps.
revoke all on table public.learning_browser_registrations from public, anon, authenticated, service_role;
grant select on table public.learning_browser_registrations to service_role;
grant insert (browser_hash,user_id,requested_at,expires_at)
  on public.learning_browser_registrations to service_role;

create or replace function public.require_pending_browser_request()
returns trigger language plpgsql security invoker set search_path = public, pg_temp as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('vault_browser_pending:' || new.user_id::text, 0));
  if (select count(*) from public.learning_browser_registrations r
      where r.user_id=new.user_id and r.status='pending' and r.expires_at > clock_timestamp()) >= 5 then
    raise exception 'pending_request_limit' using errcode='P0001';
  end if;
  if new.status <> 'pending' or new.reason <> 'requested'
    or new.approved_at is not null or new.operator_reviewed_at is not null then
    raise exception 'pending_request_only';
  end if;
  return new;
end;
$$;
revoke all on function public.require_pending_browser_request() from public, anon, authenticated, service_role;
drop trigger if exists pending_browser_request_only on public.learning_browser_registrations;
create trigger pending_browser_request_only before insert on public.learning_browser_registrations
  for each row execute function public.require_pending_browser_request();

-- SQL Editor's database operator only. No public/application approval endpoint.
create or replace function public.review_learning_browser_registration(target_request uuid, approve boolean)
returns table(request_id uuid, status text, reviewed_at timestamptz)
language plpgsql security invoker set search_path = public, pg_temp as $$
declare
  existing public.learning_browser_registrations%rowtype;
  reviewed timestamptz := clock_timestamp();
  next_state text;
begin
  if approve is null then raise exception 'invalid_review'; end if;
  select r.* into existing from public.learning_browser_registrations r
    where r.request_id = target_request for update;
  if not found or existing.expires_at <= reviewed then raise exception 'request_missing_or_expired'; end if;
  if approve and existing.status <> 'pending' then raise exception 'request_not_pending'; end if;
  next_state := case when approve then 'approved' else 'rejected' end;
  update public.learning_browser_registrations r
    set status=next_state, operator_reviewed_at=reviewed,
      approved_at=case when approve then reviewed else null end,
      reason=case when approve then 'operator_approved' else 'operator_rejected' end
    where r.request_id=target_request;
  insert into public.learning_browser_registration_audit(request_id,previous_status,next_status,reviewed_at,actor)
    values(target_request,existing.status,next_state,reviewed,current_user);
  return query select target_request,next_state,reviewed;
end;
$$;
revoke all on function public.review_learning_browser_registration(uuid,boolean)
  from public, anon, authenticated, service_role;
