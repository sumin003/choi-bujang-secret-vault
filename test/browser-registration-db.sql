begin;
do $test$
declare
  account uuid;
  target uuid;
  fixture_hash text := encode(extensions.gen_random_bytes(32),'hex');
  verified record;
  pending_count integer;
  i integer;
  rejected boolean;
begin
  select u.id into account from auth.users u
    where u.email in ('test@test.com','test2@test.com')
      and (select count(*) from public.learning_browser_registrations r where r.user_id=u.id and r.status='pending' and r.expires_at > now()) < 5
    limit 1;
  if account is null then raise exception 'test_account_or_capacity_missing'; end if;
  execute 'set local role service_role';
  insert into public.learning_browser_registrations(browser_hash,user_id,requested_at,expires_at)
    values(fixture_hash,account,clock_timestamp(),clock_timestamp()+interval '1 day')
    returning request_id into target;
  select status,reason,approved_at into verified from public.learning_browser_registrations where request_id=target;
  if verified.status <> 'pending' or verified.reason <> 'requested' or verified.approved_at is not null then
    raise exception 'request_auto_approved';
  end if;
  rejected := false;
  begin
    update public.learning_browser_registrations set status='approved' where request_id=target;
  exception when insufficient_privilege then rejected := true;
  end;
  if not rejected then raise exception 'server_can_modify_status'; end if;
  rejected := false;
  begin
    perform * from public.review_learning_browser_registration(target,true);
  exception when insufficient_privilege then rejected := true;
  end;
  if not rejected then raise exception 'server_can_call_review'; end if;
  rejected := false;
  begin
    insert into public.learning_browser_registrations(browser_hash,user_id,requested_at,expires_at,status)
      values(encode(extensions.gen_random_bytes(32),'hex'),account,clock_timestamp(),clock_timestamp()+interval '1 day','approved');
  exception when insufficient_privilege then rejected := true;
  end;
  if not rejected then raise exception 'server_can_insert_status'; end if;
  execute 'reset role';
  perform * from public.review_learning_browser_registration(target,true);
  select status,reason,approved_at,operator_reviewed_at into verified from public.learning_browser_registrations where request_id=target;
  if verified.status <> 'approved' or verified.reason <> 'operator_approved' or verified.approved_at <> verified.operator_reviewed_at then
    raise exception 'operator_approval_failed';
  end if;
  perform * from public.review_learning_browser_registration(target,false);
  select status,reason,approved_at into verified from public.learning_browser_registrations where request_id=target;
  if verified.status <> 'rejected' or verified.reason <> 'operator_rejected' or verified.approved_at is not null then
    raise exception 'operator_revocation_failed';
  end if;
  if (select count(*) from public.learning_browser_registration_audit where request_id=target) <> 2 then
    raise exception 'audit_failed';
  end if;
  execute 'set local role service_role';
  select count(*) into pending_count from public.learning_browser_registrations where user_id=account and status='pending' and expires_at > clock_timestamp();
  if pending_count < 5 then
    for i in 1..(5-pending_count) loop
      insert into public.learning_browser_registrations(browser_hash,user_id,requested_at,expires_at)
        values(encode(extensions.gen_random_bytes(32),'hex'),account,clock_timestamp(),clock_timestamp()+interval '1 day');
    end loop;
  end if;
  rejected := false;
  begin
    insert into public.learning_browser_registrations(browser_hash,user_id,requested_at,expires_at)
      values(encode(extensions.gen_random_bytes(32),'hex'),account,clock_timestamp(),clock_timestamp()+interval '1 day');
  exception when raise_exception then
    if sqlerrm = 'pending_request_limit' then rejected := true; else raise; end if;
  end;
  if not rejected then raise exception 'pending_limit_failed'; end if;
  execute 'reset role';
end;
$test$;
select true as pending_only, true as application_approval_denied, true as operator_approval_and_revocation, true as audit_written, true as sixth_pending_request_denied, true as rolled_back_after_check;
rollback;
