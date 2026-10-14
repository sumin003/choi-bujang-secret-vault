-- Admin-only integration test. Supply only the verified test account B UUID.
-- All sample rows, copies, audit additions and temporary permission changes
-- are rolled back in a PL/pgSQL subtransaction; no note contents are returned.
create or replace function learning_backup.verify_note_restore_b(p_test_owner uuid)
returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare
  test_note uuid := gen_random_uuid();
  good_copy uuid := gen_random_uuid();
  bad_copy uuid := gen_random_uuid();
  pending_copy uuid := gen_random_uuid();
  row_id bigint;
  sample public.learning_notes%rowtype;
  content_hash text;
  plan jsonb;
  result jsonb;
  before_notes text;
  before_audit text;
  after_notes text;
  after_audit text;
  old_audit_ids uuid[];
  bad_hash_blocked boolean := false;
  wrong_owner_blocked boolean := false;
  pending_blocked boolean := false;
  stale_blocked boolean := false;
  updated boolean := false;
  recreated boolean := false;
  audit_rollback boolean := false;
  others_preserved boolean := false;
  audit_preserved boolean := false;
  server_role_used boolean := false;
begin
  if p_test_owner is null or not exists(select 1 from auth.users where id=p_test_owner)
    then raise exception 'TEST_B_ACCOUNT_NOT_FOUND'; end if;
  select md5(coalesce(jsonb_agg(to_jsonb(n) order by n.id)::text,'[]')) into before_notes
    from public.learning_notes n;
  select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.event_id)::text,'[]')),
    coalesce(array_agg(a.event_id),'{}'::uuid[]) into before_audit,old_audit_ids
    from learning_backup.note_restore_audit a;
  begin
    -- Explicit unused ID avoids changing the live serial sequence in this test.
    select coalesce(min(id),0)-1 into row_id from public.learning_notes;
    insert into public.learning_notes(id,note_id,owner_id,title,content)
      overriding system value
      values(row_id,test_note,p_test_owner,md5(gen_random_uuid()::text),gen_random_uuid()::text)
      returning * into sample;
    content_hash := learning_backup.note_hash(sample.note_id,sample.owner_id,sample.title,sample.content);
    insert into learning_backup.note_copies(backup_id,note_id,original_id,owner_id,title,content,
      original_created_at,content_hash,verified_at)
      values(good_copy,test_note,row_id,p_test_owner,sample.title,sample.content,sample.created_at,content_hash,clock_timestamp()),
        (pending_copy,test_note,row_id,p_test_owner,sample.title,sample.content,sample.created_at,content_hash,null);

    -- A purported verified copy with altered bytes must also fail, and disappear
    -- when this expected exception rolls back its inner subtransaction.
    begin
      insert into learning_backup.note_copies(backup_id,note_id,original_id,owner_id,title,content,
        original_created_at,content_hash,verified_at)
        values(bad_copy,test_note,row_id,p_test_owner,sample.title,sample.content,sample.created_at,repeat('0',64),clock_timestamp());
      perform set_config('role','service_role',true);
      perform public.learning_restore_note(p_test_owner,test_note,bad_copy,repeat('0',64),content_hash);
      raise exception 'BAD_COPY_ACCEPTED';
    exception when raise_exception then
      bad_hash_blocked := sqlerrm='RESTORE_HASH_MISMATCH';
    end;

    perform set_config('role','service_role',true);
    server_role_used := current_user='service_role';
    begin
      perform public.learning_restore_note(gen_random_uuid(),test_note,good_copy,content_hash,content_hash);
      raise exception 'WRONG_OWNER_ACCEPTED';
    exception when raise_exception then wrong_owner_blocked := sqlerrm='RESTORE_SOURCE_NOT_FOUND'; end;
    begin
      perform public.learning_restore_note(p_test_owner,test_note,pending_copy,content_hash,content_hash);
      raise exception 'UNVERIFIED_COPY_ACCEPTED';
    exception when raise_exception then pending_blocked := sqlerrm='RESTORE_SOURCE_UNVERIFIED'; end;

    plan := public.learning_preview_note_restore(p_test_owner,test_note);
    update public.learning_notes set content=gen_random_uuid()::text where note_id=test_note and owner_id=p_test_owner;
    begin
      perform public.learning_restore_note(p_test_owner,test_note,good_copy,content_hash,plan->>'currentSha256');
      raise exception 'STALE_PREVIEW_ACCEPTED';
    exception when raise_exception then stale_blocked := sqlerrm='RESTORE_STATE_CHANGED'; end;
    plan := public.learning_preview_note_restore(p_test_owner,test_note);
    result := public.learning_restore_note(p_test_owner,test_note,good_copy,content_hash,plan->>'currentSha256');
    updated := (result->>'restored')::boolean and exists(select 1 from public.learning_notes n
      where n.note_id=test_note and n.id=row_id and n.owner_id=p_test_owner
        and learning_backup.note_hash(n.note_id,n.owner_id,n.title,n.content)=content_hash);

    delete from public.learning_notes where note_id=test_note and owner_id=p_test_owner;
    plan := public.learning_preview_note_restore(p_test_owner,test_note);
    if plan->>'currentSha256'<>'missing' then raise exception 'MISSING_NOTE_PREVIEW_FAILED'; end if;
    result := public.learning_restore_note(p_test_owner,test_note,good_copy,content_hash,'missing');
    recreated := (result->>'restored')::boolean and exists(select 1 from public.learning_notes n
      where n.note_id=test_note and n.id=row_id and n.owner_id=p_test_owner and n.created_at=sample.created_at
        and learning_backup.note_hash(n.note_id,n.owner_id,n.title,n.content)=content_hash);

    -- Prove the row update rolls back if its audit insert cannot succeed.
    update public.learning_notes set content=gen_random_uuid()::text where note_id=test_note and owner_id=p_test_owner;
    plan := public.learning_preview_note_restore(p_test_owner,test_note);
    perform set_config('role','postgres',true);
    begin
      revoke insert on table learning_backup.note_restore_audit from service_role;
      perform set_config('role','service_role',true);
      perform public.learning_restore_note(p_test_owner,test_note,good_copy,content_hash,plan->>'currentSha256');
      raise exception 'MISSING_AUDIT_ACCEPTED';
    exception when insufficient_privilege then audit_rollback := true; end;
    audit_rollback := audit_rollback and exists(select 1 from public.learning_notes n where n.note_id=test_note
      and learning_backup.note_hash(n.note_id,n.owner_id,n.title,n.content)=plan->>'currentSha256');
    perform set_config('role','service_role',true);
    perform public.learning_restore_note(p_test_owner,test_note,good_copy,content_hash,plan->>'currentSha256');

    select md5(coalesce(jsonb_agg(to_jsonb(n) order by n.id)::text,'[]')) into after_notes
      from public.learning_notes n where n.note_id<>test_note;
    select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.event_id)::text,'[]')) into after_audit
      from learning_backup.note_restore_audit a where a.event_id=any(old_audit_ids);
    others_preserved := before_notes=after_notes;
    audit_preserved := before_audit=after_audit;
    if not (bad_hash_blocked and wrong_owner_blocked and pending_blocked and stale_blocked
      and updated and recreated and audit_rollback and others_preserved and audit_preserved and server_role_used)
      then raise exception 'NOTE_RESTORE_TEST_FAILED'; end if;
    -- Keep the booleans, but roll back every fixture mutation and SET ROLE.
    raise sqlstate 'PZ001' using message='ROLLBACK_TEST_FIXTURE';
  exception when sqlstate 'PZ001' then null;
  end;
  select md5(coalesce(jsonb_agg(to_jsonb(n) order by n.id)::text,'[]')) into after_notes
    from public.learning_notes n;
  select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.event_id)::text,'[]')) into after_audit
    from learning_backup.note_restore_audit a;
  if before_notes<>after_notes or before_audit<>after_audit then raise exception 'TEST_ROLLBACK_FAILED'; end if;
  return jsonb_build_object('b_owner_confirmed',true,'server_role_used',server_role_used,
    'single_note_updated',updated,'deleted_note_recreated',recreated,
    'source_hash_mismatch_rejected',bad_hash_blocked,'wrong_owner_rejected',wrong_owner_blocked,
    'unverified_copy_rejected',pending_blocked,'stale_preview_rejected',stale_blocked,
    'audit_failure_rolled_back_note',audit_rollback,'other_notes_preserved',others_preserved,
    'prior_audit_preserved',audit_preserved,'test_changes_rolled_back',true);
end;
$$;
revoke all on function learning_backup.verify_note_restore_b(uuid)
  from public, anon, authenticated, service_role;
