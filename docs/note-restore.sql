-- Server-only private copies. No existing note grants or policies are changed.
create schema learning_backup;
revoke all on schema learning_backup from public, anon, authenticated;
grant usage on schema learning_backup to service_role;

create function learning_backup.note_hash(p_note_id uuid, p_owner uuid, p_title text, p_content text)
returns text language sql immutable security invoker set search_path = ''
as $$
  select pg_catalog.encode(extensions.digest(pg_catalog.convert_to(
    pg_catalog.jsonb_build_array(p_note_id, p_owner, p_title, p_content)::text, 'UTF8'), 'sha256'), 'hex');
$$;
revoke all on function learning_backup.note_hash(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function learning_backup.note_hash(uuid,uuid,text,text) to service_role;

create table learning_backup.note_copies (
  backup_id uuid primary key default gen_random_uuid(),
  note_id uuid not null,
  original_id bigint not null,
  owner_id uuid not null,
  title text not null check (length(title) between 1 and 200),
  content text not null check (length(content) between 1 and 10000),
  original_created_at timestamptz not null,
  content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
  verified_at timestamptz,
  saved_at timestamptz not null default clock_timestamp()
);
create index note_copies_owner_lookup on learning_backup.note_copies(owner_id,note_id,verified_at desc);
alter table learning_backup.note_copies enable row level security;

create table learning_backup.note_restore_audit (
  event_id uuid primary key default gen_random_uuid(),
  note_id uuid not null,
  backup_id uuid not null,
  content_hash text not null,
  previous_hash text not null,
  operation text not null check (operation in ('update','recreate')),
  restored_at timestamptz not null default clock_timestamp()
);
alter table learning_backup.note_restore_audit enable row level security;
revoke all on table learning_backup.note_copies, learning_backup.note_restore_audit
  from public, anon, authenticated, service_role;
grant select on table learning_backup.note_copies to service_role;
grant select, insert on table learning_backup.note_restore_audit to service_role;

create function public.learning_preview_note_restore(p_actor uuid, p_note_id uuid)
returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare
  saved learning_backup.note_copies%rowtype;
  live public.learning_notes%rowtype;
  current_hash text := 'missing';
  kind text := 'recreate';
begin
  if p_actor is null or p_note_id is null then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
  select * into saved from learning_backup.note_copies
    where note_id=p_note_id and owner_id=p_actor and verified_at is not null and verified_at<=clock_timestamp()
    order by verified_at desc, backup_id limit 1;
  if not found then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
  if saved.content_hash <> learning_backup.note_hash(saved.note_id,saved.owner_id,saved.title,saved.content)
    then raise exception 'RESTORE_HASH_MISMATCH'; end if;
  select * into live from public.learning_notes where note_id=p_note_id;
  if found then
    if live.owner_id is distinct from p_actor or live.id<>saved.original_id
      then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
    current_hash := learning_backup.note_hash(live.note_id,live.owner_id,live.title,live.content);
    kind := 'update';
  elsif exists(select 1 from public.learning_notes where id=saved.original_id) then
    raise exception 'RESTORE_CONFLICT';
  end if;
  return pg_catalog.jsonb_build_object('id',saved.note_id,'backupId',saved.backup_id,
    'contentSha256',saved.content_hash,'currentSha256',current_hash,'operation',kind);
end;
$$;

create function public.learning_restore_note(p_actor uuid, p_note_id uuid, p_backup_id uuid,
  p_content_hash text, p_expected_current text)
returns jsonb language plpgsql security invoker set search_path = ''
as $$
declare
  saved learning_backup.note_copies%rowtype;
  live public.learning_notes%rowtype;
  check_row public.learning_notes%rowtype;
  current_hash text := 'missing';
  kind text := 'recreate';
  affected integer;
begin
  if p_actor is null or p_note_id is null or p_backup_id is null
    then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
  if p_content_hash is null or p_content_hash !~ '^[0-9a-f]{64}$'
    or p_expected_current is null or (p_expected_current <> 'missing' and p_expected_current !~ '^[0-9a-f]{64}$')
    then raise exception 'RESTORE_HASH_MISMATCH'; end if;
  -- Serialize restoration for a deleted UUID, too. Normal live rows are locked.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_note_id::text,0));
  select * into saved from learning_backup.note_copies
    where backup_id=p_backup_id and note_id=p_note_id and owner_id=p_actor;
  if not found then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
  if saved.verified_at is null or saved.verified_at>clock_timestamp() then raise exception 'RESTORE_SOURCE_UNVERIFIED'; end if;
  if saved.content_hash <> p_content_hash
    or saved.content_hash <> learning_backup.note_hash(saved.note_id,saved.owner_id,saved.title,saved.content)
    then raise exception 'RESTORE_HASH_MISMATCH'; end if;
  select * into live from public.learning_notes where note_id=p_note_id for update;
  if found then
    if live.owner_id is distinct from p_actor or live.id<>saved.original_id
      then raise exception 'RESTORE_SOURCE_NOT_FOUND'; end if;
    current_hash := learning_backup.note_hash(live.note_id,live.owner_id,live.title,live.content);
    kind := 'update';
  elsif exists(select 1 from public.learning_notes where id=saved.original_id) then
    raise exception 'RESTORE_CONFLICT';
  end if;
  if current_hash <> p_expected_current then raise exception 'RESTORE_STATE_CHANGED'; end if;
  if kind='update' then
    update public.learning_notes set title=saved.title, content=saved.content
      where note_id=p_note_id and owner_id=p_actor and id=saved.original_id;
    get diagnostics affected = row_count;
    if affected<>1 then raise exception 'RESTORE_CONFLICT'; end if;
  else
    insert into public.learning_notes(id,note_id,owner_id,title,content,created_at)
      overriding system value
      values(saved.original_id,saved.note_id,saved.owner_id,saved.title,saved.content,saved.original_created_at);
  end if;
  select * into check_row from public.learning_notes where note_id=p_note_id;
  if not found or check_row.owner_id is distinct from p_actor
    or check_row.id<>saved.original_id
    or learning_backup.note_hash(check_row.note_id,check_row.owner_id,check_row.title,check_row.content)<>p_content_hash
    then raise exception 'RESTORE_HASH_MISMATCH'; end if;
  -- Same transaction: audit failure rolls back this single-note change.
  insert into learning_backup.note_restore_audit(note_id,backup_id,content_hash,previous_hash,operation)
    values(p_note_id,p_backup_id,p_content_hash,current_hash,kind);
  return pg_catalog.jsonb_build_object('id',p_note_id,'restored',true,'contentSha256',p_content_hash);
exception when unique_violation then raise exception 'RESTORE_CONFLICT';
end;
$$;

revoke all on function public.learning_preview_note_restore(uuid,uuid)
  from public, anon, authenticated;
revoke all on function public.learning_restore_note(uuid,uuid,uuid,text,text)
  from public, anon, authenticated;
grant execute on function public.learning_preview_note_restore(uuid,uuid) to service_role;
grant execute on function public.learning_restore_note(uuid,uuid,uuid,text,text) to service_role;
