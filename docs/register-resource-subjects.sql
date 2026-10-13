-- Run by the database operator in SQL Editor after obtaining verified engine IDs.
-- Do not place real account emails or engine identity mappings in Git.
-- This registration function is NOT callable by browser or service-role clients.
begin;
create or replace function public.register_learning_resource_subject(
  verified_class_id text,
  verified_project_id text,
  verified_subject_id text,
  account_email text
) returns void
language plpgsql security invoker set search_path = ''
as $$
declare
  account_id uuid;
  account_count integer;
  registered public.learning_resource_subjects%rowtype;
begin
  if verified_class_id is null or verified_project_id is null or verified_subject_id is null
    or verified_class_id !~ '^[A-Za-z0-9_.:-]{1,128}$'
    or verified_project_id !~ '^[A-Za-z0-9_.:-]{1,128}$'
    or verified_subject_id !~ '^[A-Za-z0-9_.:-]{1,128}$' then
    raise exception 'invalid_verified_identity';
  end if;
  select count(*) into account_count from auth.users
    where lower(email) = lower(btrim(account_email));
  if account_count <> 1 then raise exception 'account_not_unique'; end if;
  select id into account_id from auth.users
    where lower(email) = lower(btrim(account_email));
  insert into public.learning_resource_subjects(class_id,project_id,subject_id,identity_kind,user_id)
    values(verified_class_id,verified_project_id,verified_subject_id,'student',account_id)
    on conflict(class_id,project_id,subject_id) do nothing;
  select * into registered from public.learning_resource_subjects
    where class_id=verified_class_id and project_id=verified_project_id and subject_id=verified_subject_id;
  if registered.user_id is distinct from account_id or registered.identity_kind <> 'student' then
    raise exception 'binding_conflict';
  end if;
end;
$$;
revoke all on function public.register_learning_resource_subject(text,text,text,text)
  from public,anon,authenticated,service_role;
commit;

-- After the operator verifies the engine mapping, call the function once for A
-- and once for B using the real verified IDs and the account email in SQL Editor.
-- No grants, notes, ownership or instructor roles are changed by registration.
