begin;
create table public.learning_resource_subjects (
 class_id text not null, project_id text not null, subject_id text not null,
 identity_kind text not null check (identity_kind in ('student','judge')),
 user_id uuid not null, primary key (class_id,project_id,subject_id)
);
create table public.learning_instructors (
 identity_kind text not null check (identity_kind in ('student','judge')),
 user_id uuid not null, enabled boolean not null default false,
 primary key(identity_kind,user_id)
);
create table public.learning_announcements (
 id uuid primary key default gen_random_uuid(), title text not null, body text not null,
 owner_id uuid not null, owner_kind text not null check (owner_kind in ('student','judge')),
 created_at timestamptz not null default now()
);
alter table public.learning_resource_subjects enable row level security;
alter table public.learning_instructors enable row level security;
alter table public.learning_announcements enable row level security;
revoke all on table public.learning_resource_subjects, public.learning_instructors, public.learning_announcements from public, anon, authenticated;
grant select on table public.learning_resource_subjects,public.learning_instructors to service_role;
grant select,insert,update,delete on table public.learning_announcements to service_role;
commit;
