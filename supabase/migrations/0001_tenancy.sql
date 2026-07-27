-- ============================================================================
-- 0001 — tenancy
--
-- Per-tenant isolation is a sales promise, so it is the first migration rather
-- than a later retrofit. Every tenant-owned table here carries tenant_id,
-- enables row-level security, and forces it.
--
-- Two details do the actual work, and both are easy to get wrong in a way that
-- still reviews as correct:
--
--   1. FORCE ROW LEVEL SECURITY. Without it the table owner bypasses every
--      policy below, silently. The policies would look right in review and do
--      nothing the moment the app connects as the owning role.
--
--   2. current_tenant_id() returns NULL when app.tenant_id is unset, and
--      `tenant_id = NULL` evaluates to NULL rather than true. An unscoped
--      connection therefore sees zero rows instead of every row. It fails
--      closed. tests/tenancy.test.ts asserts exactly this.
-- ============================================================================

-- The role the application connects as. Deliberately not the owner of these
-- tables and deliberately not BYPASSRLS — those are the two ways RLS quietly
-- stops applying.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'atropos_app') then
    create role atropos_app nologin;
  end if;
end
$$;

create or replace function current_tenant_id() returns uuid
  language sql
  stable
as $$
  select nullif(current_setting('app.tenant_id', true), '')::uuid
$$;

comment on function current_tenant_id() is
  'Tenant scope for the current transaction. NULL when app.tenant_id is unset, '
  'which makes every RLS policy below fail closed rather than open.';

-- ---------------------------------------------------------------------------
-- enumerations
-- ---------------------------------------------------------------------------

create type connector_provider as enum (
  'aws', 'azure', 'gcp',          -- cloud
  'entra', 'okta',                -- identity
  'github', 'gitlab',             -- source
  'snowflake'                     -- data
);

create type connection_status as enum (
  'pending',    -- consent started, not yet verified
  'active',
  'error',      -- credentials rejected or scope withdrawn
  'revoked'     -- customer disconnected
);

create type scan_status as enum (
  'queued', 'running', 'succeeded', 'failed', 'cancelled'
);

create type membership_role as enum ('owner', 'admin', 'member');

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------

create table tenant (
  id          uuid primary key default gen_random_uuid(),
  slug        text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'),
  name        text not null,
  created_at  timestamptz not null default now()
);

alter table tenant enable row level security;
alter table tenant force row level security;

create policy tenant_self on tenant
  using (id = current_tenant_id())
  with check (id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- users and membership
--
-- app_user is global: one human may belong to several tenants. It is therefore
-- scoped by membership rather than by a tenant_id column.
-- ---------------------------------------------------------------------------

create table app_user (
  id          uuid primary key default gen_random_uuid(),
  email       text not null unique,
  created_at  timestamptz not null default now()
);

create table membership (
  tenant_id   uuid not null references tenant (id) on delete cascade,
  user_id     uuid not null references app_user (id) on delete cascade,
  role        membership_role not null default 'member',
  created_at  timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create index membership_user_idx on membership (user_id);

alter table app_user enable row level security;
alter table app_user force row level security;
alter table membership enable row level security;
alter table membership force row level security;

create policy app_user_visible_via_membership on app_user
  using (
    exists (
      select 1 from membership m
      where m.user_id = app_user.id
        and m.tenant_id = current_tenant_id()
    )
  );

create policy membership_tenant_isolation on membership
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- connections
--
-- A read-only connector into a customer system. Agentless: we hold API
-- credentials for a read-only principal, nothing is deployed on their side.
--
-- credential_ref is an opaque handle into the secret store. Credential
-- material is never stored in this database, and never reaches the model.
-- If a token value ever appears in this table, that is a bug and a broken
-- promise, in that order.
-- ---------------------------------------------------------------------------

create table connection (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenant (id) on delete cascade,
  provider        connector_provider not null,
  display_name    text not null,
  external_ref    text not null,       -- e.g. AWS account id, Entra tenant id
  credential_ref  text,                -- handle into the secret store; never the secret
  granted_scopes  text[] not null default '{}',
  status          connection_status not null default 'pending',
  connected_at    timestamptz,
  last_synced_at  timestamptz,
  created_at      timestamptz not null default now(),
  unique (tenant_id, provider, external_ref)
);

create index connection_tenant_idx on connection (tenant_id);

alter table connection enable row level security;
alter table connection force row level security;

create policy connection_tenant_isolation on connection
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

comment on column connection.credential_ref is
  'Opaque handle into the secret store. Never credential material. '
  'Metadata-only is load-bearing: we read that a secret exists and what it '
  'grants, never its value.';

-- ---------------------------------------------------------------------------
-- scans
--
-- Doubles as the work queue for the background worker. Claiming a scan is
-- `for update skip locked`, so multiple workers can run without coordination.
-- ---------------------------------------------------------------------------

create table scan (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references tenant (id) on delete cascade,
  status        scan_status not null default 'queued',
  trigger       text not null default 'manual',
  queued_at     timestamptz not null default now(),
  started_at    timestamptz,
  finished_at   timestamptz,
  locked_by     text,
  locked_at     timestamptz,
  error         text,
  stats         jsonb not null default '{}'::jsonb
);

-- Supports the worker's claim query, which only ever looks at queued rows.
create index scan_queue_idx on scan (status, queued_at) where status = 'queued';
create index scan_tenant_idx on scan (tenant_id, queued_at desc);

alter table scan enable row level security;
alter table scan force row level security;

create policy scan_tenant_isolation on scan
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- grants
--
-- The app role gets DML and nothing else. No DDL, no ownership, no BYPASSRLS.
-- ---------------------------------------------------------------------------

grant usage on schema public to atropos_app;
grant select, insert, update, delete on
  tenant, app_user, membership, connection, scan
  to atropos_app;
