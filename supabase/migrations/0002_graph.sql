-- ============================================================================
-- 0002 — the graph, paths, findings and choke points
--
-- The model is the one from the product brief:
--
--   untrusted input source → agent → MCP server → tool → identity → data store
--
-- Edges are permission, reachability and credential inheritance. Each edge
-- additionally carries whether it has been *observed* being exercised, which
-- is what separates "this agent can read the CRM" from "this agent read the
-- CRM four hundred times last month".
--
-- Nodes and edges hold current state rather than per-scan snapshots. A scan
-- upserts and stamps last_seen_at; anything not re-seen is stale, not deleted,
-- so a connector outage does not silently collapse a customer's graph.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- enumerations
-- ---------------------------------------------------------------------------

create type node_kind as enum (
  'input_source',   -- an origin of content we do not control
  'agent',
  'mcp_server',
  'tool',
  'identity',       -- human or non-human
  'data_store'
);

create type identity_class as enum ('human', 'nhi');

create type data_sensitivity as enum (
  'public', 'internal', 'confidential', 'regulated'
);

create type tool_capability as enum (
  'read', 'write', 'external_comms', 'code_exec'
);

create type edge_kind as enum (
  'permission',             -- source grants target the ability to act
  'reachability',           -- source can reach target over the network or an API
  'credential_inheritance'  -- target inherits the source's credential
);

-- How well a claim is backed. With the console claiming *exploitable* paths,
-- this is what has to answer "show me" in a POC.
--
--   config       the permission structure proves the path exists
--   observed     the edges on it have actually been exercised
--   triggerable  the untrusted-input edge has a named, concrete entry point
--
-- Deliberately ordered weakest to strongest; severity is computed from it.
create type evidence_grade as enum ('config', 'observed', 'triggerable');

create type severity as enum ('low', 'medium', 'high', 'critical');

create type finding_status as enum ('open', 'resolved', 'accepted', 'suppressed');

-- ---------------------------------------------------------------------------
-- technique catalogue
--
-- ATLAS and OWASP identifiers are data, not code, so correcting or extending
-- the mapping is a seed change rather than a deploy.
--
-- NOTE: the identifiers seeded at the bottom of this file are carried over
-- from the reference console. Verify each against the published MITRE ATLAS
-- matrix and the OWASP Agentic Security Initiative list before any of them is
-- shown to a customer — procurement checks these, and a wrong ID is worse than
-- no ID.
-- ---------------------------------------------------------------------------

create table technique (
  id          text primary key,          -- e.g. 'AML.T0051', 'ASI01'
  framework   text not null check (framework in ('atlas', 'owasp-agentic')),
  name        text not null,
  url         text,
  verified_at timestamptz                -- null until checked against the source
);

-- Global reference data, readable by the app, not tenant-scoped.
grant select on technique to atropos_app;

-- ---------------------------------------------------------------------------
-- nodes
-- ---------------------------------------------------------------------------

create table node (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenant (id) on delete cascade,
  kind            node_kind not null,
  external_id     text not null,       -- stable identifier in the source system
  name            text not null,
  provider        connector_provider,
  connection_id   uuid references connection (id) on delete set null,

  -- kind-specific, materialised because the rules query them on every scan
  sensitivity     data_sensitivity,    -- data_store
  capabilities    tool_capability[] not null default '{}',  -- tool
  is_untrusted    boolean not null default false,           -- input_source
  identity_class  identity_class,                           -- identity

  attributes      jsonb not null default '{}'::jsonb,
  first_seen_at   timestamptz not null default now(),
  last_seen_at    timestamptz not null default now(),

  unique (tenant_id, kind, external_id),

  -- Keep the kind-specific columns honest. A data store with no sensitivity
  -- would silently drop out of every trifecta evaluation.
  constraint node_data_store_has_sensitivity
    check (kind <> 'data_store' or sensitivity is not null),
  constraint node_identity_has_class
    check (kind <> 'identity' or identity_class is not null)
);

create index node_tenant_kind_idx on node (tenant_id, kind);

alter table node enable row level security;
alter table node force row level security;
create policy node_tenant_isolation on node
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- edges
--
-- observation_window_days is the load-bearing column for Tier 3 remediation.
-- "Revoke this unused grant" is only safe if we can say how far back we looked
-- before calling it unused. Without the window, observed = false means
-- "we saw nothing", which is not the same as "nothing happened".
-- ---------------------------------------------------------------------------

create table edge (
  id                      uuid primary key default gen_random_uuid(),
  tenant_id               uuid not null references tenant (id) on delete cascade,
  src_id                  uuid not null references node (id) on delete cascade,
  dst_id                  uuid not null references node (id) on delete cascade,
  kind                    edge_kind not null,

  observed                boolean not null default false,
  exercise_count          bigint not null default 0,
  last_exercised_at       timestamptz,
  observation_window_days integer,   -- how much log history backs `observed`

  attributes              jsonb not null default '{}'::jsonb,
  first_seen_at           timestamptz not null default now(),
  last_seen_at            timestamptz not null default now(),

  unique (tenant_id, src_id, dst_id, kind),
  constraint edge_no_self_loop check (src_id <> dst_id),
  constraint edge_observed_needs_window
    check (not observed or observation_window_days is not null)
);

create index edge_src_idx on edge (tenant_id, src_id);
create index edge_dst_idx on edge (tenant_id, dst_id);

alter table edge enable row level security;
alter table edge force row level security;
create policy edge_tenant_isolation on edge
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

comment on column edge.observation_window_days is
  'Days of audit-log history backing the observed flag. Tier 3 actions that '
  'depend on a resource being unused must refuse to run when this is null or '
  'shorter than the policy minimum.';

-- ---------------------------------------------------------------------------
-- attack paths
--
-- One row per distinct route from an untrusted source to a sensitive store.
-- node_ids and edge_ids are ordered; path_key is their fingerprint, so a
-- re-scan updates a path rather than duplicating it.
-- ---------------------------------------------------------------------------

create table attack_path (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenant (id) on delete cascade,
  path_key        text not null,
  source_node_id  uuid not null references node (id) on delete cascade,
  target_node_id  uuid not null references node (id) on delete cascade,
  node_ids        uuid[] not null,
  edge_ids        uuid[] not null,
  hops            integer not null,
  evidence        evidence_grade not null default 'config',
  observed_edges  integer not null default 0,
  first_seen_at   timestamptz not null default now(),
  last_seen_at    timestamptz not null default now(),

  unique (tenant_id, path_key),
  constraint attack_path_hops_positive check (hops > 0)
);

create index attack_path_tenant_idx on attack_path (tenant_id);

alter table attack_path enable row level security;
alter table attack_path force row level security;
create policy attack_path_tenant_isolation on attack_path
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------

create table finding (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references tenant (id) on delete cascade,
  rule_id      text not null,
  path_id      uuid references attack_path (id) on delete cascade,
  subject_id   uuid references node (id) on delete cascade,  -- for node-scoped rules
  title        text not null,
  severity     severity not null,
  evidence     evidence_grade not null,
  status       finding_status not null default 'open',
  technique_ids text[] not null default '{}',
  detail       jsonb not null default '{}'::jsonb,
  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  resolved_at   timestamptz,

  -- nulls not distinct matters here: path-scoped rules leave subject_id null and
  -- node-scoped rules leave path_id null. Under default null semantics those
  -- rows never collide, so every re-scan would insert a duplicate finding.
  unique nulls not distinct (tenant_id, rule_id, path_id, subject_id)
);

create index finding_tenant_open_idx on finding (tenant_id, severity)
  where status = 'open';

alter table finding enable row level security;
alter table finding force row level security;
create policy finding_tenant_isolation on finding
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- choke points
--
-- The wedge: not "here are your problems" but "here is the one fix that
-- collapses the most of them". Recomputed per scan, so history is kept.
-- ---------------------------------------------------------------------------

create table choke_point (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references tenant (id) on delete cascade,
  scan_id         uuid not null references scan (id) on delete cascade,
  node_id         uuid not null references node (id) on delete cascade,
  paths_covered   integer not null,
  observed_paths  integer not null default 0,
  score           numeric(12, 3) not null,
  rank            integer not null,
  computed_at     timestamptz not null default now(),

  unique (tenant_id, scan_id, node_id)
);

create index choke_point_scan_rank_idx on choke_point (tenant_id, scan_id, rank);

alter table choke_point enable row level security;
alter table choke_point force row level security;
create policy choke_point_tenant_isolation on choke_point
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- grants
-- ---------------------------------------------------------------------------

grant select, insert, update, delete on
  node, edge, attack_path, finding, choke_point
  to atropos_app;

-- ---------------------------------------------------------------------------
-- seed: technique catalogue
--
-- verified_at is deliberately null on every row. See the NOTE above.
-- ---------------------------------------------------------------------------

insert into technique (id, framework, name) values
  ('AML.T0051', 'atlas',         'LLM Prompt Injection'),
  ('AML.T0086', 'atlas',         'Indirect Prompt Injection via external content'),
  ('AML.T0057', 'atlas',         'LLM Data Leakage'),
  ('ASI01',     'owasp-agentic', 'Agent Goal and Instruction Manipulation'),
  ('ASI03',     'owasp-agentic', 'Agent Privilege and Delegation Abuse')
on conflict (id) do nothing;
