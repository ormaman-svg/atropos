import type { PoolClient } from "pg";
import { rankChokePoints } from "./chokepoints.js";
import { enumerateAttackPaths, type PathOptions } from "./paths.js";
import { evaluateRules } from "./rules.js";
import {
  buildGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "./types.js";

export interface AnalysisSummary {
  nodes: number;
  edges: number;
  paths: number;
  openFindings: number;
  resolvedFindings: number;
  chokePoints: number;
  topChokePointNodeId: string | null;
}

/**
 * Read the tenant's graph.
 *
 * No tenant filter in the SQL: RLS supplies it. If these queries ever start
 * returning another tenant's rows, tests/tenancy.test.ts is the thing that
 * should have caught it.
 */
export async function loadGraph(client: PoolClient): Promise<Graph> {
  const nodes = await client.query<{
    id: string;
    kind: GraphNode["kind"];
    name: string;
    sensitivity: GraphNode["sensitivity"];
    capabilities: GraphNode["capabilities"];
    is_untrusted: boolean;
    identity_class: GraphNode["identityClass"];
    attributes: Record<string, unknown>;
  }>(
    `select id, kind, name, sensitivity, capabilities, is_untrusted,
            identity_class, attributes
       from node`,
  );

  const edges = await client.query<{
    id: string;
    src_id: string;
    dst_id: string;
    kind: GraphEdge["kind"];
    observed: boolean;
    exercise_count: string;
    last_exercised_at: Date | null;
    observation_window_days: number | null;
  }>(
    `select id, src_id, dst_id, kind, observed, exercise_count::text,
            last_exercised_at, observation_window_days
       from edge`,
  );

  return buildGraph(
    nodes.rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      name: r.name,
      sensitivity: r.sensitivity,
      capabilities: r.capabilities ?? [],
      isUntrusted: r.is_untrusted,
      identityClass: r.identity_class,
      attributes: r.attributes ?? {},
    })),
    edges.rows.map((r) => ({
      id: r.id,
      srcId: r.src_id,
      dstId: r.dst_id,
      kind: r.kind,
      observed: r.observed,
      exerciseCount: Number(r.exercise_count),
      lastExercisedAt: r.last_exercised_at,
      observationWindowDays: r.observation_window_days,
    })),
  );
}

/**
 * Full analysis pass for one tenant, inside an already tenant-scoped
 * transaction.
 *
 * Findings that no longer fire are resolved rather than deleted, and paths are
 * kept with a last_seen_at stamp rather than removed. A security product that
 * forgets what it used to say cannot be audited, and "this finding went away
 * and here is when" is exactly what a customer asks after a remediation.
 */
export async function analyse(
  client: PoolClient,
  scanId: string,
  options: PathOptions = {},
): Promise<AnalysisSummary> {
  const { rows: scoped } = await client.query<{ tenant_id: string | null }>(
    "select current_tenant_id() as tenant_id",
  );
  const tenantId = scoped[0]?.tenant_id;
  if (!tenantId) {
    throw new Error("analyse must run inside withTenant");
  }

  const graph = await loadGraph(client);
  const paths = enumerateAttackPaths(graph, options);
  const hits = evaluateRules(graph, paths);
  const chokePoints = rankChokePoints(graph, paths);

  // --- paths -------------------------------------------------------------
  // Looped rather than batched: tenant graphs are small enough that clarity
  // wins, and this is the code most likely to be read during an incident.
  const pathIdByKey = new Map<string, string>();
  for (const path of paths) {
    const { rows } = await client.query<{ id: string }>(
      `insert into attack_path
         (tenant_id, path_key, source_node_id, target_node_id,
          node_ids, edge_ids, hops, evidence, observed_edges)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       on conflict (tenant_id, path_key) do update
         set last_seen_at   = now(),
             evidence       = excluded.evidence,
             observed_edges = excluded.observed_edges
       returning id`,
      [
        tenantId,
        path.pathKey,
        path.sourceId,
        path.targetId,
        path.nodeIds,
        path.edgeIds,
        path.hops,
        path.evidence,
        path.observedEdges,
      ],
    );
    if (rows[0]) pathIdByKey.set(path.pathKey, rows[0].id);
  }

  // --- findings ----------------------------------------------------------
  const liveFindingIds: string[] = [];
  for (const hit of hits) {
    const pathId = hit.pathKey ? (pathIdByKey.get(hit.pathKey) ?? null) : null;
    if (hit.pathKey && !pathId) continue; // path failed to persist; skip rather than orphan

    const { rows } = await client.query<{ id: string }>(
      `insert into finding
         (tenant_id, rule_id, path_id, subject_id, title, severity,
          evidence, technique_ids, detail, status)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'open')
       on conflict (tenant_id, rule_id, path_id, subject_id) do update
         set last_seen_at   = now(),
             title          = excluded.title,
             severity       = excluded.severity,
             evidence       = excluded.evidence,
             technique_ids  = excluded.technique_ids,
             detail         = excluded.detail,
             status         = 'open',
             resolved_at    = null
       returning id`,
      [
        tenantId,
        hit.ruleId,
        pathId,
        hit.subjectId ?? null,
        hit.title,
        hit.severity,
        hit.evidence,
        hit.techniqueIds,
        JSON.stringify(hit.detail),
      ],
    );
    if (rows[0]) liveFindingIds.push(rows[0].id);
  }

  // Anything open that this scan did not re-raise has been fixed, or the thing
  // it described no longer exists. Either way it is resolved, with a timestamp.
  const resolved = await client.query(
    `update finding
        set status = 'resolved', resolved_at = now()
      where status = 'open'
        and not (id = any($1::uuid[]))`,
    [liveFindingIds],
  );

  // --- choke points ------------------------------------------------------
  for (const cp of chokePoints) {
    await client.query(
      `insert into choke_point
         (tenant_id, scan_id, node_id, paths_covered, observed_paths, score, rank)
       values ($1, $2, $3, $4, $5, $6, $7)
       on conflict (tenant_id, scan_id, node_id) do update
         set paths_covered  = excluded.paths_covered,
             observed_paths = excluded.observed_paths,
             score          = excluded.score,
             rank           = excluded.rank,
             computed_at    = now()`,
      [
        tenantId,
        scanId,
        cp.nodeId,
        cp.pathsCovered,
        cp.observedPaths,
        cp.score,
        cp.rank,
      ],
    );
  }

  return {
    nodes: graph.nodes.size,
    edges: graph.edges.length,
    paths: paths.length,
    openFindings: liveFindingIds.length,
    resolvedFindings: resolved.rowCount ?? 0,
    chokePoints: chokePoints.length,
    topChokePointNodeId: chokePoints[0]?.nodeId ?? null,
  };
}
