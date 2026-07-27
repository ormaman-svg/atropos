import {
  bumpSeverity,
  type DataSensitivity,
  type EnumeratedPath,
  type EvidenceGrade,
  type Graph,
  type GraphNode,
  type RuleHit,
  type Severity,
} from "./types.js";

const SENSITIVITY_SEVERITY: Record<DataSensitivity, Severity> = {
  regulated: "critical",
  confidential: "high",
  internal: "medium",
  public: "low",
};

/**
 * Severity is derived, never hardcoded.
 *
 * Base comes from what the path reaches. Evidence then moves it: a route we
 * can only prove structurally is demoted, because "exploitable" is a strong
 * word and config alone does not earn it. A live route with a named entry
 * point is promoted.
 */
export function severityFor(
  sensitivity: DataSensitivity | null,
  evidence: EvidenceGrade,
): Severity {
  const base = SENSITIVITY_SEVERITY[sensitivity ?? "internal"];
  const shift = evidence === "config" ? -1 : evidence === "triggerable" ? 1 : 0;
  return bumpSeverity(base, shift);
}

/** Nodes reachable from `startId`, following any edge kind, bounded by depth. */
function reachableFrom(graph: Graph, startId: string, maxDepth = 6): Set<string> {
  const seen = new Set<string>([startId]);
  let frontier = [startId];
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const edge of graph.out.get(id) ?? []) {
        if (seen.has(edge.dstId)) continue;
        seen.add(edge.dstId);
        next.push(edge.dstId);
      }
    }
    frontier = next;
  }
  seen.delete(startId);
  return seen;
}

/** Nodes that can reach `targetId`. Built by inverting adjacency once per call. */
function reachesTarget(graph: Graph, targetId: string, maxDepth = 6): Set<string> {
  const incoming = new Map<string, string[]>();
  for (const e of graph.edges) {
    const list = incoming.get(e.dstId);
    if (list) list.push(e.srcId);
    else incoming.set(e.dstId, [e.srcId]);
  }
  const seen = new Set<string>([targetId]);
  let frontier = [targetId];
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const src of incoming.get(id) ?? []) {
        if (seen.has(src)) continue;
        seen.add(src);
        next.push(src);
      }
    }
    frontier = next;
  }
  seen.delete(targetId);
  return seen;
}

/**
 * The lethal trifecta: private data access, untrusted content exposure, and
 * external communication in one agent.
 *
 * Detection v1, and the one rule that is fully computable from configuration
 * alone. Any two of the three is a design smell; all three is an agent that
 * can be told what to do by a stranger and has somewhere to send the results.
 */
function lethalTrifecta(graph: Graph): RuleHit[] {
  const hits: RuleHit[] = [];

  for (const node of graph.nodes.values()) {
    if (node.kind !== "agent") continue;

    const downstream = reachableFrom(graph, node.id);
    const upstream = reachesTarget(graph, node.id);

    const stores = [...downstream]
      .map((id) => graph.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === "data_store")
      .filter((n) => n.sensitivity === "confidential" || n.sensitivity === "regulated");

    const untrustedSources = [...upstream]
      .map((id) => graph.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === "input_source" && n.isUntrusted);

    const egressTools = [...downstream]
      .map((id) => graph.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === "tool")
      .filter((n) => n.capabilities.includes("external_comms"));

    if (stores.length === 0 || untrustedSources.length === 0 || egressTools.length === 0) {
      continue;
    }

    const worst = stores.some((s) => s.sensitivity === "regulated")
      ? "regulated"
      : "confidential";

    hits.push({
      ruleId: "lethal-trifecta",
      title: `${node.name} holds the lethal trifecta`,
      // Node-scoped, so there is no single path to grade. Config is the honest
      // floor: the capability combination is structural.
      severity: severityFor(worst, "config"),
      evidence: "config",
      techniqueIds: ["ASI01", "AML.T0051"],
      subjectId: node.id,
      detail: {
        private_data: stores.map((s) => s.name),
        untrusted_input: untrustedSources.map((s) => s.name),
        external_comms: egressTools.map((t) => t.name),
      },
    });
  }

  return hits;
}

/** Any route from an untrusted origin to regulated data. */
function untrustedToRegulated(graph: Graph, paths: EnumeratedPath[]): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const path of paths) {
    const target = graph.nodes.get(path.targetId);
    const source = graph.nodes.get(path.sourceId);
    if (!target || !source || target.sensitivity !== "regulated") continue;

    hits.push({
      ruleId: "untrusted-input-to-regulated-data",
      title: `${source.name} reaches ${target.name} in ${path.hops} hops`,
      severity: severityFor(target.sensitivity, path.evidence),
      evidence: path.evidence,
      techniqueIds: ["ASI01", "AML.T0086"],
      pathKey: path.pathKey,
      detail: {
        hops: path.hops,
        observed_edges: path.observedEdges,
        chain: path.nodeIds.map((id) => graph.nodes.get(id)?.name ?? id),
      },
    });
  }
  return hits;
}

/** A route that transits an MCP server we know to be unauthenticated. */
function unauthenticatedMcpExposure(
  graph: Graph,
  paths: EnumeratedPath[],
): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const path of paths) {
    const openServers = path.nodeIds
      .map((id) => graph.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === "mcp_server")
      .filter((n) => n.attributes["authenticated"] === false);
    if (openServers.length === 0) continue;

    const target = graph.nodes.get(path.targetId);
    hits.push({
      ruleId: "unauthenticated-mcp-exposure",
      title: `Unauthenticated ${openServers[0]!.name} sits on a path to ${
        target?.name ?? "sensitive data"
      }`,
      severity: severityFor(target?.sensitivity ?? null, path.evidence),
      evidence: path.evidence,
      techniqueIds: ["ASI03", "AML.T0051"],
      pathKey: path.pathKey,
      detail: {
        mcp_servers: openServers.map((s) => s.name),
        hops: path.hops,
      },
    });
  }
  return hits;
}

/**
 * One identity inherited by several agents.
 *
 * This is the shape that makes choke-point analysis pay: a single shared
 * service principal is usually the node that every path runs through, so one
 * scoping change collapses all of them at once.
 */
function sharedIdentityInheritance(graph: Graph): RuleHit[] {
  const inheritors = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    if (edge.kind !== "credential_inheritance") continue;
    const identity = graph.nodes.get(edge.dstId);
    const holder = graph.nodes.get(edge.srcId);
    if (identity?.kind !== "identity" || !holder) continue;
    const set = inheritors.get(identity.id);
    if (set) set.add(holder.id);
    else inheritors.set(identity.id, new Set([holder.id]));
  }

  const hits: RuleHit[] = [];
  for (const [identityId, holders] of inheritors) {
    if (holders.size < 2) continue;
    const identity = graph.nodes.get(identityId);
    if (!identity) continue;

    const stores = [...reachableFrom(graph, identityId)]
      .map((id) => graph.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === "data_store")
      .filter((n) => n.sensitivity === "confidential" || n.sensitivity === "regulated");
    if (stores.length === 0) continue;

    hits.push({
      ruleId: "shared-identity-privilege-inheritance",
      title: `${identity.name} is shared by ${holders.size} agents`,
      severity: severityFor(
        stores.some((s) => s.sensitivity === "regulated") ? "regulated" : "confidential",
        "config",
      ),
      evidence: "config",
      techniqueIds: ["ASI03"],
      subjectId: identity.id,
      detail: {
        agent_count: holders.size,
        agents: [...holders].map((id) => graph.nodes.get(id)?.name ?? id),
        reaches: stores.map((s) => s.name),
      },
    });
  }
  return hits;
}

export function evaluateRules(graph: Graph, paths: EnumeratedPath[]): RuleHit[] {
  return [
    ...lethalTrifecta(graph),
    ...untrustedToRegulated(graph, paths),
    ...unauthenticatedMcpExposure(graph, paths),
    ...sharedIdentityInheritance(graph),
  ];
}
