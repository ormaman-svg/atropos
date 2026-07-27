export type NodeKind =
  | "input_source"
  | "agent"
  | "mcp_server"
  | "tool"
  | "identity"
  | "data_store";

export type EdgeKind = "permission" | "reachability" | "credential_inheritance";

export type DataSensitivity = "public" | "internal" | "confidential" | "regulated";

export type ToolCapability = "read" | "write" | "external_comms" | "code_exec";

export type IdentityClass = "human" | "nhi";

/**
 * How well a claim is backed.
 *
 * The console claims *exploitable* paths, so this is what has to answer
 * "show me" when a POC engineer pushes back. Ordered weakest to strongest;
 * severity is computed from it rather than hardcoded.
 */
export type EvidenceGrade = "config" | "observed" | "triggerable";

export type Severity = "low" | "medium" | "high" | "critical";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  name: string;
  sensitivity: DataSensitivity | null;
  capabilities: ToolCapability[];
  isUntrusted: boolean;
  identityClass: IdentityClass | null;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  srcId: string;
  dstId: string;
  kind: EdgeKind;
  observed: boolean;
  exerciseCount: number;
  lastExercisedAt: Date | null;
  observationWindowDays: number | null;
}

export interface Graph {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  /** Adjacency, source node id → outgoing edges. */
  out: Map<string, GraphEdge[]>;
}

export interface EnumeratedPath {
  pathKey: string;
  sourceId: string;
  targetId: string;
  nodeIds: string[];
  edgeIds: string[];
  hops: number;
  observedEdges: number;
  evidence: EvidenceGrade;
}

export interface RuleHit {
  ruleId: string;
  title: string;
  severity: Severity;
  evidence: EvidenceGrade;
  techniqueIds: string[];
  /** Set for path-scoped rules. */
  pathKey?: string;
  /** Set for node-scoped rules. */
  subjectId?: string;
  detail: Record<string, unknown>;
}

export interface ScoredChokePoint {
  nodeId: string;
  pathsCovered: number;
  observedPaths: number;
  score: number;
  rank: number;
}

export const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

export function bumpSeverity(s: Severity, by: number): Severity {
  const i = SEVERITY_ORDER.indexOf(s);
  const next = Math.min(SEVERITY_ORDER.length - 1, Math.max(0, i + by));
  return SEVERITY_ORDER[next]!;
}

export function buildGraph(nodes: GraphNode[], edges: GraphEdge[]): Graph {
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const out = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    // Drop dangling edges rather than letting traversal blow up on them. A
    // connector that returns a reference to something it could not read is a
    // normal occurrence, not an exception.
    if (!nodeMap.has(e.srcId) || !nodeMap.has(e.dstId)) continue;
    const list = out.get(e.srcId);
    if (list) list.push(e);
    else out.set(e.srcId, [e]);
  }
  return { nodes: nodeMap, edges, out };
}
