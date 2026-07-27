import type {
  EnumeratedPath,
  EvidenceGrade,
  Graph,
  GraphEdge,
  GraphNode,
} from "./types.js";

export interface PathOptions {
  /** Longest route we will report. Past this, a path stops being actionable. */
  maxHops?: number;
  /** Safety valve. A misconfigured tenant should degrade, not hang the worker. */
  maxPaths?: number;
  /** Which stores count as worth reaching. */
  targetSensitivity?: ReadonlyArray<NonNullable<GraphNode["sensitivity"]>>;
}

const DEFAULTS = {
  maxHops: 8,
  maxPaths: 5_000,
  targetSensitivity: ["confidential", "regulated"] as const,
};

/**
 * Every simple route from an untrusted origin to a sensitive store.
 *
 * Depth-first with the current path as the visited set, so routes are simple
 * (no repeated node) but siblings are still explored — which is the point,
 * since two different routes through the same shared identity are two
 * different findings and collapse to one fix.
 */
export function enumerateAttackPaths(
  graph: Graph,
  options: PathOptions = {},
): EnumeratedPath[] {
  const maxHops = options.maxHops ?? DEFAULTS.maxHops;
  const maxPaths = options.maxPaths ?? DEFAULTS.maxPaths;
  const targetSensitivity = new Set<string>(
    options.targetSensitivity ?? DEFAULTS.targetSensitivity,
  );

  const isTarget = (n: GraphNode) =>
    n.kind === "data_store" && n.sensitivity !== null && targetSensitivity.has(n.sensitivity);

  const sources = [...graph.nodes.values()].filter(
    (n) => n.kind === "input_source" && n.isUntrusted,
  );

  const found: EnumeratedPath[] = [];
  const seenKeys = new Set<string>();

  for (const source of sources) {
    if (found.length >= maxPaths) break;

    const nodeStack: string[] = [source.id];
    const edgeStack: GraphEdge[] = [];
    const onPath = new Set<string>([source.id]);

    const walk = (currentId: string): void => {
      if (found.length >= maxPaths) return;
      if (edgeStack.length >= maxHops) return;

      for (const edge of graph.out.get(currentId) ?? []) {
        if (onPath.has(edge.dstId)) continue;
        const next = graph.nodes.get(edge.dstId);
        if (!next) continue;

        nodeStack.push(next.id);
        edgeStack.push(edge);
        onPath.add(next.id);

        if (isTarget(next)) {
          const pathKey = nodeStack.join(">");
          if (!seenKeys.has(pathKey)) {
            seenKeys.add(pathKey);
            found.push(materialise(pathKey, source, next, nodeStack, edgeStack));
          }
          // Do not walk past a target: reaching the data is the finding, and
          // continuing produces longer paths that collapse to the same fix.
        } else {
          walk(next.id);
        }

        onPath.delete(next.id);
        edgeStack.pop();
        nodeStack.pop();
      }
    };

    walk(source.id);
  }

  return found;
}

function materialise(
  pathKey: string,
  source: GraphNode,
  target: GraphNode,
  nodeStack: readonly string[],
  edgeStack: readonly GraphEdge[],
): EnumeratedPath {
  const observedEdges = edgeStack.filter((e) => e.observed).length;
  return {
    pathKey,
    sourceId: source.id,
    targetId: target.id,
    nodeIds: [...nodeStack],
    edgeIds: edgeStack.map((e) => e.id),
    hops: edgeStack.length,
    observedEdges,
    evidence: gradeEvidence(source, edgeStack),
  };
}

/**
 * How strongly we can stand behind this path.
 *
 *   config       the permission structure proves the route exists, and nothing
 *                more. We know it *can* happen.
 *   observed     every edge on the route has actually been exercised inside a
 *                known audit window. The route is live, not theoretical.
 *   triggerable  live, and the untrusted origin has a named entry point an
 *                attacker can actually write to.
 *
 * Note the deliberate gap: none of these grades assert that a prompt injection
 * will succeed. That edge is probabilistic and content-dependent, and we do not
 * compute it. `triggerable` is the strongest claim the data supports, and it is
 * a claim about reachability and liveness, not about model behaviour.
 */
function gradeEvidence(
  source: GraphNode,
  edges: readonly GraphEdge[],
): EvidenceGrade {
  if (edges.length === 0) return "config";
  const allObserved = edges.every((e) => e.observed);
  if (!allObserved) return "config";

  const entryPoint = source.attributes["entry_point"];
  const hasNamedEntryPoint = typeof entryPoint === "string" && entryPoint.length > 0;
  return hasNamedEntryPoint ? "triggerable" : "observed";
}
