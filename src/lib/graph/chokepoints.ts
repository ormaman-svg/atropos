import { severityFor } from "./rules.js";
import type {
  EnumeratedPath,
  Graph,
  ScoredChokePoint,
  Severity,
} from "./types.js";

/**
 * How much a path is worth collapsing. Superlinear on purpose: one critical
 * path is worth more than three mediums, because the fix that removes it is
 * the one worth interrupting an engineer for.
 */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 8,
  high: 4,
  medium: 2,
  low: 1,
};

/** A live path counts for more than a merely possible one. */
const OBSERVED_MULTIPLIER = 1.5;

/**
 * Rank the nodes by how much removing them would collapse.
 *
 * This is the wedge, so it is worth being precise about what it computes: for
 * every interior node, the weighted set of paths that transit it. Endpoints are
 * excluded — the untrusted source is usually not ours to remove, and the data
 * store is the thing we are protecting, so neither is a fix.
 *
 * It is deliberately *not* a graph-theoretic articulation point. An articulation
 * point is a node whose removal disconnects the graph, which is a stronger and
 * less useful condition here: the question a customer asks is not "what would
 * disconnect this" but "what one change kills the most of my critical paths".
 * A node can cover fourteen paths without being an articulation point for any
 * of them.
 */
export function rankChokePoints(
  graph: Graph,
  paths: EnumeratedPath[],
): ScoredChokePoint[] {
  const covered = new Map<string, EnumeratedPath[]>();

  for (const path of paths) {
    // Interior only: drop the first and last node.
    for (const nodeId of path.nodeIds.slice(1, -1)) {
      const list = covered.get(nodeId);
      if (list) list.push(path);
      else covered.set(nodeId, [path]);
    }
  }

  const scored: Omit<ScoredChokePoint, "rank">[] = [];

  for (const [nodeId, transiting] of covered) {
    let score = 0;
    let observedPaths = 0;

    for (const path of transiting) {
      const target = graph.nodes.get(path.targetId);
      const severity = severityFor(target?.sensitivity ?? null, path.evidence);
      const fullyObserved = path.observedEdges === path.edgeIds.length;
      if (fullyObserved) observedPaths += 1;
      score += SEVERITY_WEIGHT[severity] * (fullyObserved ? OBSERVED_MULTIPLIER : 1);
    }

    scored.push({
      nodeId,
      pathsCovered: transiting.length,
      observedPaths,
      score: Math.round(score * 1000) / 1000,
    });
  }

  scored.sort(
    (a, b) => b.score - a.score || b.pathsCovered - a.pathsCovered || a.nodeId.localeCompare(b.nodeId),
  );

  return scored.map((s, i) => ({ ...s, rank: i + 1 }));
}
