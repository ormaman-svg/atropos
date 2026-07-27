/*
 * Path engine, against the topology from design/rigel-console.html:
 *
 *   support@ inbox   → triage-agent    ┐
 *   public docs MCP  → docs-assistant  ├→ svc-agent-prod →  CUSTOMER_PII
 *   jira webhook     → release-agent   ┘                    exports bucket
 *                                                           deploy keys
 *
 * The reference console hardcodes three paths. A real engine over the same
 * shape finds nine, because a genuinely shared identity means every untrusted
 * origin reaches every store it grants. That is not a bug in either — it is
 * the console being illustrative and the engine being literal.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { getPool, withTenant } from "@/lib/db";
import { analyse, type AnalysisSummary } from "@/lib/graph/engine";

process.env.DATABASE_URL ??= "postgresql://postgres@localhost:55432/atropos_dev";

let owner: Client;
const tenants: string[] = [];

beforeAll(async () => {
  owner = new Client({ connectionString: process.env.DATABASE_URL });
  await owner.connect();
});

afterAll(async () => {
  for (const id of tenants) {
    await owner.query("delete from tenant where id = $1", [id]);
  }
  await owner.end();
  await getPool().end();
});

// --- fixture helpers -------------------------------------------------------

async function newTenant(label: string): Promise<string> {
  const slug = `${label}-${Date.now()}-${tenants.length}`;
  const { rows } = await owner.query<{ id: string }>(
    "insert into tenant (slug, name) values ($1, $1) returning id",
    [slug],
  );
  const id = rows[0]!.id;
  tenants.push(id);
  return id;
}

interface NodeSpec {
  kind: string;
  name: string;
  sensitivity?: string;
  capabilities?: string[];
  untrusted?: boolean;
  identityClass?: string;
  attributes?: Record<string, unknown>;
}

async function addNode(tenantId: string, spec: NodeSpec): Promise<string> {
  const { rows } = await owner.query<{ id: string }>(
    `insert into node (tenant_id, kind, external_id, name, sensitivity,
                       capabilities, is_untrusted, identity_class, attributes)
     values ($1, $2::node_kind, $3, $3, $4::data_sensitivity,
             $5::tool_capability[], $6, $7::identity_class, $8)
     returning id`,
    [
      tenantId,
      spec.kind,
      spec.name,
      spec.sensitivity ?? null,
      spec.capabilities ?? [],
      spec.untrusted ?? false,
      spec.identityClass ?? null,
      JSON.stringify(spec.attributes ?? {}),
    ],
  );
  return rows[0]!.id;
}

async function addEdge(
  tenantId: string,
  src: string,
  dst: string,
  kind: string,
  observed = false,
): Promise<string> {
  const { rows } = await owner.query<{ id: string }>(
    `insert into edge (tenant_id, src_id, dst_id, kind, observed,
                       exercise_count, observation_window_days)
     values ($1, $2, $3, $4::edge_kind, $5, $6, $7)
     returning id`,
    [tenantId, src, dst, kind, observed, observed ? 412 : 0, observed ? 90 : null],
  );
  return rows[0]!.id;
}

/** The console topology. Returns node name → id. */
async function seedConsole(
  tenantId: string,
  opts: { observed?: boolean } = {},
): Promise<Record<string, string>> {
  const observed = opts.observed ?? false;
  const n: Record<string, string> = {};

  n["inbox"] = await addNode(tenantId, {
    kind: "input_source",
    name: "support@ inbox",
    untrusted: true,
    attributes: { entry_point: "support@acme.example" },
  });
  n["docs"] = await addNode(tenantId, {
    kind: "input_source",
    name: "public docs MCP",
    untrusted: true,
  });
  n["jira"] = await addNode(tenantId, {
    kind: "input_source",
    name: "jira webhook",
    untrusted: true,
  });

  n["triage"] = await addNode(tenantId, { kind: "agent", name: "triage-agent" });
  n["docsAgent"] = await addNode(tenantId, { kind: "agent", name: "docs-assistant" });
  n["release"] = await addNode(tenantId, { kind: "agent", name: "release-agent" });

  n["svc"] = await addNode(tenantId, {
    kind: "identity",
    name: "svc-agent-prod",
    identityClass: "nhi",
  });

  n["pii"] = await addNode(tenantId, {
    kind: "data_store",
    name: "CUSTOMER_PII",
    sensitivity: "regulated",
  });
  n["exports"] = await addNode(tenantId, {
    kind: "data_store",
    name: "exports bucket",
    sensitivity: "confidential",
  });
  n["keys"] = await addNode(tenantId, {
    kind: "data_store",
    name: "deploy keys",
    sensitivity: "confidential",
  });

  await addEdge(tenantId, n["inbox"]!, n["triage"]!, "reachability", observed);
  await addEdge(tenantId, n["docs"]!, n["docsAgent"]!, "reachability", observed);
  await addEdge(tenantId, n["jira"]!, n["release"]!, "reachability", observed);

  for (const agent of ["triage", "docsAgent", "release"]) {
    await addEdge(tenantId, n[agent]!, n["svc"]!, "credential_inheritance", observed);
  }
  for (const store of ["pii", "exports", "keys"]) {
    await addEdge(tenantId, n["svc"]!, n[store]!, "permission", observed);
  }

  return n;
}

async function runScan(tenantId: string): Promise<AnalysisSummary> {
  const { rows } = await owner.query<{ id: string }>(
    "insert into scan (tenant_id, status) values ($1, 'running') returning id",
    [tenantId],
  );
  const scanId = rows[0]!.id;
  return withTenant(tenantId, (c) => analyse(c, scanId));
}

// --- tests -----------------------------------------------------------------

describe("path enumeration", () => {
  it("finds every route from an untrusted origin to a sensitive store", async () => {
    const tenantId = await newTenant("console");
    await seedConsole(tenantId);
    const summary = await runScan(tenantId);

    // 3 untrusted origins × 3 stores reachable through the shared identity.
    expect(summary.paths).toBe(9);
    expect(summary.nodes).toBe(10);
    expect(summary.edges).toBe(9);
  });

  it("does not walk past a target", async () => {
    const tenantId = await newTenant("nopast");
    await seedConsole(tenantId);
    await runScan(tenantId);

    const hops = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ hops: number }>("select distinct hops from attack_path");
      return r.rows.map((x) => x.hops);
    });
    // inbox → agent → identity → store. Every path is exactly three hops.
    expect(hops).toEqual([3]);
  });
});

describe("choke points", () => {
  it("ranks the shared identity first, covering every path", async () => {
    const tenantId = await newTenant("choke");
    const n = await seedConsole(tenantId);
    const summary = await runScan(tenantId);

    expect(summary.topChokePointNodeId).toBe(n["svc"]);

    const top = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ name: string; paths_covered: number; rank: number }>(
        `select nd.name, cp.paths_covered, cp.rank
           from choke_point cp join node nd on nd.id = cp.node_id
          order by cp.rank limit 3`,
      );
      return r.rows;
    });

    expect(top[0]?.name).toBe("svc-agent-prod");
    expect(top[0]?.paths_covered).toBe(9);
    // The agents each sit on three paths, so they rank below the identity.
    expect(top[1]?.paths_covered).toBe(3);
  });
});

describe("rules", () => {
  it("raises one finding per route reaching regulated data", async () => {
    const tenantId = await newTenant("regulated");
    await seedConsole(tenantId);
    await runScan(tenantId);

    const findings = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ rule_id: string; severity: string; technique_ids: string[] }>(
        `select rule_id, severity, technique_ids from finding
          where rule_id = 'untrusted-input-to-regulated-data' and status = 'open'`,
      );
      return r.rows;
    });

    expect(findings).toHaveLength(3);
    expect(findings[0]?.technique_ids).toEqual(
      expect.arrayContaining(["ASI01", "AML.T0086"]),
    );
  });

  it("flags the shared identity", async () => {
    const tenantId = await newTenant("shared");
    await seedConsole(tenantId);
    await runScan(tenantId);

    const rows = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ title: string; detail: { agent_count: number } }>(
        `select title, detail from finding
          where rule_id = 'shared-identity-privilege-inheritance' and status = 'open'`,
      );
      return r.rows;
    });

    expect(rows).toHaveLength(1);
    expect(rows[0]?.detail.agent_count).toBe(3);
  });

  it("raises the lethal trifecta only when all three legs are present", async () => {
    const tenantId = await newTenant("trifecta");
    const n = await seedConsole(tenantId);

    const before = await withTenant(tenantId, async (c) => {
      await analyse(c, (await c.query<{ id: string }>(
        "insert into scan (tenant_id, status) values (current_tenant_id(), 'running') returning id",
      )).rows[0]!.id);
      const r = await c.query("select 1 from finding where rule_id = 'lethal-trifecta'");
      return r.rowCount;
    });
    // No tool with external comms yet: private data and untrusted input only.
    expect(before).toBe(0);

    const slack = await addNode(tenantId, {
      kind: "tool",
      name: "slack-post",
      capabilities: ["external_comms"],
    });
    await addEdge(tenantId, n["triage"]!, slack, "permission");
    await runScan(tenantId);

    const after = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ title: string; detail: Record<string, string[]> }>(
        "select title, detail from finding where rule_id = 'lethal-trifecta' and status = 'open'",
      );
      return r.rows;
    });

    expect(after).toHaveLength(1);
    expect(after[0]?.title).toContain("triage-agent");
    expect(after[0]?.detail.external_comms).toEqual(["slack-post"]);
  });
});

describe("evidence grading", () => {
  it("demotes a route we can only prove structurally", async () => {
    const tenantId = await newTenant("config-only");
    await seedConsole(tenantId, { observed: false });
    await runScan(tenantId);

    const rows = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ evidence: string; severity: string }>(
        `select evidence, severity from finding
          where rule_id = 'untrusted-input-to-regulated-data' limit 1`,
      );
      return r.rows;
    });

    // Regulated data would be critical, but config evidence alone does not
    // earn the word "exploitable", so it lands one below.
    expect(rows[0]?.evidence).toBe("config");
    expect(rows[0]?.severity).toBe("high");
  });

  it("promotes a route whose every edge has been exercised", async () => {
    const tenantId = await newTenant("observed");
    await seedConsole(tenantId, { observed: true });
    await runScan(tenantId);

    const rows = await withTenant(tenantId, async (c) => {
      const r = await c.query<{ evidence: string; severity: string; title: string }>(
        `select f.evidence, f.severity, f.title from finding f
           join attack_path p on p.id = f.path_id
           join node src on src.id = p.source_node_id
          where f.rule_id = 'untrusted-input-to-regulated-data'
          order by src.name`,
      );
      return r.rows;
    });

    // support@ inbox carries a named entry point, so it grades triggerable and
    // is promoted past the others.
    const inbox = rows.find((r) => r.title.startsWith("support@"));
    const jira = rows.find((r) => r.title.startsWith("jira"));
    expect(inbox?.evidence).toBe("triggerable");
    expect(inbox?.severity).toBe("critical");
    expect(jira?.evidence).toBe("observed");
    expect(jira?.severity).toBe("critical");
  });
});

describe("remediation collapse", () => {
  it("resolves findings and clears paths when the choke point is scoped", async () => {
    const tenantId = await newTenant("collapse");
    const n = await seedConsole(tenantId);

    const before = await runScan(tenantId);
    expect(before.paths).toBe(9);
    expect(before.openFindings).toBeGreaterThan(0);

    // The fix from the console: stop the shared identity granting the stores.
    await owner.query("delete from edge where tenant_id = $1 and src_id = $2", [
      tenantId,
      n["svc"],
    ]);

    const after = await runScan(tenantId);
    expect(after.paths).toBe(0);
    expect(after.openFindings).toBe(0);
    expect(after.resolvedFindings).toBe(before.openFindings);

    const open = await withTenant(tenantId, async (c) => {
      const r = await c.query("select 1 from finding where status = 'open'");
      return r.rowCount;
    });
    expect(open).toBe(0);
  });
});
