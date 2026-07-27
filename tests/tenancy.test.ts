/*
 * Cross-tenant isolation.
 *
 * This runs before any feature lands on top of the schema. Per-tenant
 * isolation is something we say out loud in sales conversations, so it gets an
 * executable assertion rather than a design note.
 *
 * The interesting cases are the last two: a policy that filters SELECT but
 * lets a foreign INSERT through, or one that returns everything when the
 * tenant is simply not set, both review as correct.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "pg";
import { getPool, withTenant } from "@/lib/db";

process.env.DATABASE_URL ??=
  "postgresql://postgres@localhost:55432/atropos_dev";

/** Seeds run as superuser, which bypasses RLS — that is the point of a fixture. */
let owner: Client;

const A = { id: "", slug: `acme-${Date.now()}` };
const B = { id: "", slug: `globex-${Date.now()}` };

beforeAll(async () => {
  owner = new Client({ connectionString: process.env.DATABASE_URL });
  await owner.connect();

  for (const t of [A, B]) {
    const { rows } = await owner.query<{ id: string }>(
      "insert into tenant (slug, name) values ($1, $2) returning id",
      [t.slug, t.slug],
    );
    t.id = rows[0]!.id;

    const user = await owner.query<{ id: string }>(
      "insert into app_user (email) values ($1) returning id",
      [`someone@${t.slug}.test`],
    );
    await owner.query(
      "insert into membership (tenant_id, user_id, role) values ($1, $2, 'owner')",
      [t.id, user.rows[0]!.id],
    );
    await owner.query(
      `insert into connection (tenant_id, provider, display_name, external_ref, status)
       values ($1, 'aws', $2, $3, 'active')`,
      [t.id, `${t.slug} prod`, `acct-${t.slug}`],
    );
    await owner.query("insert into scan (tenant_id, status) values ($1, 'queued')", [
      t.id,
    ]);
  }
});

afterAll(async () => {
  for (const t of [A, B]) {
    if (t.id) await owner.query("delete from tenant where id = $1", [t.id]);
  }
  await owner.end();
  await getPool().end();
});

describe("row-level security", () => {
  it("shows a tenant only its own connections", async () => {
    const rows = await withTenant(A.id, async (c) => {
      const r = await c.query<{ tenant_id: string }>("select tenant_id from connection");
      return r.rows;
    });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.tenant_id === A.id)).toBe(true);
  });

  it("shows a tenant only its own scans", async () => {
    const rows = await withTenant(B.id, async (c) => {
      const r = await c.query<{ tenant_id: string }>("select tenant_id from scan");
      return r.rows;
    });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.tenant_id === B.id)).toBe(true);
  });

  it("shows a tenant only its own tenant row", async () => {
    const rows = await withTenant(A.id, async (c) => {
      const r = await c.query<{ id: string }>("select id from tenant");
      return r.rows;
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.id).toBe(A.id);
  });

  it("shows users only through membership in the current tenant", async () => {
    const rows = await withTenant(A.id, async (c) => {
      const r = await c.query<{ email: string }>("select email from app_user");
      return r.rows;
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.email).toBe(`someone@${A.slug}.test`);
  });

  it("refuses an insert attributed to another tenant", async () => {
    await expect(
      withTenant(A.id, (c) =>
        c.query(
          `insert into connection (tenant_id, provider, display_name, external_ref)
           values ($1, 'github', 'smuggled', 'x')`,
          [B.id],
        ),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it("cannot update another tenant's row", async () => {
    const count = await withTenant(A.id, async (c) => {
      const r = await c.query("update connection set display_name = 'hijacked' where tenant_id = $1", [
        B.id,
      ]);
      return r.rowCount;
    });
    expect(count).toBe(0);
  });

  it("cannot delete another tenant's row", async () => {
    const count = await withTenant(A.id, async (c) => {
      const r = await c.query("delete from scan where tenant_id = $1", [B.id]);
      return r.rowCount;
    });
    expect(count).toBe(0);
  });

  it("fails closed when no tenant is set", async () => {
    // The dangerous failure mode: an unscoped connection seeing everything.
    // current_tenant_id() returns NULL, `tenant_id = NULL` is NULL, so no row
    // passes the policy.
    const client = await getPool().connect();
    try {
      await client.query("begin");
      await client.query("set local role atropos_app");
      for (const table of ["connection", "scan", "tenant", "membership", "app_user"]) {
        const r = await client.query(`select 1 from ${table}`);
        expect(r.rowCount, `${table} leaked rows with no tenant set`).toBe(0);
      }
      await client.query("rollback");
    } finally {
      client.release();
    }
  });
});
