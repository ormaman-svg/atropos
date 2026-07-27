import { Pool, type PoolClient } from "pg";

let pool: Pool | undefined;

export function getPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
      throw new Error("DATABASE_URL is not set");
    }
    pool = new Pool({ connectionString, max: 10 });
  }
  return pool;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Run a unit of work scoped to one tenant.
 *
 * Everything tenant-facing goes through here. The scope is established two
 * ways at once, both transaction-local:
 *
 *   - `set local role atropos_app` — drops to the non-owning, non-BYPASSRLS
 *     role, so the policies in 0001_tenancy.sql actually apply even if the
 *     pool happens to be connected as a more privileged user.
 *   - `set_config('app.tenant_id', …, true)` — the third argument is
 *     is_local, which scopes the setting to this transaction.
 *
 * Both reset on commit or rollback, so neither can leak onto the next borrower
 * of a pooled connection. That is the whole reason this is a transaction and
 * not a `set` on checkout.
 */
export async function withTenant<T>(
  tenantId: string,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  if (!UUID.test(tenantId)) {
    throw new Error(`withTenant: not a uuid: ${tenantId}`);
  }

  const client = await getPool().connect();
  try {
    await client.query("begin");
    await client.query("set local role atropos_app");
    await client.query("select set_config('app.tenant_id', $1, true)", [
      tenantId,
    ]);
    const result = await fn(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Run a unit of work with no tenant scope, as the owning role.
 *
 * This is the escape hatch and it is deliberately ugly to reach for. It exists
 * for work that is genuinely cross-tenant — the worker claiming the next queued
 * scan is the only current caller. Anything that touches tenant *data* rather
 * than tenant *scheduling* belongs in withTenant instead.
 *
 * Keep the set of callers small enough to audit by reading.
 */
export async function withSystem<T>(
  reason: string,
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  if (!reason) {
    throw new Error("withSystem: a reason is required");
  }
  const client = await getPool().connect();
  try {
    await client.query("begin");
    const result = await fn(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
