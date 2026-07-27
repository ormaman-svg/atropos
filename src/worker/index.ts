/*
 * Background scan worker.
 *
 * Claiming is the only cross-tenant operation: the queue has to be read before
 * we know whose scan it is. Everything after the claim runs inside
 * withTenant, so the scan body is subject to the same RLS as a request.
 *
 * `for update skip locked` means several workers can run against one database
 * with no coordination — each claims a different row or none.
 */
import { getPool, withSystem, withTenant } from "../lib/db.js";
import { analyse } from "../lib/graph/engine.js";
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

const WORKER_ID = `${process.env.HOSTNAME ?? "worker"}-${randomUUID().slice(0, 8)}`;
const IDLE_DELAY_MS = 2_000;

type Claim = { id: string; tenant_id: string };

async function claimNextScan(): Promise<Claim | null> {
  return withSystem("claim next queued scan across tenants", async (c) => {
    const { rows } = await c.query<Claim>(
      `select id, tenant_id
         from scan
        where status = 'queued'
        order by queued_at
        for update skip locked
        limit 1`,
    );
    const claim = rows[0];
    if (!claim) return null;

    await c.query(
      `update scan
          set status = 'running', started_at = now(),
              locked_by = $2, locked_at = now()
        where id = $1`,
      [claim.id, WORKER_ID],
    );
    return claim;
  });
}

/**
 * The scan body: enumerate paths, evaluate rules, rank choke points.
 *
 * Connector ingestion still has to land in front of this — today the graph is
 * whatever is already in `node` and `edge`. Analysis over that graph is real.
 */
async function runScan(scanId: string, client: PoolClient): Promise<void> {
  const summary = await analyse(client, scanId);
  await client.query("update scan set stats = $2 where id = $1", [
    scanId,
    JSON.stringify(summary),
  ]);
}

async function processOne(claim: Claim): Promise<void> {
  try {
    await withTenant(claim.tenant_id, async (c) => {
      await runScan(claim.id, c);
      await c.query(
        "update scan set status = 'succeeded', finished_at = now() where id = $1",
        [claim.id],
      );
    });
  } catch (error) {
    // The failure is recorded outside the tenant transaction, which has already
    // rolled back by the time we get here.
    await withSystem("record scan failure", (c) =>
      c.query(
        `update scan
            set status = 'failed', finished_at = now(), error = $2
          where id = $1`,
        [claim.id, (error as Error).message.slice(0, 2000)],
      ),
    );
    console.error(`scan ${claim.id} failed:`, error);
  }
}

async function main() {
  let running = true;
  const stop = () => {
    running = false;
    console.log("shutting down after current scan");
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  console.log(`worker ${WORKER_ID} started`);
  while (running) {
    const claim = await claimNextScan();
    if (claim) {
      await processOne(claim);
    } else {
      await new Promise((r) => setTimeout(r, IDLE_DELAY_MS));
    }
  }
  await getPool().end();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
