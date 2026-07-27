/*
 * Apply every migration in supabase/migrations that has not run yet.
 *
 * Each file runs inside its own transaction and is recorded in
 * schema_migrations, so a failed migration leaves nothing half-applied.
 */
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "pg";

const MIGRATIONS = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "supabase",
  "migrations",
);

async function main() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error("DATABASE_URL is not set (try: npm run db:start)");
  }

  const client = new Client({ connectionString });
  await client.connect();

  await client.query(`
    create table if not exists schema_migrations (
      name        text primary key,
      applied_at  timestamptz not null default now()
    )
  `);

  const { rows } = await client.query<{ name: string }>(
    "select name from schema_migrations",
  );
  const applied = new Set(rows.map((r) => r.name));

  const files = (await readdir(MIGRATIONS))
    .filter((f) => f.endsWith(".sql"))
    .sort();

  let count = 0;
  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = await readFile(join(MIGRATIONS, file), "utf8");
    try {
      await client.query("begin");
      await client.query(sql);
      await client.query("insert into schema_migrations (name) values ($1)", [
        file,
      ]);
      await client.query("commit");
      console.log(`applied ${file}`);
      count += 1;
    } catch (error) {
      await client.query("rollback");
      throw new Error(`migration ${file} failed: ${(error as Error).message}`, {
        cause: error,
      });
    }
  }

  console.log(count === 0 ? "nothing to apply" : `${count} migration(s) applied`);
  await client.end();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
