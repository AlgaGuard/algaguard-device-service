import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
const pool = new pg.Pool({ connectionString: databaseUrl, max: 1 });
const client = await pool.connect();
try {
  await client.query(
    "SELECT pg_advisory_lock(hashtext('algaguard-device-service-migrations'))",
  );
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    service text NOT NULL, filename text NOT NULL, sha256 text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (service, filename)
  )`);
  const files = (await readdir(path.resolve("migrations")))
    .filter((value) => /^\d+_.+\.sql$/.test(value))
    .sort();
  for (const filename of files) {
    const sql = await readFile(path.resolve("migrations", filename), "utf8");
    const sha256 = createHash("sha256").update(sql).digest("hex");
    const applied = await client.query(
      "SELECT sha256 FROM schema_migrations WHERE service = $1 AND filename = $2",
      ["algaguard-device-service", filename],
    );
    if (applied.rows[0]) {
      if (applied.rows[0].sha256 !== sha256)
        throw new Error(`Applied migration changed: ${filename}`);
      continue;
    }
    await client.query("BEGIN");
    try {
      await client.query(sql);
      await client.query(
        "INSERT INTO schema_migrations(service, filename, sha256) VALUES ($1, $2, $3)",
        ["algaguard-device-service", filename, sha256],
      );
      await client.query("COMMIT");
      process.stdout.write(
        `${JSON.stringify({ migration: filename, status: "applied" })}\n`,
      );
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
} finally {
  await client.query(
    "SELECT pg_advisory_unlock(hashtext('algaguard-device-service-migrations'))",
  );
  client.release();
  await pool.end();
}
