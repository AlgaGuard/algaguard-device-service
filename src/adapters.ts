import pg from "pg";
import { createClient } from "redis";
import type { ServiceConfig } from "./config.js";
export function createPostgresPool(config: ServiceConfig) {
  return new pg.Pool({
    connectionString: config.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30_000,
  });
}
export function createRedis(config: ServiceConfig) {
  return createClient({ url: config.REDIS_URL });
}
