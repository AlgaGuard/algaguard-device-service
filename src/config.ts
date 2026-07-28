import { z } from "zod";

const environmentSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    DATABASE_URL: z.string().min(1),
    REDIS_URL: z.string().url(),
    ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF: z.enum(["0", "1"]).default("0"),
    PHYSICAL_SESSION_HANDOFF_WRAPPING_KEY: z.string().min(1).optional(),
    HTTP_BODY_LIMIT: z
      .string()
      .regex(/^[1-9][0-9]*(kb|mb)$/i)
      .default("256kb"),
    DEVICE_CA_PROVIDER: z
      .enum(["disabled", "local-development"])
      .default("disabled"),
    DEVICE_CA_CERTIFICATE_PATH: z.string().min(1).optional(),
    DEVICE_CA_PRIVATE_KEY_PATH: z.string().min(1).optional(),
    DEVICE_CERTIFICATE_VALIDITY_DAYS: z.coerce
      .number()
      .int()
      .min(1)
      .max(397)
      .default(90),
    DEVICE_BOOTSTRAP_TTL_SECONDS: z.coerce
      .number()
      .int()
      .min(60)
      .max(3600)
      .default(600),
    DEVICE_BOOTSTRAP_MAX_ATTEMPTS: z.coerce
      .number()
      .int()
      .min(1)
      .max(20)
      .default(5),
    DEVICE_ROTATION_OVERLAP_SECONDS: z.coerce
      .number()
      .int()
      .min(30)
      .max(86400)
      .default(300),
    DEVICE_BROKER_HOST: z.string().min(1).max(253).default("emqx"),
    DEVICE_BROKER_PORT: z.coerce.number().int().min(1).max(65535).default(8883),
    DEVICE_BROKER_SERVER_NAME: z.string().min(1).max(253).default("emqx"),
    DEVICE_BROKER_KEEPALIVE_SECONDS: z.coerce
      .number()
      .int()
      .min(15)
      .max(3600)
      .default(60),
    DEVICE_BROKER_SESSION_EXPIRY_SECONDS: z.coerce
      .number()
      .int()
      .min(0)
      .max(604800)
      .default(3600),
    DEVICE_BROKER_AUTH_CACHE_SECONDS: z.coerce
      .number()
      .int()
      .min(1)
      .max(300)
      .default(30),
    DEVICE_REVOCATION_EFFECTIVE_SECONDS: z.coerce
      .number()
      .int()
      .min(0)
      .max(300)
      .default(30),
    BROKER_DEVICE_AUTH_TOKEN: z.string().min(32).optional(),
    BROKER_MANAGEMENT_URL: z.string().url().optional(),
    BROKER_MANAGEMENT_AUTHORIZATION: z.string().min(1).optional(),
    LOG_LEVEL: z
      .enum(["fatal", "error", "warn", "info", "debug", "trace"])
      .default("info"),
  })
  .superRefine((value, context) => {
    if (value.ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF === "1") {
      if (value.NODE_ENV !== "development" && value.NODE_ENV !== "test")
        context.addIssue({
          code: "custom",
          path: ["ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF"],
          message: "physical session handoff is development-only",
        });
      const key = value.PHYSICAL_SESSION_HANDOFF_WRAPPING_KEY;
      if (!key || Buffer.from(key, "base64url").length !== 32)
        context.addIssue({
          code: "custom",
          path: ["PHYSICAL_SESSION_HANDOFF_WRAPPING_KEY"],
          message: "a 32-byte base64url wrapping key is required",
        });
    }
    if (value.DEVICE_CA_PROVIDER === "local-development") {
      if (value.NODE_ENV === "production")
        context.addIssue({
          code: "custom",
          path: ["DEVICE_CA_PROVIDER"],
          message: "local development CA is forbidden in production",
        });
      if (!value.DEVICE_CA_CERTIFICATE_PATH)
        context.addIssue({
          code: "custom",
          path: ["DEVICE_CA_CERTIFICATE_PATH"],
          message: "CA certificate path is required",
        });
      if (!value.DEVICE_CA_PRIVATE_KEY_PATH)
        context.addIssue({
          code: "custom",
          path: ["DEVICE_CA_PRIVATE_KEY_PATH"],
          message: "CA private key path is required",
        });
      if (!value.BROKER_DEVICE_AUTH_TOKEN)
        context.addIssue({
          code: "custom",
          path: ["BROKER_DEVICE_AUTH_TOKEN"],
          message: "broker service token is required",
        });
    }
  });
export type ServiceConfig = z.infer<typeof environmentSchema>;
export function loadConfig(
  environment: NodeJS.ProcessEnv = process.env,
): ServiceConfig {
  return environmentSchema.parse(environment);
}
