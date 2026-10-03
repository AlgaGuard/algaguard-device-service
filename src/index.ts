import * as grpc from "@grpc/grpc-js";
import { createPostgresPool, createRedis } from "./adapters.js";
import { buildApp } from "./app.js";
import { createAuthenticator, GrpcAccessAuthorizer } from "./auth.js";
import { loadConfig } from "./config.js";
import { buildGrpcServer } from "./grpc-server.js";
import { OpenSslDevelopmentCaAdapter } from "./credential-ca.js";
import {
  createStaticBrokerAuthenticator,
  DeviceCredentialService,
  HttpBrokerSessionAdapter,
  NoopBrokerSessionAdapter,
} from "./credential-service.js";
import { PostgresCredentialStore } from "./credential-store.js";
import { DevelopmentCredentialProvider } from "./domain.js";
import { PostgresDeviceRepository } from "./repository.js";
import {
  PhysicalSessionCipher,
  PhysicalSessionHandoffService,
  RedisPhysicalSessionHandoffStore,
  type RedisHandoffClient,
} from "./physical-session-handoff.js";
import { developmentOnboardingWindowMs } from "./development-onboarding-policy.js";
import {
  QrOnboardingGrantSigner,
  QrOnboardingService,
} from "./qr-onboarding.js";
import {
  GrpcPhysicalUnpairCommandVerifier,
  GrpcPhysicalUnpairNotifier,
} from "./physical-unpair.js";

const config = loadConfig();
const onboardingWindowMs = developmentOnboardingWindowMs(
  config.ALGAGUARD_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS,
);
const pool = createPostgresPool(config);
const repository = new PostgresDeviceRepository(pool);
const qrOnboarding =
  config.ALGAGUARD_ENABLE_QR_ONBOARDING === "1"
    ? new QrOnboardingService(
        repository,
        new QrOnboardingGrantSigner(
          config.QR_ONBOARDING_SIGNING_PRIVATE_KEY_PKCS8!,
        ),
        onboardingWindowMs,
      )
    : undefined;
const credentialStore = new PostgresCredentialStore(pool);
const redis =
  config.ALGAGUARD_ENABLE_PHYSICAL_SESSION_HANDOFF === "1"
    ? createRedis(config)
    : undefined;
if (redis) await redis.connect();
const physicalSessionHandoff = redis
  ? new PhysicalSessionHandoffService(
      repository,
      new RedisPhysicalSessionHandoffStore(
        redis as unknown as RedisHandoffClient,
      ),
      PhysicalSessionCipher.fromBase64Url(
        config.PHYSICAL_SESSION_HANDOFF_WRAPPING_KEY!,
      ),
      () => new Date(),
      onboardingWindowMs,
    )
  : undefined;
const credentialLifecycle =
  config.DEVICE_CA_PROVIDER === "local-development"
    ? new DeviceCredentialService(
        repository,
        credentialStore,
        new OpenSslDevelopmentCaAdapter({
          caCertificatePath: config.DEVICE_CA_CERTIFICATE_PATH!,
          caPrivateKeyPath: config.DEVICE_CA_PRIVATE_KEY_PATH!,
          environment: config.NODE_ENV,
        }),
        config.BROKER_MANAGEMENT_URL && config.BROKER_MANAGEMENT_AUTHORIZATION
          ? new HttpBrokerSessionAdapter(
              config.BROKER_MANAGEMENT_URL,
              config.BROKER_MANAGEMENT_AUTHORIZATION,
            )
          : new NoopBrokerSessionAdapter(),
        {
          bootstrapTtlMs: config.DEVICE_BOOTSTRAP_TTL_SECONDS * 1000,
          bootstrapAttempts: config.DEVICE_BOOTSTRAP_MAX_ATTEMPTS,
          certificateValidityDays: config.DEVICE_CERTIFICATE_VALIDITY_DAYS,
          rotationOverlapSeconds: config.DEVICE_ROTATION_OVERLAP_SECONDS,
          brokerHost: config.DEVICE_BROKER_HOST,
          brokerPort: config.DEVICE_BROKER_PORT,
          brokerServerName: config.DEVICE_BROKER_SERVER_NAME,
          brokerKeepAliveSeconds: config.DEVICE_BROKER_KEEPALIVE_SECONDS,
          brokerSessionExpirySeconds:
            config.DEVICE_BROKER_SESSION_EXPIRY_SECONDS,
          brokerAuthCacheSeconds: config.DEVICE_BROKER_AUTH_CACHE_SECONDS,
          revocationEffectiveWithinSeconds:
            config.DEVICE_REVOCATION_EFFECTIVE_SECONDS,
        },
      )
    : undefined;
const authenticate = createAuthenticator();
const server = buildApp({
  repository,
  authenticate,
  authorize: new GrpcAccessAuthorizer(config.ACCESS_SERVICE_GRPC_ADDRESS),
  credentials: new DevelopmentCredentialProvider(),
  ...(credentialLifecycle
    ? {
        credentialLifecycle,
        authenticateBroker: createStaticBrokerAuthenticator(
          config.BROKER_DEVICE_AUTH_TOKEN!,
        ),
      }
    : {}),
  ...(physicalSessionHandoff ? { physicalSessionHandoff } : {}),
  ...(qrOnboarding ? { qrOnboarding } : {}),
  ...(config.COMMAND_SERVICE_GRPC_ADDRESS
    ? {
        physicalUnpairVerifier: new GrpcPhysicalUnpairCommandVerifier(
          config.COMMAND_SERVICE_GRPC_ADDRESS,
        ),
      }
    : {}),
  ...(config.REALTIME_SERVICE_GRPC_ADDRESS
    ? {
        physicalUnpairNotifier: new GrpcPhysicalUnpairNotifier(
          config.REALTIME_SERVICE_GRPC_ADDRESS,
        ),
      }
    : {}),
  ownedDeviceBootstrapReissueEnabled:
    config.ALGAGUARD_ENABLE_OWNED_DEVICE_BOOTSTRAP_REISSUE === "1",
  developmentOnboardingWindowMs: onboardingWindowMs,
  httpBodyLimit: config.HTTP_BODY_LIMIT,
}).listen(config.PORT, () => {
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-device-service", message: "listening", port: config.PORT })}\n`,
  );
});

const grpcServer = buildGrpcServer({ repository, authenticate });
grpcServer.bindAsync(
  `0.0.0.0:${config.GRPC_PORT}`,
  grpc.ServerCredentials.createInsecure(),
  (error, port) => {
    if (error) throw error;
    process.stdout.write(
      `${JSON.stringify({ level: "info", service: "algaguard-device-service", message: "grpc listening", port })}\n`,
    );
  },
);

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(
    `${JSON.stringify({ level: "info", service: "algaguard-device-service", message: "shutdown", signal })}\n`,
  );
  const deadline = setTimeout(() => process.exit(1), 10_000);
  deadline.unref();
  grpcServer.tryShutdown(() => {});
  server.close(async (error) => {
    try {
      await repository.close();
      await redis?.close();
      clearTimeout(deadline);
      process.exit(error ? 1 : 0);
    } catch {
      process.exit(1);
    }
  });
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
