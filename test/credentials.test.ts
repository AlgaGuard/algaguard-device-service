import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";
import { randomUUID, X509Certificate } from "node:crypto";
import { OpenSslDevelopmentCaAdapter } from "../src/credential-ca.js";
import {
  createStaticBrokerAuthenticator,
  DeviceCredentialService,
  type BrokerSessionAdapter,
} from "../src/credential-service.js";
import { MemoryCredentialStore } from "../src/credential-store.js";
import {
  DomainError,
  MemoryDeviceRepository,
  type DeviceRecord,
  type DeviceRepository,
} from "../src/domain.js";

const execute = promisify(execFile);

class RecordingBroker implements BrokerSessionAdapter {
  readonly disconnected: string[] = [];
  async disconnectClient(deviceId: string) {
    this.disconnected.push(deviceId);
  }
}

const options = {
  bootstrapTtlMs: 60_000,
  bootstrapAttempts: 2,
  certificateValidityDays: 2,
  rotationOverlapSeconds: 300,
  brokerHost: "mqtt.localhost",
  brokerPort: 8883,
  brokerServerName: "mqtt.localhost",
  brokerKeepAliveSeconds: 60,
  brokerSessionExpirySeconds: 3600,
  brokerAuthCacheSeconds: 30,
  revocationEffectiveWithinSeconds: 30,
};

async function openssl(arguments_: string[]) {
  await execute("openssl", arguments_, {
    encoding: "utf8",
    maxBuffer: 512 * 1024,
    windowsHide: true,
  });
}

async function generateCsr(
  directory: string,
  name: string,
  device: Pick<DeviceRecord, "deviceId" | "deviceUuid">,
) {
  const privateKeyPath = path.join(directory, `${name}.private.pem`);
  const csrPath = path.join(directory, `${name}.csr.pem`);
  await openssl([
    "ecparam",
    "-name",
    "prime256v1",
    "-genkey",
    "-noout",
    "-out",
    privateKeyPath,
  ]);
  await openssl([
    "req",
    "-new",
    "-key",
    privateKeyPath,
    "-subj",
    `/CN=${device.deviceId}`,
    "-addext",
    `subjectAltName=URI:urn:algaguard:device:${device.deviceUuid}`,
    "-out",
    csrPath,
  ]);
  return { csrPem: await readFile(csrPath, "utf8"), privateKeyPath };
}

async function generateUnsupportedCsr(
  directory: string,
  name: string,
  device: Pick<DeviceRecord, "deviceId" | "deviceUuid">,
) {
  const privateKeyPath = path.join(directory, `${name}.private.pem`);
  const csrPath = path.join(directory, `${name}.csr.pem`);
  await openssl(["genpkey", "-algorithm", "Ed25519", "-out", privateKeyPath]);
  await openssl([
    "req",
    "-new",
    "-key",
    privateKeyPath,
    "-subj",
    `/CN=${device.deviceId}`,
    "-addext",
    `subjectAltName=URI:urn:algaguard:device:${device.deviceUuid}`,
    "-out",
    csrPath,
  ]);
  return { csrPem: await readFile(csrPath, "utf8"), privateKeyPath };
}

async function fixture(context: TestContext) {
  const directory = await mkdtemp(
    path.join(tmpdir(), "algaguard-credential-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const caPrivateKeyPath = path.join(directory, "development-ca.private.pem");
  const caCertificatePath = path.join(directory, "development-ca.pem");
  await openssl([
    "ecparam",
    "-name",
    "prime256v1",
    "-genkey",
    "-noout",
    "-out",
    caPrivateKeyPath,
  ]);
  await openssl([
    "req",
    "-new",
    "-x509",
    "-key",
    caPrivateKeyPath,
    "-sha256",
    "-days",
    "2",
    "-subj",
    "/CN=AlgaGuard Development Device CA",
    "-out",
    caCertificatePath,
  ]);
  const repository = new MemoryDeviceRepository();
  const organizationId = "10000000-0000-4000-8000-000000000001";
  const created = await repository.createDevice({
    organizationId,
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  const claim = await repository.createClaim(created.deviceId, 60_000, "owner");
  const claimed = await repository.consumeClaim({
    deviceId: created.deviceId,
    secret: claim.c,
    organizationId,
    subjectId: "owner",
  });
  const device = claimed.device;
  const ca = new OpenSslDevelopmentCaAdapter({
    caCertificatePath,
    caPrivateKeyPath,
    environment: "test",
  });
  const store = new MemoryCredentialStore();
  const broker = new RecordingBroker();
  const service = new DeviceCredentialService(
    repository,
    store,
    ca,
    broker,
    options,
  );
  return {
    directory,
    ca,
    repository,
    store,
    broker,
    service,
    device,
    sessionToken: claimed.bootstrap.sessionToken,
  };
}

test("claim sessions exchange once into an ownership-bound CSR bootstrap", async (context) => {
  const value = await fixture(context);
  const exchanged = await value.service.exchangeBootstrapSession({
    sessionToken: value.sessionToken,
    deviceId: value.device.deviceId,
  });
  assert.equal(exchanged.deviceUuid, value.device.deviceUuid);
  assert.doesNotMatch(
    JSON.stringify(exchanged),
    /private[_-]?key|organizationId/i,
  );
  await assert.rejects(
    value.service.exchangeBootstrapSession({
      sessionToken: value.sessionToken,
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "USED_SESSION_TOKEN",
  );
  const generated = await generateCsr(
    value.directory,
    "exchanged",
    value.device,
  );
  await value.repository.transferOwnership(
    value.device.deviceUuid,
    "10000000-0000-4000-8000-000000000002",
    "owner",
  );
  await assert.rejects(
    value.service.issueInitial({
      token: exchanged.bootstrapToken,
      deviceUuid: exchanged.deviceUuid,
      deviceId: exchanged.deviceId,
      idempotencyKey: randomUUID(),
      keyAlgorithm: "EC_P256",
      csrPem: generated.csrPem,
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "OWNERSHIP_VERSION_CHANGED",
  );
});

async function issueInitial(
  value: Awaited<ReturnType<typeof fixture>>,
  name = "initial",
) {
  const bootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  const generated = await generateCsr(value.directory, name, value.device);
  const idempotencyKey = randomUUID();
  const issued = await value.service.issueInitial({
    token: bootstrap.bootstrapToken,
    deviceUuid: value.device.deviceUuid,
    deviceId: value.device.deviceId,
    idempotencyKey,
    keyAlgorithm: "EC_P256",
    csrPem: generated.csrPem,
  });
  return { bootstrap, generated, idempotencyKey, issued };
}

test("initial issuance consumes a hashed one-time bootstrap and never returns a private key", async (context) => {
  const value = await fixture(context);
  const initial = await issueInitial(value);
  assert.equal(initial.issued.credential.status, "ACTIVE");
  assert.deepEqual(initial.issued.credential.sanUris, [
    `urn:algaguard:device:${value.device.deviceUuid}`,
  ]);
  assert.equal(initial.issued.credential.deviceId, value.device.deviceId);
  assert.equal(
    (await value.repository.getDevice(value.device.deviceUuid))?.lifecycle,
    "ACTIVE",
  );
  assert.doesNotMatch(
    JSON.stringify(initial.issued),
    /private[_-]?key|mqttPassword|organizationId/i,
  );
  const records = await value.store.listCredentials(value.device.deviceUuid);
  assert.equal(records.length, 1);
  assert.ok(records[0]?.certificatePem);
  assert.equal("privateKey" in records[0]!, false);

  const replay = await value.service.issueInitial({
    token: initial.bootstrap.bootstrapToken,
    deviceUuid: value.device.deviceUuid,
    deviceId: value.device.deviceId,
    idempotencyKey: initial.idempotencyKey,
    keyAlgorithm: "EC_P256",
    csrPem: initial.generated.csrPem,
  });
  assert.equal(
    replay.credential.credentialId,
    initial.issued.credential.credentialId,
  );
  await assert.rejects(
    value.service.issueInitial({
      token: initial.bootstrap.bootstrapToken,
      deviceUuid: value.device.deviceUuid,
      deviceId: value.device.deviceId,
      idempotencyKey: randomUUID(),
      keyAlgorithm: "EC_P256",
      csrPem: initial.generated.csrPem,
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "BOOTSTRAP_UNAVAILABLE",
  );
});

test("bootstrap attempts are bounded and malformed CSR leaves explicit failed history", async (context) => {
  const value = await fixture(context);
  const bootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  const generated = await generateCsr(value.directory, "bounded", value.device);
  for (const expectedStatus of [401, 429]) {
    await assert.rejects(
      value.service.issueInitial({
        token: `wrong-${randomUUID()}`,
        deviceUuid: value.device.deviceUuid,
        deviceId: value.device.deviceId,
        idempotencyKey: randomUUID(),
        keyAlgorithm: "EC_P256",
        csrPem: generated.csrPem,
      }),
      (error: unknown) =>
        error instanceof DomainError && error.status === expectedStatus,
    );
  }

  const recoveryBootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  await assert.rejects(
    value.service.issueInitial({
      token: recoveryBootstrap.bootstrapToken,
      deviceUuid: value.device.deviceUuid,
      deviceId: value.device.deviceId,
      idempotencyKey: randomUUID(),
      keyAlgorithm: "EC_P256",
      csrPem:
        "-----BEGIN CERTIFICATE REQUEST-----\n" +
        "MALFORMED".repeat(20) +
        "\n-----END CERTIFICATE REQUEST-----\n",
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "CERTIFICATE_OPERATION_FAILED",
  );
  const history = await value.store.listCredentials(value.device.deviceUuid);
  assert.equal(history[0]?.status, "FAILED");
  assert.equal(history[0]?.revocationReason, "ISSUANCE_ERROR");
});

test("bootstrap rejects unclaimed devices, conflicting identifiers, and unsupported CSR algorithms", async (context) => {
  const value = await fixture(context);
  const unclaimed = await value.repository.createDevice({
    organizationId: "10000000-0000-4000-8000-000000000002",
    hardwareModel: "ESP32-S3-DEVKITC-1-N16R8",
  });
  await assert.rejects(
    value.service.createBootstrap(unclaimed.deviceUuid, "owner"),
    (error: unknown) =>
      error instanceof DomainError && error.code === "DEVICE_UNCLAIMED",
  );

  const bootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  const generated = await generateCsr(
    value.directory,
    "identifier-mismatch",
    value.device,
  );
  await assert.rejects(
    value.service.issueInitial({
      token: bootstrap.bootstrapToken,
      deviceUuid: value.device.deviceUuid,
      deviceId: "AG-999999",
      idempotencyKey: randomUUID(),
      keyAlgorithm: "EC_P256",
      csrPem: generated.csrPem,
    }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "DEVICE_IDENTITY_MISMATCH",
  );

  const unsupportedBootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  const unsupported = await generateUnsupportedCsr(
    value.directory,
    "unsupported-ed25519",
    value.device,
  );
  await assert.rejects(
    value.service.issueInitial({
      token: unsupportedBootstrap.bootstrapToken,
      deviceUuid: value.device.deviceUuid,
      deviceId: value.device.deviceId,
      idempotencyKey: randomUUID(),
      keyAlgorithm: "EC_P256",
      csrPem: unsupported.csrPem,
    }),
    (error: unknown) =>
      error instanceof DomainError &&
      error.code === "CSR_ALGORITHM_UNSUPPORTED",
  );
  assert.equal(
    (await value.store.listCredentials(value.device.deviceUuid))[0]?.status,
    "FAILED",
  );
});

test("concurrent initial issuance permits exactly one credential", async (context) => {
  const value = await fixture(context);
  const bootstrap = await value.service.createBootstrap(
    value.device.deviceUuid,
    "owner",
  );
  const generated = await generateCsr(
    value.directory,
    "concurrent",
    value.device,
  );
  const outcomes = await Promise.allSettled(
    [randomUUID(), randomUUID()].map((idempotencyKey) =>
      value.service.issueInitial({
        token: bootstrap.bootstrapToken,
        deviceUuid: value.device.deviceUuid,
        deviceId: value.device.deviceId,
        idempotencyKey,
        keyAlgorithm: "EC_P256",
        csrPem: generated.csrPem,
      }),
    ),
  );
  assert.equal(
    outcomes.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter((result) => result.status === "rejected").length,
    1,
  );
  assert.equal(
    (await value.store.listCredentials(value.device.deviceUuid)).length,
    1,
  );
});

test("broker authentication binds fingerprint, SAN UUID, CN deviceId, lifecycle, and exact ACLs", async (context) => {
  const value = await fixture(context);
  const initial = await issueInitial(value);
  const allowed = await value.service.authenticateBroker({
    clientId: value.device.deviceId,
    certificatePem: initial.issued.credential.certificatePem!,
  });
  assert.equal(allowed.result, "allow");
  const allowedDer = await value.service.authenticateBroker({
    clientId: value.device.deviceId,
    certificatePem: new X509Certificate(
      initial.issued.credential.certificatePem!,
    ).raw.toString("base64"),
  });
  assert.equal(allowedDer.result, "allow");
  if (allowed.result !== "allow") assert.fail("credential should authenticate");
  assert.equal(
    allowed.acl.filter((rule) => rule.permission === "allow").length,
    10,
  );
  assert.ok(
    allowed.acl.some(
      (rule) =>
        rule.action === "publish" &&
        rule.topic ===
          `algaguard/v1/devices/${value.device.deviceId}/telemetry`,
    ),
  );
  assert.equal(
    allowed.acl.some(
      (rule) => rule.permission === "allow" && /[+#]/.test(rule.topic),
    ),
    false,
  );
  const crossDevice = await value.service.authenticateBroker({
    clientId: "AG-000002",
    certificatePem: initial.issued.credential.certificatePem!,
  });
  assert.equal(crossDevice.result, "deny");
  assert.deepEqual(value.service.getMetrics(), {
    mtlsAccepted: 2,
    credentialMismatch: 1,
    revokedOrExpired: 0,
    inactiveDevice: 0,
  });
});

test("rotation keeps a bounded overlap, proves the new connection, and persistently rejects the old certificate", async (context) => {
  const value = await fixture(context);
  const initial = await issueInitial(value);
  const rotation = await value.service.beginRotation({
    deviceUuid: value.device.deviceUuid,
    actorId: "owner",
    requestKey: randomUUID(),
    reason: "ADMIN_REQUESTED",
  });
  const replacement = await generateCsr(
    value.directory,
    "replacement",
    value.device,
  );
  const issuedReplacement = await value.service.issueRotation({
    rotationId: rotation.rotationId,
    currentCertificatePem: initial.issued.credential.certificatePem!,
    idempotencyKey: randomUUID(),
    keyAlgorithm: "EC_P256",
    csrPem: replacement.csrPem,
  });
  const overlap = await value.store.listCredentials(value.device.deviceUuid);
  assert.equal(
    overlap.filter((credential) => credential.status === "ROTATING").length,
    2,
  );

  const replacementConnection = await value.service.authenticateBroker({
    clientId: value.device.deviceId,
    certificatePem: issuedReplacement.credential.certificatePem!,
  });
  assert.equal(replacementConnection.result, "allow");
  const completed = await value.service.acknowledgeRotation({
    rotationId: rotation.rotationId,
    newCredentialId: issuedReplacement.credential.credentialId,
    result: "CONNECTED",
  });
  assert.equal(completed.lifecycleStatus, "ACTIVE");
  assert.deepEqual(completed.activeCredentialIds, [
    issuedReplacement.credential.credentialId,
  ]);
  assert.ok(value.broker.disconnected.includes(value.device.deviceId));

  const oldResult = await value.service.authenticateBroker({
    clientId: value.device.deviceId,
    certificatePem: initial.issued.credential.certificatePem!,
  });
  const newResult = await value.service.authenticateBroker({
    clientId: value.device.deviceId,
    certificatePem: issuedReplacement.credential.certificatePem!,
  });
  assert.equal(oldResult.result, "deny");
  assert.equal(newResult.result, "allow");

  const restarted = new DeviceCredentialService(
    value.repository,
    value.store,
    value.ca,
    value.broker,
    options,
  );
  assert.equal(
    (
      await restarted.authenticateBroker({
        clientId: value.device.deviceId,
        certificatePem: initial.issued.credential.certificatePem!,
      })
    ).result,
    "deny",
  );
});

test("failed rotation restores the working credential and compromise revocation is immediate", async (context) => {
  const value = await fixture(context);
  const initial = await issueInitial(value);
  const rotation = await value.service.beginRotation({
    deviceUuid: value.device.deviceUuid,
    actorId: "owner",
    requestKey: randomUUID(),
    reason: "RECOVERY",
  });
  const replacement = await generateCsr(
    value.directory,
    "failed-replacement",
    value.device,
  );
  const issuedReplacement = await value.service.issueRotation({
    rotationId: rotation.rotationId,
    currentCertificatePem: initial.issued.credential.certificatePem!,
    idempotencyKey: randomUUID(),
    keyAlgorithm: "EC_P256",
    csrPem: replacement.csrPem,
  });
  await value.service.acknowledgeRotation({
    rotationId: rotation.rotationId,
    newCredentialId: issuedReplacement.credential.credentialId,
    result: "FAILED",
    failureCode: "BROKER_UNREACHABLE",
  });
  assert.equal(
    (
      await value.service.authenticateBroker({
        clientId: value.device.deviceId,
        certificatePem: initial.issued.credential.certificatePem!,
      })
    ).result,
    "allow",
  );
  const revoked = await value.service.revoke({
    deviceUuid: value.device.deviceUuid,
    credentialId: initial.issued.credential.credentialId,
    reason: "COMPROMISED",
    actorId: "owner",
  });
  assert.equal(revoked.status, "COMPROMISED");
  assert.equal(
    (
      await value.service.authenticateBroker({
        clientId: value.device.deviceId,
        certificatePem: initial.issued.credential.certificatePem!,
      })
    ).result,
    "deny",
  );
});

test("unknown, wrong-CA, expired, inactive, and identity-mismatched certificates are denied", async (context) => {
  const value = await fixture(context);
  const initial = await issueInitial(value);
  const unknownDirectory = await mkdtemp(
    path.join(tmpdir(), "algaguard-wrong-ca-"),
  );
  context.after(async () =>
    rm(unknownDirectory, { recursive: true, force: true }),
  );
  const wrong = await generateCsr(unknownDirectory, "unknown", value.device);
  const wrongCertificatePath = path.join(unknownDirectory, "wrong.pem");
  await openssl([
    "req",
    "-new",
    "-x509",
    "-key",
    wrong.privateKeyPath,
    "-days",
    "2",
    "-subj",
    `/CN=${value.device.deviceId}`,
    "-addext",
    `subjectAltName=URI:urn:algaguard:device:${value.device.deviceUuid}`,
    "-out",
    wrongCertificatePath,
  ]);
  assert.equal(
    (
      await value.service.authenticateBroker({
        clientId: value.device.deviceId,
        certificatePem: await readFile(wrongCertificatePath, "utf8"),
      })
    ).result,
    "deny",
  );
  assert.equal(
    (
      await value.service.authenticateBroker(
        {
          clientId: value.device.deviceId,
          certificatePem: initial.issued.credential.certificatePem!,
        },
        new Date(Date.parse(initial.issued.credential.notAfter!) + 1_000),
      )
    ).result,
    "deny",
  );

  const inactiveRepository = Object.create(
    value.repository,
  ) as DeviceRepository;
  inactiveRepository.getDevice = async () => ({
    ...(await value.repository.getDevice(value.device.deviceUuid))!,
    lifecycle: "INACTIVE",
  });
  const inactiveService = new DeviceCredentialService(
    inactiveRepository,
    value.store,
    value.ca,
    value.broker,
    options,
  );
  const fresh = await fixture(context);
  const freshInitial = await issueInitial(fresh, "fresh-inactive");
  const inactiveFreshRepository = Object.create(
    fresh.repository,
  ) as DeviceRepository;
  inactiveFreshRepository.getDevice = async () => ({
    ...(await fresh.repository.getDevice(fresh.device.deviceUuid))!,
    lifecycle: "INACTIVE",
  });
  const inactiveFreshService = new DeviceCredentialService(
    inactiveFreshRepository,
    fresh.store,
    fresh.ca,
    fresh.broker,
    options,
  );
  assert.equal(
    (
      await inactiveFreshService.authenticateBroker({
        clientId: fresh.device.deviceId,
        certificatePem: freshInitial.issued.credential.certificatePem!,
      })
    ).result,
    "deny",
  );
  void inactiveService;
});

test("local development CA is explicitly forbidden in production", () => {
  assert.throws(
    () =>
      new OpenSslDevelopmentCaAdapter({
        caCertificatePath: path.resolve("development-ca.pem"),
        caPrivateKeyPath: path.resolve("development-ca.private.pem"),
        environment: "production",
      }),
    (error: unknown) =>
      error instanceof DomainError && error.code === "DEVELOPMENT_CA_FORBIDDEN",
  );
});

test("broker integration requires an exact service bearer token", () => {
  const authenticate = createStaticBrokerAuthenticator("x".repeat(32));
  assert.doesNotThrow(() => authenticate(`Bearer ${"x".repeat(32)}`));
  assert.throws(
    () => authenticate(`Bearer ${"y".repeat(32)}`),
    (error: unknown) =>
      error instanceof DomainError && error.code === "SERVICE_TOKEN_REQUIRED",
  );
  assert.throws(() => authenticate(undefined));
});
