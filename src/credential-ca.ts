import { execFile } from "node:child_process";
import {
  X509Certificate,
  createHash,
  createPublicKey,
  randomBytes,
} from "node:crypto";
import {
  chmod,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { DomainError } from "./domain.js";

const execute = promisify(execFile);

export type SupportedKeyAlgorithm = "EC_P256" | "RSA_3072";

export interface InspectedCsr {
  subjectCommonName: string;
  sanUris: string[];
  keyAlgorithm: SupportedKeyAlgorithm;
}

export interface InspectedCertificate {
  certificateSerial: string;
  fingerprintSha256: string;
  certificatePem: string;
  issuerDistinguishedName: string;
  subjectDistinguishedName: string;
  subjectCommonName: string;
  sanUris: string[];
  notBefore: string;
  notAfter: string;
}

export interface IssuedClientCertificate extends InspectedCertificate {
  caChainPem: string[];
}

export interface CertificateAuthorityAdapter {
  inspectCertificateSigningRequest(csrPem: string): Promise<InspectedCsr>;
  issueClientCertificate(input: {
    csrPem: string;
    deviceUuid: string;
    deviceId: string;
    validityDays: number;
  }): Promise<IssuedClientCertificate>;
  revokeCertificate(input: {
    certificateSerial: string;
    reason: string;
    revokedAt: string;
  }): Promise<void>;
  inspectCertificate(certificatePem: string): Promise<InspectedCertificate>;
  getCaChain(): Promise<string[]>;
  validateIssuedCertificate(input: {
    certificatePem: string;
    deviceUuid: string;
    deviceId: string;
  }): Promise<InspectedCertificate>;
}

function sha256Fingerprint(certificate: X509Certificate) {
  return createHash("sha256").update(certificate.raw).digest("hex");
}

function certificateCommonName(subject: string) {
  const match = subject.match(/(?:^|\n|,)CN\s*=\s*([^,\n]+)/);
  if (!match)
    throw new DomainError(
      "CERTIFICATE_IDENTITY_INVALID",
      400,
      "Certificate common name is missing",
    );
  return match[1]!.trim();
}

function sanUris(subjectAltName: string | undefined) {
  if (!subjectAltName) return [];
  return [...subjectAltName.matchAll(/URI:([^,\s]+)/g)].map((match) =>
    match[1]!.trim(),
  );
}

export function inspectPublicCertificate(
  certificatePem: string,
): InspectedCertificate {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certificatePem);
  } catch {
    throw new DomainError(
      "CERTIFICATE_MALFORMED",
      400,
      "Public certificate is malformed",
    );
  }
  return {
    certificateSerial: certificate.serialNumber.toUpperCase(),
    fingerprintSha256: sha256Fingerprint(certificate),
    certificatePem,
    issuerDistinguishedName: certificate.issuer,
    subjectDistinguishedName: certificate.subject,
    subjectCommonName: certificateCommonName(certificate.subject),
    sanUris: sanUris(certificate.subjectAltName),
    notBefore: certificate.validFromDate.toISOString(),
    notAfter: certificate.validToDate.toISOString(),
  };
}

function requireExactBinding(
  value: Pick<
    InspectedCertificate | InspectedCsr,
    "subjectCommonName" | "sanUris"
  >,
  deviceUuid: string,
  deviceId: string,
) {
  const expectedUri = `urn:algaguard:device:${deviceUuid}`;
  if (
    value.subjectCommonName !== deviceId ||
    value.sanUris.length !== 1 ||
    value.sanUris[0] !== expectedUri
  )
    throw new DomainError(
      "CERTIFICATE_IDENTITY_MISMATCH",
      400,
      "Certificate identity does not match the scoped device",
    );
}

export class OpenSslDevelopmentCaAdapter implements CertificateAuthorityAdapter {
  private readonly revocationPath: string;

  constructor(
    private readonly options: {
      caCertificatePath: string;
      caPrivateKeyPath: string;
      opensslPath?: string;
      environment?: string;
    },
  ) {
    if ((options.environment ?? process.env.NODE_ENV) === "production")
      throw new DomainError(
        "DEVELOPMENT_CA_FORBIDDEN",
        503,
        "The local development CA cannot be selected in production",
      );
    if (
      !path.isAbsolute(options.caCertificatePath) ||
      !path.isAbsolute(options.caPrivateKeyPath)
    )
      throw new DomainError(
        "DEVELOPMENT_CA_PATH_INVALID",
        503,
        "Development CA paths must be absolute",
      );
    this.revocationPath = path.join(
      path.dirname(options.caPrivateKeyPath),
      "revocations.json",
    );
  }

  private async openssl(arguments_: string[]) {
    try {
      return await execute(this.options.opensslPath ?? "openssl", arguments_, {
        encoding: "utf8",
        maxBuffer: 512 * 1024,
        windowsHide: true,
      });
    } catch {
      throw new DomainError(
        "CERTIFICATE_OPERATION_FAILED",
        422,
        "Certificate operation failed",
      );
    }
  }

  async inspectCertificateSigningRequest(csrPem: string) {
    const directory = await mkdtemp(path.join(tmpdir(), "algaguard-csr-"));
    const csrPath = path.join(directory, "request.pem");
    try {
      await writeFile(csrPath, csrPem, { encoding: "utf8", mode: 0o600 });
      const verified = await this.openssl([
        "req",
        "-in",
        csrPath,
        "-noout",
        "-verify",
        "-subject",
        "-nameopt",
        "RFC2253",
      ]);
      const text = await this.openssl([
        "req",
        "-in",
        csrPath,
        "-noout",
        "-text",
      ]);
      const publicKeyPem = await this.openssl([
        "req",
        "-in",
        csrPath,
        "-pubkey",
        "-noout",
      ]);
      const subject = `${verified.stdout}\n${verified.stderr}`;
      const commonName = subject.match(/CN\s*=\s*([^,\r\n]+)/m)?.[1]?.trim();
      const uris = [...text.stdout.matchAll(/URI:([^,\s]+)/g)].map((match) =>
        match[1]!.trim(),
      );
      const publicKey = createPublicKey(publicKeyPem.stdout);
      const publicJwk = publicKey.export({ format: "jwk" });
      const isEcP256 =
        publicKey.asymmetricKeyType === "ec" &&
        publicJwk.kty === "EC" &&
        publicJwk.crv === "P-256";
      const isRsa3072 =
        publicKey.asymmetricKeyType === "rsa" &&
        publicKey.asymmetricKeyDetails?.modulusLength === 3072;
      if (!commonName)
        throw new DomainError(
          "CSR_IDENTITY_INVALID",
          400,
          "CSR common name is missing",
        );
      if (!isEcP256 && !isRsa3072)
        throw new DomainError(
          "CSR_ALGORITHM_UNSUPPORTED",
          422,
          "CSR must use EC P-256 or RSA 3072",
        );
      return {
        subjectCommonName: commonName,
        sanUris: uris,
        keyAlgorithm: isEcP256 ? "EC_P256" : "RSA_3072",
      } as InspectedCsr;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  async issueClientCertificate(input: {
    csrPem: string;
    deviceUuid: string;
    deviceId: string;
    validityDays: number;
  }) {
    const inspectedCsr = await this.inspectCertificateSigningRequest(
      input.csrPem,
    );
    requireExactBinding(inspectedCsr, input.deviceUuid, input.deviceId);
    const directory = await mkdtemp(path.join(tmpdir(), "algaguard-issue-"));
    const csrPath = path.join(directory, "request.pem");
    const certificatePath = path.join(directory, "certificate.pem");
    const extensionPath = path.join(directory, "client-extensions.cnf");
    const serial = randomBytes(20).toString("hex").toUpperCase();
    try {
      await writeFile(csrPath, input.csrPem, { encoding: "utf8", mode: 0o600 });
      await writeFile(
        extensionPath,
        [
          "[client_cert]",
          "basicConstraints=critical,CA:FALSE",
          "keyUsage=critical,digitalSignature",
          "extendedKeyUsage=clientAuth",
          "subjectKeyIdentifier=hash",
          "authorityKeyIdentifier=keyid,issuer",
          "",
        ].join("\n"),
        { encoding: "utf8", mode: 0o600 },
      );
      await this.openssl([
        "x509",
        "-req",
        "-in",
        csrPath,
        "-CA",
        this.options.caCertificatePath,
        "-CAkey",
        this.options.caPrivateKeyPath,
        "-set_serial",
        `0x${serial}`,
        "-days",
        String(input.validityDays),
        "-sha256",
        "-copy_extensions",
        "copy",
        "-extfile",
        extensionPath,
        "-extensions",
        "client_cert",
        "-out",
        certificatePath,
      ]);
      const certificatePem = await readFile(certificatePath, "utf8");
      const inspected = await this.validateIssuedCertificate({
        certificatePem,
        deviceUuid: input.deviceUuid,
        deviceId: input.deviceId,
      });
      return { ...inspected, caChainPem: await this.getCaChain() };
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  async revokeCertificate(input: {
    certificateSerial: string;
    reason: string;
    revokedAt: string;
  }) {
    let records: Array<{
      certificateSerial: string;
      reason: string;
      revokedAt: string;
    }> = [];
    try {
      records = JSON.parse(
        await readFile(this.revocationPath, "utf8"),
      ) as typeof records;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (
      !records.some(
        (record) => record.certificateSerial === input.certificateSerial,
      )
    )
      records.push(input);
    const temporaryPath = `${this.revocationPath}.${process.pid}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(records, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await chmod(temporaryPath, 0o600).catch(() => undefined);
    await rename(temporaryPath, this.revocationPath);
  }

  async inspectCertificate(certificatePem: string) {
    return inspectPublicCertificate(certificatePem);
  }

  async getCaChain() {
    return [await readFile(this.options.caCertificatePath, "utf8")];
  }

  async validateIssuedCertificate(input: {
    certificatePem: string;
    deviceUuid: string;
    deviceId: string;
  }) {
    const inspected = inspectPublicCertificate(input.certificatePem);
    requireExactBinding(inspected, input.deviceUuid, input.deviceId);
    const directory = await mkdtemp(path.join(tmpdir(), "algaguard-verify-"));
    const certificatePath = path.join(directory, "certificate.pem");
    try {
      await writeFile(certificatePath, input.certificatePem, {
        encoding: "utf8",
        mode: 0o600,
      });
      await this.openssl([
        "verify",
        "-purpose",
        "sslclient",
        "-CAfile",
        this.options.caCertificatePath,
        certificatePath,
      ]);
      return inspected;
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
}
