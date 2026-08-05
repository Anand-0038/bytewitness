import { describe, expect, it } from "vitest";
import {
  hashFile,
  normalizeSignerKeyId,
  parseProof,
  sealFile,
  serializeProof,
  serializeVerificationReport,
  verificationReportFilename,
  verifyFile,
} from "./proof";

describe("ByteWitness proof receipts", () => {
  it("hashes exact bytes with SHA-256", async () => {
    const file = new File(["hello world"], "hello.txt", { type: "text/plain", lastModified: 1 });
    expect(await hashFile(file)).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  });

  it("seals and verifies an unchanged file", async () => {
    const file = new File(["original bytes"], "evidence.txt", { type: "text/plain", lastModified: 2 });
    const { receipt } = await sealFile(file);
    const result = await verifyFile(file, receipt);

    expect(result.status).toBe("verified");
    expect(parseProof(JSON.parse(serializeProof(receipt)))).toEqual(receipt);
  });

  it("separates signer trust from receipt and file verification", async () => {
    const file = new File(["original bytes"], "evidence.txt", { type: "text/plain", lastModified: 2 });
    const { receipt } = await sealFile(file);
    const wrongKeyId = `${receipt.signer.keyId.startsWith("0") ? "1" : "0"}${receipt.signer.keyId.slice(1)}`;

    const withoutExpectedSigner = await verifyFile(file, receipt);
    const expectedSigner = await verifyFile(file, receipt, {
      expectedSignerKeyId: receipt.signer.keyId.toUpperCase(),
    });
    const differentSigner = await verifyFile(file, receipt, { expectedSignerKeyId: wrongKeyId });

    expect(withoutExpectedSigner.signerTrust).toBe("not-established");
    expect(expectedSigner.signerTrust).toBe("expected");
    expect(differentSigner.signerTrust).toBe("different");
    expect(normalizeSignerKeyId(`  ${receipt.signer.keyId.toUpperCase()} `)).toBe(receipt.signer.keyId);
    expect(normalizeSignerKeyId("not-a-key-id")).toBeUndefined();
  });

  it("detects a changed file", async () => {
    const original = new File(["original bytes"], "evidence.txt", { type: "text/plain", lastModified: 2 });
    const changed = new File(["changed bytes"], "evidence.txt", { type: "text/plain", lastModified: 3 });
    const { receipt } = await sealFile(original);
    const result = await verifyFile(changed, receipt);

    expect(result.status).toBe("file-mismatch");
  });

  it("rejects receipt tampering", async () => {
    const file = new File(["original bytes"], "evidence.txt", { type: "text/plain", lastModified: 2 });
    const { receipt } = await sealFile(file);
    const tampered = { ...receipt, createdAt: "2025-01-01T00:00:00.000Z" };
    const result = await verifyFile(file, tampered);

    expect(result.status).toBe("invalid-signature");
    expect(result.signerTrust).toBe("not-established");
  });

  it("writes a human-readable report for a changed file", async () => {
    const original = new File(["original bytes"], "evidence.txt", { type: "text/plain", lastModified: 2 });
    const changed = new File(["changed bytes"], "evidence.txt", { type: "text/plain", lastModified: 3 });
    const { receipt } = await sealFile(original);
    const result = await verifyFile(changed, receipt, { expectedSignerKeyId: receipt.signer.keyId });
    const report = serializeVerificationReport(
      result,
      changed,
      new Date("2026-08-05T12:00:00.000Z"),
      receipt.signer.keyId,
    );

    expect(report).toContain("ByteWitness verification report");
    expect(report).toContain("Failed — receipt signature valid, but file bytes differ");
    expect(report).toContain("Receipt integrity: Valid");
    expect(report).toContain("File integrity: Mismatch");
    expect(report).toContain(`Expected SHA-256: ${receipt.file.sha256}`);
    expect(report).toContain("Calculated SHA-256:");
    expect(report).toContain("Signer trust: Expected signer key matched");
    expect(report).toContain(`Expected signer key ID: ${receipt.signer.keyId}`);
    expect(report).toContain("(local device time)");
    expect(report).toContain("It does not independently prove legal identity");
  });

  it("creates a safe verification report filename", () => {
    expect(verificationReportFilename("client contract (final).pdf")).toBe(
      "client-contract-final-.pdf.bytewitness-report.txt",
    );
  });

  it("reports unavailable checks for malformed receipts", () => {
    const file = new File(["bytes"], "evidence.txt", { type: "text/plain" });
    const report = serializeVerificationReport(
      {
        status: "invalid-proof",
        message: "The receipt format is invalid or unsupported.",
        signerTrust: "not-established",
      },
      file,
      new Date("2026-08-05T12:00:00.000Z"),
    );

    expect(report).toContain("Receipt integrity: Not available");
    expect(report).toContain("File integrity: Not checked");
    expect(report).toContain("Signer trust: Not independently established");
    expect(report).toContain("Reason: The receipt format is invalid or unsupported.");
  });
});
