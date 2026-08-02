import { describe, expect, it } from "vitest";
import { hashFile, parseProof, sealFile, serializeProof, verifyFile } from "./proof";

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
  });
});
