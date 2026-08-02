import { sha256 } from "@noble/hashes/sha2.js";
import { z } from "zod";

const PROOF_FORMAT = "bytewitness-proof" as const;
const PROOF_VERSION = 1 as const;
const SIGNING_ALGORITHM = "ECDSA-P256-SHA256" as const;
const CHUNK_SIZE_BYTES = 2 * 1024 * 1024;
const MAX_PROOF_SIZE_BYTES = 512 * 1024;
const KEY_DATABASE = "bytewitness-keys";
const KEY_STORE = "signing-keys";
const KEY_RECORD = "primary-device-key";

const publicKeySchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: z.string().min(1),
    y: z.string().min(1),
    ext: z.boolean().optional(),
    key_ops: z.array(z.string()).optional(),
  })
  .strict();

const fileRecordSchema = z
  .object({
    name: z.string().min(1).max(1024),
    size: z.number().int().nonnegative(),
    type: z.string().max(1024),
    lastModified: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

const signerSchema = z
  .object({
    algorithm: z.literal(SIGNING_ALGORITHM),
    keyId: z.string().regex(/^[a-f0-9]{20}$/),
    publicKey: publicKeySchema,
  })
  .strict();

export const proofReceiptSchema = z
  .object({
    format: z.literal(PROOF_FORMAT),
    version: z.literal(PROOF_VERSION),
    createdAt: z.string().datetime({ offset: true }),
    file: fileRecordSchema,
    signer: signerSchema,
    signature: z.string().regex(/^[A-Za-z0-9_-]+$/),
  })
  .strict();

export type ProofReceipt = z.infer<typeof proofReceiptSchema>;
export type ProgressHandler = (percent: number) => void;

export interface SealResult {
  receipt: ProofReceipt;
  keyStorage: "persistent" | "session";
}

export type VerificationResult =
  | { status: "verified"; receipt: ProofReceipt }
  | { status: "file-mismatch"; receipt: ProofReceipt; actualHash: string }
  | { status: "invalid-signature"; receipt: ProofReceipt }
  | { status: "invalid-proof"; message: string };

interface StoredKeyRecord {
  id: typeof KEY_RECORD;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

interface SigningKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  storage: "persistent" | "session";
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer as ArrayBuffer;
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Proof data contains a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalize(entry)}`).join(",")}}`;
  }
  throw new Error("Proof data contains an unsupported value.");
}

function receiptPayload(receipt: Omit<ProofReceipt, "signature">): ArrayBuffer {
  return new TextEncoder().encode(canonicalize(receipt)).buffer as ArrayBuffer;
}

async function hashText(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

export async function hashFile(file: File, onProgress?: ProgressHandler): Promise<string> {
  const hasher = sha256.create();
  const total = file.size;
  if (total === 0) onProgress?.(100);

  for (let offset = 0; offset < total; offset += CHUNK_SIZE_BYTES) {
    const end = Math.min(offset + CHUNK_SIZE_BYTES, total);
    const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    hasher.update(chunk);
    onProgress?.(Math.round((end / total) * 100));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  return bytesToHex(hasher.digest());
}

async function createKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

function openKeyDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(KEY_STORE)) {
        request.result.createObjectStore(KEY_STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open the local key store."));
  });
}

async function getStoredKey(): Promise<StoredKeyRecord | undefined> {
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(KEY_STORE, "readonly");
    const request = transaction.objectStore(KEY_STORE).get(KEY_RECORD);
    request.onsuccess = () => resolve(request.result as StoredKeyRecord | undefined);
    request.onerror = () => reject(request.error ?? new Error("Could not read the local signing key."));
    transaction.oncomplete = () => database.close();
  });
}

async function storeKey(keyPair: CryptoKeyPair): Promise<void> {
  const database = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(KEY_STORE, "readwrite");
    transaction.objectStore(KEY_STORE).put({
      id: KEY_RECORD,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    } satisfies StoredKeyRecord);
    transaction.oncomplete = () => {
      database.close();
      resolve();
    };
    transaction.onerror = () => {
      database.close();
      reject(transaction.error ?? new Error("Could not save the local signing key."));
    };
  });
}

async function getSigningKey(): Promise<SigningKey> {
  if (typeof indexedDB !== "undefined") {
    try {
      const stored = await getStoredKey();
      if (stored) return { ...stored, storage: "persistent" };
      const created = await createKeyPair();
      await storeKey(created);
      return { ...created, storage: "persistent" };
    } catch {
      // Private browsing and hardened environments can disable IndexedDB.
    }
  }

  const sessionKey = await createKeyPair();
  return { ...sessionKey, storage: "session" };
}

function toPayload(receipt: ProofReceipt): Omit<ProofReceipt, "signature"> {
  const { signature: _signature, ...payload } = receipt;
  return payload;
}

export async function sealFile(file: File, onProgress?: ProgressHandler): Promise<SealResult> {
  const [sha256Hash, signingKey] = await Promise.all([hashFile(file, onProgress), getSigningKey()]);
  const exportedKey = await crypto.subtle.exportKey("jwk", signingKey.publicKey);
  const publicKey = publicKeySchema.parse(exportedKey);
  const keyId = (await hashText(canonicalize(publicKey))).slice(0, 20);

  const payload: Omit<ProofReceipt, "signature"> = {
    format: PROOF_FORMAT,
    version: PROOF_VERSION,
    createdAt: new Date().toISOString(),
    file: {
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: file.lastModified,
      sha256: sha256Hash,
    },
    signer: {
      algorithm: SIGNING_ALGORITHM,
      keyId,
      publicKey,
    },
  };

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    signingKey.privateKey,
    receiptPayload(payload),
  );

  return {
    receipt: { ...payload, signature: bytesToBase64Url(new Uint8Array(signature)) },
    keyStorage: signingKey.storage,
  };
}

export function parseProof(value: unknown): ProofReceipt {
  return proofReceiptSchema.parse(value);
}

export async function parseProofFile(file: File): Promise<ProofReceipt> {
  if (file.size > MAX_PROOF_SIZE_BYTES) throw new Error("Proof files must be smaller than 512 KB.");
  try {
    return parseProof(JSON.parse(await file.text()));
  } catch (error) {
    if (error instanceof z.ZodError) throw new Error("This is not a valid ByteWitness proof receipt.");
    if (error instanceof Error) throw error;
    throw new Error("This proof receipt could not be read.");
  }
}

export async function verifyFile(
  file: File,
  proofValue: unknown,
  onProgress?: ProgressHandler,
): Promise<VerificationResult> {
  let receipt: ProofReceipt;
  try {
    receipt = parseProof(proofValue);
  } catch {
    return { status: "invalid-proof", message: "The receipt format is invalid or unsupported." };
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      receipt.signer.publicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const signatureValid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      base64UrlToBuffer(receipt.signature),
      receiptPayload(toPayload(receipt)),
    );
    if (!signatureValid) return { status: "invalid-signature", receipt };
  } catch {
    return { status: "invalid-signature", receipt };
  }

  const actualHash = await hashFile(file, onProgress);
  if (actualHash !== receipt.file.sha256) return { status: "file-mismatch", receipt, actualHash };
  return { status: "verified", receipt };
}

export function serializeProof(receipt: ProofReceipt): string {
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

export function proofFilename(fileName: string): string {
  const safeName = fileName.replace(/[^a-zA-Z0-9._-]+/gu, "-").replace(/^-+|-+$/gu, "") || "file";
  return `${safeName}.bytewitness.json`;
}
