import { proofFilename, serializeProof, type ProofReceipt } from "./proof";

const DEMO_FILENAME = "bytewitness-demo.txt";
const DEMO_TYPE = "text/plain";
const DEMO_LAST_MODIFIED = Date.UTC(2026, 7, 5, 12, 0, 0);

const ORIGINAL_CONTENT = `Project handoff checklist

ByteWitness demo file
Version: approved
Recipient: design-review@example.test
`;

const CHANGED_CONTENT = `Project handoff checklist

ByteWitness demo file
Version: revised
Recipient: design-review@example.test
`;

export interface DemoFiles {
  original: File;
  changed: File;
}

export function createDemoFiles(): DemoFiles {
  return {
    original: new File([ORIGINAL_CONTENT], DEMO_FILENAME, {
      type: DEMO_TYPE,
      lastModified: DEMO_LAST_MODIFIED,
    }),
    changed: new File([CHANGED_CONTENT], DEMO_FILENAME, {
      type: DEMO_TYPE,
      lastModified: DEMO_LAST_MODIFIED + 1_000,
    }),
  };
}

export function createReceiptFile(receipt: ProofReceipt): File {
  return new File([serializeProof(receipt)], proofFilename(receipt.file.name), {
    type: "application/json",
  });
}

export function createTamperedReceiptFile(receipt: ProofReceipt): File {
  const tamperedReceipt: ProofReceipt = {
    ...receipt,
    createdAt: new Date(0).toISOString(),
  };

  return new File([serializeProof(tamperedReceipt)], proofFilename(receipt.file.name), {
    type: "application/json",
  });
}
