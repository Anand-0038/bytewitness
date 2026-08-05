import {
  Asterisk,
  ArrowRight,
  BracketsCurly,
  Check,
  Copy,
  DownloadSimple,
  File,
  FileImage,
  FileText,
  FileVideo,
  Fingerprint,
  Key,
  LockKey,
  MagnifyingGlass,
  Play,
  SealCheck,
  ShieldCheck,
  Stamp,
  UploadSimple,
  Warning,
  X,
} from "@phosphor-icons/react";
import { type ChangeEvent, type DragEvent, useCallback, useRef, useState } from "react";
import {
  parseProofFile,
  normalizeSignerKeyId,
  proofFilename,
  sealFile,
  serializeProof,
  serializeVerificationReport,
  verificationReportFilename,
  verifyFile,
  type ProofReceipt,
  type SignerTrust,
  type VerificationResult,
} from "./lib/proof";
import { createDemoFiles, createReceiptFile, createTamperedReceiptFile } from "./lib/demo";

type Mode = "seal" | "verify";
type ProcessState = "idle" | "working" | "success" | "error";
type KeyCopyState = "copied" | "idle" | "unavailable";
type DemoStage =
  | "idle"
  | "sample-selected"
  | "sample-sealed"
  | "changed-ready"
  | "changed-detected"
  | "tampered-ready"
  | "complete";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function shortHash(hash: string): string {
  return `${hash.slice(0, 18)}…${hash.slice(-12)}`;
}

function readableError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Something unexpected happened. Your file was not changed or uploaded.";
}

function downloadText(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

interface FilePickerProps {
  id: string;
  label: string;
  hint: string;
  file?: globalThis.File;
  accept?: string;
  onFile: (file: globalThis.File) => void;
  compact?: boolean;
}

function FilePicker({ id, label, hint, file, accept, onFile, compact = false }: FilePickerProps) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = (event: DragEvent<HTMLFieldSetElement>) => {
    event.preventDefault();
    setDragging(false);
    const droppedFile = event.dataTransfer.files.item(0);
    if (droppedFile) onFile(droppedFile);
  };

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.item(0);
    if (selectedFile) onFile(selectedFile);
    event.target.value = "";
  };

  return (
    <fieldset
      className={`file-picker ${compact ? "file-picker--compact" : ""} ${dragging ? "is-dragging" : ""} ${file ? "has-file" : ""}`}
      onDragEnter={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={handleDrop}
    >
      <legend className="sr-only">{label} file picker</legend>
      <div className="file-picker__icon" aria-hidden="true">
        {file ? (
          <File size={compact ? 32 : 56} weight="duotone" />
        ) : (
          <UploadSimple size={compact ? 32 : 58} weight="bold" />
        )}
      </div>
      <div className="file-picker__copy">
        <p className="file-picker__label">{file ? file.name : label}</p>
        <p className="file-picker__hint">
          {file ? `${formatBytes(file.size)} · ${file.type || "Unknown type"}` : hint}
        </p>
      </div>
      <button className="text-button" type="button" onClick={() => inputRef.current?.click()}>
        {file ? "Replace" : "Browse"}
      </button>
      <input
        ref={inputRef}
        id={id}
        className="sr-only"
        type="file"
        accept={accept}
        aria-label={label}
        onChange={handleChange}
      />
    </fieldset>
  );
}

function Progress({ percent, label }: { percent: number; label: string }) {
  return (
    <div className="progress" role="status" aria-live="polite">
      <div className="progress__meta">
        <span>{label}</span>
        <span>{percent}%</span>
      </div>
      <div className="progress__track" aria-hidden="true">
        <div className="progress__bar" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

interface ProofDetailsProps {
  copyState: KeyCopyState;
  onCopyKey: () => void;
  receipt: ProofReceipt;
}

function ProofDetails({ copyState, onCopyKey, receipt }: ProofDetailsProps) {
  return (
    <dl className="proof-details">
      <div>
        <dt>SHA-256 fingerprint</dt>
        <dd title={receipt.file.sha256}>{shortHash(receipt.file.sha256)}</dd>
      </div>
      <div>
        <dt>Signing key</dt>
        <div className="proof-details__value">
          <dd>{receipt.signer.keyId}</dd>
          <button
            type="button"
            className="text-button proof-details__copy"
            onClick={onCopyKey}
            aria-label="Copy signer key ID"
          >
            {copyState === "copied" ? (
              <Check size={16} weight="bold" aria-hidden="true" />
            ) : (
              <Copy size={16} weight="bold" aria-hidden="true" />
            )}
            {copyState === "copied" ? "Copied" : "Copy key ID"}
          </button>
        </div>
        <span className="proof-details__copy-status" aria-live="polite">
          {copyState === "copied"
            ? "Share this key ID through a trusted channel."
            : copyState === "unavailable"
              ? "Clipboard unavailable; select the key ID manually."
              : "Use this ID when a verifier needs to confirm the expected signer."}
        </span>
      </div>
      <div>
        <dt>Receipt creation time — device clock</dt>
        <dd>
          {new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
            new Date(receipt.createdAt),
          )}
        </dd>
      </div>
    </dl>
  );
}

function ResultBanner({ result }: { result: VerificationResult }) {
  if (result.status === "verified") {
    return (
      <div className="result result--success" role="status">
        <SealCheck size={34} weight="fill" aria-hidden="true" />
        <div>
          <h3>File match confirmed. Receipt signature valid.</h3>
          <p>This file has the same SHA-256 fingerprint as the signed receipt.</p>
        </div>
      </div>
    );
  }
  if (result.status === "file-mismatch") {
    return (
      <div className="result result--danger" role="alert">
        <Warning size={34} weight="fill" aria-hidden="true" />
        <div>
          <h3>Receipt signature valid; file mismatch detected.</h3>
          <p>
            The receipt contents are unchanged since they were signed, but the selected file has different
            bytes.
          </p>
        </div>
      </div>
    );
  }
  if (result.status === "invalid-signature") {
    return (
      <div className="result result--danger" role="alert">
        <X size={34} weight="bold" aria-hidden="true" />
        <div>
          <h3>Receipt signature is invalid.</h3>
          <p>The proof contents or signature were changed. Do not trust this receipt.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="result result--danger" role="alert">
      <X size={34} weight="bold" aria-hidden="true" />
      <div>
        <h3>Proof could not be verified.</h3>
        <p>{result.message}</p>
      </div>
    </div>
  );
}

interface VerificationCheckProps {
  detail: string;
  label: string;
  tone: "danger" | "muted" | "success" | "warning";
  value: string;
}

function VerificationCheck({ detail, label, tone, value }: VerificationCheckProps) {
  return (
    <div className={`verification-check verification-check--${tone}`}>
      <div className="verification-check__heading">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <p>{detail}</p>
    </div>
  );
}

function signerTrustCheck(trust: SignerTrust): VerificationCheckProps {
  switch (trust) {
    case "expected":
      return {
        label: "Signer trust",
        value: "Expected signer",
        detail: "The receipt key ID matches the key ID you supplied.",
        tone: "success",
      };
    case "different":
      return {
        label: "Signer trust",
        value: "Different signer",
        detail: "The receipt is internally valid, but its key ID does not match the expected signer.",
        tone: "danger",
      };
    case "not-established":
      return {
        label: "Signer trust",
        value: "Not established",
        detail: "No independently trusted signer key ID was supplied.",
        tone: "muted",
      };
  }
}

function VerificationChecks({ result }: { result: VerificationResult }) {
  const receiptCheck: VerificationCheckProps =
    result.status === "invalid-proof"
      ? {
          label: "Receipt integrity",
          value: "Not available",
          detail: "The receipt could not be parsed as a supported ByteWitness proof.",
          tone: "muted",
        }
      : result.status === "invalid-signature"
        ? {
            label: "Receipt integrity",
            value: "Invalid",
            detail: "The signed receipt fields or signature cannot be trusted.",
            tone: "danger",
          }
        : {
            label: "Receipt integrity",
            value: "Valid",
            detail: "The receipt signature is valid for the public key included in that receipt.",
            tone: "success",
          };

  const fileCheck: VerificationCheckProps =
    result.status === "verified"
      ? {
          label: "File integrity",
          value: "Match",
          detail: "The selected file has the same SHA-256 fingerprint as the receipt.",
          tone: "success",
        }
      : result.status === "file-mismatch"
        ? {
            label: "File integrity",
            value: "Mismatch",
            detail: "The selected file has different bytes from the file recorded in the receipt.",
            tone: "danger",
          }
        : {
            label: "File integrity",
            value: "Not checked",
            detail: "File bytes are checked only after the receipt passes signature validation.",
            tone: "muted",
          };

  return (
    <fieldset className="verification-checks">
      <legend className="sr-only">Verification checks</legend>
      <VerificationCheck {...receiptCheck} />
      <VerificationCheck {...fileCheck} />
      <VerificationCheck {...signerTrustCheck(result.signerTrust)} />
    </fieldset>
  );
}

interface ExpectedSignerFieldProps {
  error?: string;
  onChange: (value: string) => void;
  value: string;
}

function ExpectedSignerField({ error, onChange, value }: ExpectedSignerFieldProps) {
  return (
    <div className="expected-signer">
      <div className="expected-signer__label">
        <label htmlFor="expected-signer-key">Expected signer key ID</label>
        <span>Optional</span>
      </div>
      <p id="expected-signer-help">
        Paste a 20-character key ID received through a channel you already trust. ByteWitness cannot establish
        identity from the receipt alone.
      </p>
      <div className="expected-signer__input">
        <input
          id="expected-signer-key"
          type="text"
          value={value}
          placeholder="e.g. 4f9a…c2d1"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-describedby="expected-signer-help"
          aria-invalid={Boolean(error)}
          onChange={(event) => onChange(event.target.value)}
        />
        {value ? (
          <button type="button" className="text-button" onClick={() => onChange("")}>
            Clear
          </button>
        ) : null}
      </div>
      {error ? (
        <p className="inline-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

function ReceiptExplainer() {
  return (
    <details className="receipt-explainer">
      <summary>
        <BracketsCurly size={24} weight="bold" aria-hidden="true" />
        <span>
          <strong>What is inside this receipt?</strong>
          <small>Read the signed fields in plain language</small>
        </span>
      </summary>
      <div className="receipt-explainer__body">
        <p>
          Every field below is covered by the receipt signature, so changing one field breaks verification.
        </p>
        <dl>
          <div>
            <dt>File fingerprint</dt>
            <dd>The SHA-256 digest of the exact bytes that were sealed.</dd>
          </div>
          <div>
            <dt>Signer key ID</dt>
            <dd>A short identifier for this browser’s signing key. It is continuity, not legal identity.</dd>
          </div>
          <div>
            <dt>Public key</dt>
            <dd>The non-secret key used to check that the receipt signature is valid.</dd>
          </div>
          <div>
            <dt>Created at</dt>
            <dd>
              The clock value reported by the device when the receipt was created, not a trusted timestamp.
            </dd>
          </div>
        </dl>
      </div>
    </details>
  );
}

interface GuidedDemoPanelProps {
  stage: DemoStage;
  onContinue: () => void;
  onRestart: () => void;
}

function GuidedDemoPanel({ stage, onContinue, onRestart }: GuidedDemoPanelProps) {
  if (stage === "idle") return null;

  const content = {
    "sample-selected": {
      eyebrow: "Guided demo · ready",
      title: "Create a proof for the sample file.",
      body: "This local sample lets you demonstrate both failure states without preparing files in advance.",
      action: null,
    },
    "sample-sealed": {
      eyebrow: "Guided demo · step 1 of 3",
      title: "The sample is sealed. Now test changed bytes.",
      body: "ByteWitness will switch to Verify a proof with a changed copy selected. The verification still runs for real.",
      action: "Test changed bytes",
    },
    "changed-ready": {
      eyebrow: "Guided demo · step 2 of 3",
      title: "Verify the changed sample.",
      body: "Click Verify integrity to show that a receipt with a valid signature cannot make different file bytes pass.",
      action: null,
    },
    "changed-detected": {
      eyebrow: "Guided demo · step 2 complete",
      title: "Changed bytes detected. Now edit the receipt.",
      body: "The next step restores the original sample and alters a signed receipt field so you can show signature failure too.",
      action: "Test tampered receipt",
    },
    "tampered-ready": {
      eyebrow: "Guided demo · step 3 of 3",
      title: "Verify the edited receipt.",
      body: "Click Verify integrity to prove that changing the timestamp or any other signed field invalidates the receipt.",
      action: null,
    },
    complete: {
      eyebrow: "Guided demo · complete",
      title: "You showed both tampering paths.",
      body: "The file mismatch and invalid-signature results came from the same real verification flow used for any file and receipt.",
      action: "Run the sample again",
    },
  }[stage];

  return (
    <aside className="demo-guide" aria-live="polite">
      <div className="demo-guide__copy">
        <p>{content.eyebrow}</p>
        <h3>{content.title}</h3>
        <span>{content.body}</span>
      </div>
      {content.action ? (
        <button
          className="secondary-button demo-guide__action"
          type="button"
          onClick={stage === "complete" ? onRestart : onContinue}
        >
          {content.action}
          {stage === "complete" ? <Play size={20} weight="bold" /> : <ArrowRight size={20} weight="bold" />}
        </button>
      ) : null}
    </aside>
  );
}

export function App() {
  const [mode, setMode] = useState<Mode>("seal");
  const [sealState, setSealState] = useState<ProcessState>("idle");
  const [sealProgress, setSealProgress] = useState(0);
  const [sealError, setSealError] = useState<string>();
  const [selectedFile, setSelectedFile] = useState<globalThis.File>();
  const [receipt, setReceipt] = useState<ProofReceipt>();
  const [keyStorage, setKeyStorage] = useState<"persistent" | "session">();
  const [keyCopyState, setKeyCopyState] = useState<KeyCopyState>("idle");
  const [verifyFileSelection, setVerifyFileSelection] = useState<globalThis.File>();
  const [proofFile, setProofFile] = useState<globalThis.File>();
  const [verifyState, setVerifyState] = useState<ProcessState>("idle");
  const [verifyProgress, setVerifyProgress] = useState(0);
  const [verifyError, setVerifyError] = useState<string>();
  const [verificationResult, setVerificationResult] = useState<VerificationResult>();
  const [verificationCompletedAt, setVerificationCompletedAt] = useState<Date>();
  const [expectedSignerKeyId, setExpectedSignerKeyId] = useState("");
  const [expectedSignerError, setExpectedSignerError] = useState<string>();
  const [demoOriginal, setDemoOriginal] = useState<globalThis.File>();
  const [demoChanged, setDemoChanged] = useState<globalThis.File>();
  const [demoStage, setDemoStage] = useState<DemoStage>("idle");

  const clearVerificationResult = useCallback(() => {
    setVerifyState("idle");
    setVerifyProgress(0);
    setVerifyError(undefined);
    setVerificationResult(undefined);
    setVerificationCompletedAt(undefined);
  }, []);

  const resetSeal = useCallback(() => {
    setSealState("idle");
    setSealProgress(0);
    setSealError(undefined);
    setReceipt(undefined);
    setKeyStorage(undefined);
    setKeyCopyState("idle");
  }, []);

  const selectSealFile = useCallback(
    (file: globalThis.File) => {
      resetSeal();
      setSelectedFile(file);
      setDemoOriginal(undefined);
      setDemoChanged(undefined);
      setDemoStage("idle");
    },
    [resetSeal],
  );

  const handleLoadDemo = () => {
    const files = createDemoFiles();
    resetSeal();
    clearVerificationResult();
    setSelectedFile(files.original);
    setVerifyFileSelection(undefined);
    setProofFile(undefined);
    setExpectedSignerKeyId("");
    setExpectedSignerError(undefined);
    setDemoOriginal(files.original);
    setDemoChanged(files.changed);
    setDemoStage("sample-selected");
    setMode("seal");
  };

  const handleSeal = async () => {
    if (!selectedFile || sealState === "working") return;
    setSealState("working");
    setSealError(undefined);
    setSealProgress(0);
    try {
      const result = await sealFile(selectedFile, setSealProgress);
      setReceipt(result.receipt);
      setKeyStorage(result.keyStorage);
      setSealState("success");
      setDemoStage(demoOriginal === selectedFile ? "sample-sealed" : "idle");
    } catch (error) {
      setSealError(readableError(error));
      setSealState("error");
    }
  };

  const handleDownload = () => {
    if (!receipt) return;
    downloadText(proofFilename(receipt.file.name), serializeProof(receipt), "application/json");
  };

  const handleCopySignerKey = async () => {
    if (!receipt || !navigator.clipboard) {
      setKeyCopyState("unavailable");
      return;
    }
    try {
      await navigator.clipboard.writeText(receipt.signer.keyId);
      setKeyCopyState("copied");
    } catch {
      setKeyCopyState("unavailable");
    }
  };

  const handleDownloadReport = () => {
    if (!verificationResult || !verifyFileSelection) return;
    const normalizedExpectedSignerKeyId = normalizeSignerKeyId(expectedSignerKeyId);
    const report = serializeVerificationReport(
      verificationResult,
      verifyFileSelection,
      verificationCompletedAt ?? new Date(),
      normalizedExpectedSignerKeyId,
    );
    downloadText(verificationReportFilename(verifyFileSelection.name), report, "text/plain;charset=utf-8");
  };

  const prepareGuidedChangedFile = () => {
    if (!receipt || !demoChanged) return;
    setMode("verify");
    setVerifyFileSelection(demoChanged);
    setProofFile(createReceiptFile(receipt));
    clearVerificationResult();
    setDemoStage("changed-ready");
    window.requestAnimationFrame(() => document.querySelector<HTMLElement>(".workspace")?.focus());
  };

  const prepareGuidedTamperedReceipt = () => {
    if (!receipt || !demoOriginal) return;
    setMode("verify");
    setVerifyFileSelection(demoOriginal);
    setProofFile(createTamperedReceiptFile(receipt));
    clearVerificationResult();
    setDemoStage("tampered-ready");
    window.requestAnimationFrame(() => document.querySelector<HTMLElement>(".workspace")?.focus());
  };

  const handleVerify = async () => {
    if (!verifyFileSelection || !proofFile || verifyState === "working") return;
    const normalizedExpectedSignerKeyId = normalizeSignerKeyId(expectedSignerKeyId);
    if (expectedSignerKeyId.trim() && !normalizedExpectedSignerKeyId) {
      setExpectedSignerError(
        "Enter the 20-character hexadecimal key ID shown in a trusted receipt or profile.",
      );
      clearVerificationResult();
      return;
    }
    setExpectedSignerError(undefined);
    setVerifyState("working");
    setVerifyError(undefined);
    setVerificationResult(undefined);
    setVerificationCompletedAt(undefined);
    setVerifyProgress(0);
    try {
      const parsedProof = await parseProofFile(proofFile);
      const result = await verifyFile(verifyFileSelection, parsedProof, {
        expectedSignerKeyId: normalizedExpectedSignerKeyId,
        onProgress: setVerifyProgress,
      });
      setVerificationResult(result);
      setVerificationCompletedAt(new Date());
      setVerifyState(result.status === "verified" ? "success" : "error");
      if (demoStage === "changed-ready" && result.status === "file-mismatch") {
        setDemoStage("changed-detected");
      } else if (
        demoStage === "tampered-ready" &&
        (result.status === "invalid-signature" || result.status === "invalid-proof")
      ) {
        setDemoStage("complete");
      }
    } catch (error) {
      setVerifyError(readableError(error));
      setVerifyState("error");
    }
  };

  const switchMode = (nextMode: Mode) => {
    setMode(nextMode);
    window.requestAnimationFrame(() => document.querySelector<HTMLElement>(".workspace")?.focus());
  };

  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#top" aria-label="ByteWitness home">
          <span className="brand__mark" aria-hidden="true">
            <Asterisk size={38} weight="bold" />
          </span>
          <span>
            <strong>ByteWitness</strong>
            <small>Private file integrity</small>
          </span>
        </a>
        <div className="privacy-lockup">
          <ShieldCheck size={40} color="var(--accent)" weight="duotone" aria-hidden="true" />
          <span>
            <strong>100% local. Zero uploads.</strong>Your files never leave your device.
          </span>
        </div>
      </header>

      <section id="top" className="hero" aria-labelledby="hero-title">
        <h1 id="hero-title">
          Seal once.
          <br />
          Verify exactly<span>.</span>
        </h1>
        <div className="hero__aside">
          <p>
            Cryptographically seal any file in your browser. Keep a portable proof that detects even a
            one-byte change.
          </p>
          <div className="trust-point">
            <LockKey size={26} weight="bold" aria-hidden="true" />
            <span>
              <strong>Private by design</strong>All processing happens locally.
            </span>
          </div>
          <div className="trust-point trust-point--lavender">
            <FileText size={26} weight="bold" aria-hidden="true" />
            <span>
              <strong>Portable proof</strong>Download a signed JSON receipt.
            </span>
          </div>
        </div>
      </section>

      <nav className="mode-switcher" aria-label="Choose a task">
        <button
          type="button"
          className={mode === "seal" ? "is-active" : ""}
          aria-pressed={mode === "seal"}
          onClick={() => switchMode("seal")}
        >
          <Stamp size={26} weight="bold" aria-hidden="true" />
          Seal a file
        </button>
        <button
          type="button"
          className={mode === "verify" ? "is-active" : ""}
          aria-pressed={mode === "verify"}
          onClick={() => switchMode("verify")}
        >
          <MagnifyingGlass size={26} weight="bold" aria-hidden="true" />
          Verify a proof
        </button>
      </nav>

      <section
        className="workspace"
        tabIndex={-1}
        aria-label={mode === "seal" ? "Seal a file" : "Verify a proof"}
      >
        {mode === "seal" ? (
          <div className="seal-flow">
            {!receipt ? (
              <>
                <FilePicker
                  id="seal-file"
                  label="Drag & drop your file here"
                  hint="or browse · processed locally in 2 MB chunks"
                  file={selectedFile}
                  onFile={selectSealFile}
                />
                <aside className="file-types" aria-label="Supported file types">
                  <strong>Works with</strong>
                  <span>
                    <FileText size={21} />
                    Documents
                  </span>
                  <span>
                    <FileImage size={21} />
                    Images
                  </span>
                  <span>
                    <FileVideo size={21} />
                    Videos
                  </span>
                  <span>
                    <BracketsCurly size={21} />
                    Archives + more
                  </span>
                  <button className="sample-button" type="button" onClick={handleLoadDemo}>
                    <Play size={20} weight="bold" aria-hidden="true" />
                    Try the guided sample
                  </button>
                </aside>
                {selectedFile ? (
                  <div className="workspace__action">
                    {sealState === "working" ? (
                      <Progress percent={sealProgress} label="Hashing and signing locally" />
                    ) : (
                      <button className="primary-button" type="button" onClick={handleSeal}>
                        <Fingerprint size={24} weight="bold" />
                        Create signed proof
                      </button>
                    )}
                    {sealError ? (
                      <p className="inline-error" role="alert">
                        {sealError}
                      </p>
                    ) : null}
                  </div>
                ) : null}
                {demoStage === "sample-selected" ? (
                  <GuidedDemoPanel
                    stage={demoStage}
                    onContinue={prepareGuidedChangedFile}
                    onRestart={handleLoadDemo}
                  />
                ) : null}
              </>
            ) : (
              <div className="seal-success">
                <div className="seal-success__heading">
                  <SealCheck size={48} weight="fill" aria-hidden="true" />
                  <div>
                    <p>Proof created</p>
                    <h2>{receipt.file.name}</h2>
                  </div>
                </div>
                <ProofDetails copyState={keyCopyState} onCopyKey={handleCopySignerKey} receipt={receipt} />
                <ReceiptExplainer />
                <div className="seal-success__actions">
                  <button className="primary-button" type="button" onClick={handleDownload}>
                    <DownloadSimple size={24} weight="bold" />
                    Download proof
                  </button>
                  <button
                    className="secondary-button"
                    type="button"
                    onClick={() => {
                      setSelectedFile(undefined);
                      resetSeal();
                      setDemoOriginal(undefined);
                      setDemoChanged(undefined);
                      setDemoStage("idle");
                    }}
                  >
                    Seal another file
                  </button>
                </div>
                {keyStorage === "session" ? (
                  <p className="key-note">
                    <Warning size={18} />
                    Your browser blocked persistent key storage, so this receipt uses a one-session signing
                    key. The receipt remains verifiable.
                  </p>
                ) : (
                  <p className="key-note">
                    <Key size={18} />
                    Signed with this browser profile’s non-exportable device key. Private browsing or clearing
                    site data may remove the key, but not receipt verification.
                  </p>
                )}
                <GuidedDemoPanel
                  stage={demoStage}
                  onContinue={
                    demoStage === "changed-detected" ? prepareGuidedTamperedReceipt : prepareGuidedChangedFile
                  }
                  onRestart={handleLoadDemo}
                />
              </div>
            )}
          </div>
        ) : (
          <div className="verify-flow">
            <div className="verify-flow__heading">
              <p>Bring both items</p>
              <h2>Check the signed receipt against the file.</h2>
            </div>
            <div className="verify-pickers">
              <FilePicker
                compact
                id="verify-original"
                label="Original file"
                hint="Choose the file to check"
                file={verifyFileSelection}
                onFile={(file) => {
                  setVerifyFileSelection(file);
                  clearVerificationResult();
                  setDemoStage("idle");
                }}
              />
              <FilePicker
                compact
                id="verify-proof"
                label="Proof receipt"
                hint="Choose a .bytewitness.json file"
                file={proofFile}
                accept="application/json,.json"
                onFile={(file) => {
                  setProofFile(file);
                  clearVerificationResult();
                  setDemoStage("idle");
                }}
              />
            </div>
            <ExpectedSignerField
              value={expectedSignerKeyId}
              error={expectedSignerError}
              onChange={(value) => {
                setExpectedSignerKeyId(value);
                setExpectedSignerError(undefined);
                clearVerificationResult();
                setDemoStage("idle");
              }}
            />
            {verifyState === "working" ? (
              <Progress percent={verifyProgress} label="Checking signature and exact bytes" />
            ) : (
              <button
                className="primary-button"
                type="button"
                disabled={!verifyFileSelection || !proofFile}
                onClick={handleVerify}
              >
                <ShieldCheck size={24} weight="bold" />
                Verify integrity
              </button>
            )}
            {verifyError ? (
              <p className="inline-error" role="alert">
                {verifyError}
              </p>
            ) : null}
            {verificationResult ? (
              <div className="verification-result">
                <ResultBanner result={verificationResult} />
                <VerificationChecks result={verificationResult} />
                <button className="secondary-button" type="button" onClick={handleDownloadReport}>
                  <DownloadSimple size={22} weight="bold" />
                  Download verification report
                </button>
              </div>
            ) : null}
            {verificationResult ? <ReceiptExplainer /> : null}
            <GuidedDemoPanel
              stage={demoStage}
              onContinue={
                demoStage === "changed-detected" ? prepareGuidedTamperedReceipt : prepareGuidedChangedFile
              }
              onRestart={handleLoadDemo}
            />
          </div>
        )}
      </section>

      <section className="technical-strip" aria-label="How ByteWitness works">
        <article>
          <BracketsCurly size={46} weight="bold" aria-hidden="true" />
          <div>
            <h2>Your proof, in plain JSON</h2>
            <p>Human-readable, portable, and independently inspectable.</p>
          </div>
        </article>
        <article>
          <strong className="tech-mark">
            SHA
            <br />
            256
          </strong>
          <div>
            <h2>Chunked fingerprint</h2>
            <p>Exact bytes are hashed locally without loading the full file into memory.</p>
          </div>
        </article>
        <article>
          <Key size={46} weight="bold" aria-hidden="true" />
          <div>
            <h2>ECDSA P-256</h2>
            <p>Your browser signs the receipt with a non-exportable device key.</p>
          </div>
        </article>
        <article>
          <Check size={46} color="var(--accent)" weight="bold" aria-hidden="true" />
          <div>
            <h2>Verify anywhere</h2>
            <p>The original file and JSON proof are enough—no account or server.</p>
          </div>
        </article>
      </section>

      <section className="limits" aria-labelledby="limits-title">
        <Fingerprint size={26} weight="bold" aria-hidden="true" />
        <div>
          <h2 id="limits-title">What this proof means</h2>
          <p>
            ByteWitness proves byte-for-byte integrity and receipt signature validity under its included
            public key. It does not independently prove a person’s identity, legal ownership, or a trusted
            external creation time.
          </p>
        </div>
      </section>

      <footer>
        <span className="footer__promise">
          <LockKey size={17} />
          Local-first. Privacy-first. Evidence-first.
        </span>
        <a href="https://github.com/Anand-0038/bytewitness" target="_blank" rel="noreferrer">
          Open-source project <span aria-hidden="true">↗</span>
        </a>
      </footer>
    </main>
  );
}
