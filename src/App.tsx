import {
  Asterisk,
  BracketsCurly,
  Check,
  DownloadSimple,
  File,
  FileImage,
  FileText,
  FileVideo,
  Fingerprint,
  Key,
  LockKey,
  MagnifyingGlass,
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
  proofFilename,
  sealFile,
  serializeProof,
  verifyFile,
  type ProofReceipt,
  type VerificationResult,
} from "./lib/proof";

type Mode = "seal" | "verify";
type ProcessState = "idle" | "working" | "success" | "error";

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
      <input ref={inputRef} id={id} className="sr-only" type="file" accept={accept} onChange={handleChange} />
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

function ProofDetails({ receipt }: { receipt: ProofReceipt }) {
  return (
    <dl className="proof-details">
      <div>
        <dt>SHA-256 fingerprint</dt>
        <dd title={receipt.file.sha256}>{shortHash(receipt.file.sha256)}</dd>
      </div>
      <div>
        <dt>Signing key</dt>
        <dd>{receipt.signer.keyId}</dd>
      </div>
      <div>
        <dt>Signed on this device</dt>
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
          <h3>Exact match. Signature valid.</h3>
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
          <h3>File does not match.</h3>
          <p>The receipt is authentic, but these file bytes are different from the sealed original.</p>
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

export function App() {
  const [mode, setMode] = useState<Mode>("seal");
  const [sealState, setSealState] = useState<ProcessState>("idle");
  const [sealProgress, setSealProgress] = useState(0);
  const [sealError, setSealError] = useState<string>();
  const [selectedFile, setSelectedFile] = useState<globalThis.File>();
  const [receipt, setReceipt] = useState<ProofReceipt>();
  const [keyStorage, setKeyStorage] = useState<"persistent" | "session">();
  const [verifyFileSelection, setVerifyFileSelection] = useState<globalThis.File>();
  const [proofFile, setProofFile] = useState<globalThis.File>();
  const [verifyState, setVerifyState] = useState<ProcessState>("idle");
  const [verifyProgress, setVerifyProgress] = useState(0);
  const [verifyError, setVerifyError] = useState<string>();
  const [verificationResult, setVerificationResult] = useState<VerificationResult>();

  const resetSeal = useCallback(() => {
    setSealState("idle");
    setSealProgress(0);
    setSealError(undefined);
    setReceipt(undefined);
    setKeyStorage(undefined);
  }, []);

  const selectSealFile = useCallback(
    (file: globalThis.File) => {
      resetSeal();
      setSelectedFile(file);
    },
    [resetSeal],
  );

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
    } catch (error) {
      setSealError(readableError(error));
      setSealState("error");
    }
  };

  const handleDownload = () => {
    if (!receipt) return;
    const blob = new Blob([serializeProof(receipt)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = proofFilename(receipt.file.name);
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleVerify = async () => {
    if (!verifyFileSelection || !proofFile || verifyState === "working") return;
    setVerifyState("working");
    setVerifyError(undefined);
    setVerificationResult(undefined);
    setVerifyProgress(0);
    try {
      const parsedProof = await parseProofFile(proofFile);
      const result = await verifyFile(verifyFileSelection, parsedProof, setVerifyProgress);
      setVerificationResult(result);
      setVerifyState(result.status === "verified" ? "success" : "error");
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
                <ProofDetails receipt={receipt} />
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
                    Signed with this browser’s non-exportable device key. Clearing site data removes the key
                    but not receipt verification.
                  </p>
                )}
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
                  setVerificationResult(undefined);
                  setVerifyState("idle");
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
                  setVerificationResult(undefined);
                  setVerifyState("idle");
                }}
              />
            </div>
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
            {verificationResult ? <ResultBanner result={verificationResult} /> : null}
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
            ByteWitness proves byte-for-byte integrity and receipt authenticity under its included public key.
            It does not independently prove a person’s identity, legal ownership, or a trusted external
            creation time.
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
