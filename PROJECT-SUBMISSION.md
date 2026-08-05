# ByteWitness — Rampamble submission draft

## Tagline

Seal exact file bytes locally. Keep a signed proof. Detect tampering anywhere.

## Inspiration

Digital files are effortless to edit, while ordinary users have no simple way to check whether a later copy is exactly the one they trusted. Students share research, freelancers deliver work, and journalists preserve source material—but many integrity tools require uploads, accounts, or blockchain fees. We wanted a private baseline that makes cryptographic verification understandable and immediate.

## What it does

ByteWitness turns any file into a portable, human-readable integrity receipt without uploading it. It hashes the file locally in 2 MB chunks, signs the receipt with a non-exportable browser key, and downloads a `.bytewitness.json` proof. Anyone can later provide the original file and proof to verify both the ECDSA signature and exact SHA-256 fingerprint. A verifier can optionally compare the receipt's key ID with an expected signer key obtained through a trusted channel. One changed byte produces a clear failure.

## How we built it

The application is a static React and TypeScript web app. `@noble/hashes` performs incremental SHA-256 hashing so large files do not need to be loaded into memory at once. Web Crypto generates an ECDSA P-256 key whose private half is non-exportable; IndexedDB retains that key within the browser profile and uses add-if-absent initialization so simultaneous tabs converge on one signer key. Receipts are strict, versioned JSON validated with Zod. Verification imports only the included public key, validates the signature over canonicalized receipt fields, recalculates the file fingerprint, and optionally compares the receipt key ID with an expected signer key supplied through a trusted channel. No backend or file API exists.

## Challenges we ran into

The hardest product decision was being precise about what self-signed cryptography proves. A local receipt can prove byte-level integrity and signature consistency, but it cannot independently establish legal identity or trusted time. We designed that limitation into the interface and documentation instead of hiding it. We also used chunked hashing and strict untrusted-input validation so the demo architecture remains credible beyond tiny sample files.

## Accomplishments that we're proud of

- A complete seal, download, and independent verify loop with real browser cryptography.
- Explicit detection of both file tampering and receipt tampering.
- No accounts, uploads, analytics, external fonts, or simulated success states.
- A responsive, accessible interface that explains the cryptography in plain language.
- A guided browser-local sample flow that demonstrates changed-file and tampered-receipt failures without setup friction.
- A downloadable human-readable verification report with explicit local-time and trust-boundary wording.
- Separate receipt-integrity, file-integrity, and optional expected-signer trust results.
- Race-safe device-key initialization across simultaneous browser tabs.
- A versioned proof format and regression tests for exact hashing, valid verification, changed files, and edited receipts.

## What we learned

Trustworthy product design is as much about limiting claims as adding capabilities. Separating file integrity, signer-key continuity, identity, and trusted timestamps made ByteWitness simpler to explain and safer to use. We also learned that Web Crypto keys can remain non-exportable while still being persisted by the browser through structured cloning in IndexedDB.

## What's next for ByteWitness

The next optional trust tier is external anchoring: users could publish a proof hash or device-key fingerprint to a trusted channel without exposing the original file. We also want QR-based key-ID exchange, multi-file Merkle manifests, installable offline caching, and a documented verification CLI that implements the same open proof format.

## Built with

React, TypeScript, Vite, Web Crypto, ECDSA P-256, SHA-256, IndexedDB, Zod, Noble Hashes, Phosphor Icons

## Required submission assets

- Public GitHub repository: https://github.com/Anand-0038/bytewitness
- Live demo URL: https://bytewitness.regal-flame-7335.chatgpt.site
- Demo video (3–5 minutes): external recording required
- Screenshots: `public/screenshots/bytewitness-desktop.png` and `public/screenshots/bytewitness-mobile.png`
- Team member details: Anand / Devpost profile
