# ByteWitness demo script (3–4 minutes)

## 0:00–0:25 — The problem

“A contract, research file, or source document can be changed in seconds. Most people have no simple way to check whether a later copy is exactly the one they trusted. ByteWitness creates a private, portable integrity receipt without uploading the file.”

Show the hero and point to **100% local. Zero uploads.**

## 0:25–1:15 — Seal the original

1. Keep the browser Network panel visible and clear it.
2. Click **Try the guided sample**. It creates a browser-local sample file; no fixture is uploaded.
3. Click **Create signed proof**.
4. Explain the displayed SHA-256 fingerprint, device key ID, and browser-clock time.
5. Click **Copy key ID** and explain that a verifier can compare it through a trusted channel.
6. Download the `.bytewitness.json` proof.
7. Show that no network request occurred.

“The file is hashed in 2 MB chunks. Web Crypto signs the versioned receipt with an ECDSA P-256 private key that is non-exportable and stored only in this browser profile.”

## 1:15–2:00 — Verify the exact file

1. Download the proof, then open **Verify a proof**.
2. Select the sample file and its downloaded receipt.
3. Optionally paste the exchanged value into **Expected signer key ID**.
4. Click **Verify integrity**.
5. Pause on **File match confirmed. Receipt signature valid.** and the three verification checks.

“Verification imports only the public key included in the receipt, checks the signature over every signed field, recalculates the file fingerprint, and compares the exact bytes. No ByteWitness server is involved.”

## 2:00–2:35 — Detect changed bytes

1. Return to the seal result and click **Test changed bytes**.
2. Click **Verify integrity** on the preselected changed sample.
3. Pause on **Receipt signature valid; file mismatch detected.**

“The receipt signature is valid for the public key included in that receipt, but one changed byte is enough to produce a different SHA-256 fingerprint.”

## 2:35–3:05 — Detect a forged receipt

1. Click **Test tampered receipt**.
2. Click **Verify integrity** on the preselected original and edited receipt.
3. Pause on **Receipt signature is invalid.**

“Changing the timestamp, filename, hash, key ID, or any other signed receipt field breaks the signature.”

## 3:05–3:35 — Honest trust boundary and impact

Scroll to **What this proof means**.

“ByteWitness proves byte-level integrity and consistency with the included signer key. It deliberately does not claim legal identity, ownership, or a trusted external timestamp. That honest boundary makes it useful today for students, creators, freelancers, and journalists, while leaving a clear path to optional public key and timestamp anchoring later.”

Download the verification report to show the human-readable result, then end on the responsive mobile view and the GitHub repository.
