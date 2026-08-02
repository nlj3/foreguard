// Small crypto helpers for the control plane, all on the Web Crypto API so they run
// identically in Workers and in the Node test environment.

/** Lowercase hex SHA-256 of a string — used to store API keys by hash, never raw. */
export async function sha256hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** A fresh instance API key: `fgk_` + 32 cryptographically-random base64url bytes. */
export function randomKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64url = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `fgk_${b64url}`;
}

/** Decode standard base64 (the encoding Rust's `base64` crate emits) to bytes. */
function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Verify an Ed25519 signature (both `pubkey` and `sig` are standard base64) over a
 * UTF-8 `message`. Returns false on any malformed input rather than throwing, so a
 * bad attestation is simply rejected.
 */
export async function verifyEd25519(pubkey: string, sig: string, message: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", fromBase64(pubkey), { name: "Ed25519" }, false, [
      "verify",
    ]);
    return await crypto.subtle.verify("Ed25519", key, fromBase64(sig), new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

/** The canonical string an instance signs to attest its ledger head. Must match the
 * Rust signer byte-for-byte. */
export function headMessage(instance: string, seq: number, hash: string): string {
  return `foreguard-head-v1\n${instance}\n${seq}\n${hash}`;
}
