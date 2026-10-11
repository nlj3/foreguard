// Server-side integrity checking of an ingested batch of Foreguard ledger entries.
//
// Each entry carries the `_fg` envelope Foreguard writes: `{ seq, prev, hash }`,
// where `hash = SHA-256(prev ‖ seq ‖ canonical-payload)` chains it to the one
// before. The control plane verifies **linkage** across a batch — that it continues
// the instance's stored head, that `prev` links match, and that `seq` increases by
// one with no gaps. That detects a stream that has been truncated, reordered, or had
// entries dropped or injected before it reached us, and it never trusts a batch that
// doesn't cleanly extend what we already hold.
//
// It does not re-derive the SHA content hash here (that is `foreguard verify`'s job
// locally, and re-deriving it server-side means matching Rust's canonical JSON
// byte-for-byte — a deliberate follow-up, not a silent gap). We store every hash so
// that check can be run later.

/** The integrity envelope Foreguard stamps on each ledger line. */
export interface FgEnvelope {
  seq: number;
  prev: string;
  hash: string;
}

/** A parsed ingest entry: the raw record plus its extracted envelope. */
export interface ParsedEntry {
  fg: FgEnvelope;
  record: Record<string, unknown>;
}

export type VerifyResult =
  | { ok: true; lastSeq: number; lastHash: string }
  | { ok: false; index: number; reason: string };

/** Pull the `_fg` envelope off one raw ledger object, validating its shape. */
export function parseEntry(raw: unknown): ParsedEntry | null {
  if (typeof raw !== "object" || raw === null) return null;
  const record = raw as Record<string, unknown>;
  const fg = record["_fg"];
  if (typeof fg !== "object" || fg === null) return null;
  const e = fg as Record<string, unknown>;
  if (
    typeof e["seq"] !== "number" ||
    !Number.isInteger(e["seq"]) ||
    typeof e["prev"] !== "string" ||
    typeof e["hash"] !== "string"
  ) {
    return null;
  }
  return { fg: { seq: e["seq"], prev: e["prev"], hash: e["hash"] }, record };
}

/**
 * Verify that `entries` cleanly extend a chain whose head is `(prevSeq, prevHash)`
 * — use `prevSeq = -1`, `prevHash = "genesis"` for a brand-new instance. Returns the
 * new head on success, or the index and reason of the first break.
 */
export function verifyBatch(
  prevSeq: number,
  prevHash: string,
  entries: ParsedEntry[],
): VerifyResult {
  let seq = prevSeq;
  let hash = prevHash;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry) return { ok: false, index: i, reason: "missing entry" };
    const { fg } = entry;
    if (fg.prev !== hash) {
      return {
        ok: false,
        index: i,
        reason: `chain link broken: expected prev ${hash}, got ${fg.prev} ` +
          `(entries dropped, reordered, or injected before ingest)`,
      };
    }
    if (fg.seq !== seq + 1) {
      return {
        ok: false,
        index: i,
        reason: `sequence gap: expected ${seq + 1}, got ${fg.seq}`,
      };
    }
    seq = fg.seq;
    hash = fg.hash;
  }
  return { ok: true, lastSeq: seq, lastHash: hash };
}
