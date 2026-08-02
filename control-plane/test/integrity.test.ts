import { describe, it, expect } from "vitest";
import { parseEntry, verifyBatch, type ParsedEntry } from "../src/integrity.js";

/** A fake chained entry — linkage only, so hashes are opaque labels. */
function entry(seq: number, prev: string, hash: string, extra: Record<string, unknown> = {}): ParsedEntry {
  return { fg: { seq, prev, hash }, record: { _fg: { seq, prev, hash }, ...extra } };
}

describe("parseEntry", () => {
  it("extracts a valid _fg envelope", () => {
    const p = parseEntry({ tool: "x", _fg: { seq: 0, prev: "genesis", hash: "h0" } });
    expect(p?.fg).toEqual({ seq: 0, prev: "genesis", hash: "h0" });
  });
  it("rejects objects without a well-formed envelope", () => {
    expect(parseEntry({ tool: "x" })).toBeNull();
    expect(parseEntry({ _fg: { seq: "0", prev: "genesis", hash: "h" } })).toBeNull();
    expect(parseEntry(null)).toBeNull();
    expect(parseEntry("nope")).toBeNull();
  });
});

describe("verifyBatch", () => {
  it("accepts a chain that extends from genesis", () => {
    const batch = [entry(0, "genesis", "h0"), entry(1, "h0", "h1"), entry(2, "h1", "h2")];
    expect(verifyBatch(-1, "genesis", batch)).toEqual({ ok: true, lastSeq: 2, lastHash: "h2" });
  });

  it("accepts a batch that continues a stored head", () => {
    const batch = [entry(3, "h2", "h3"), entry(4, "h3", "h4")];
    expect(verifyBatch(2, "h2", batch)).toEqual({ ok: true, lastSeq: 4, lastHash: "h4" });
  });

  it("rejects a broken prev link (dropped/reordered/injected)", () => {
    const batch = [entry(0, "genesis", "h0"), entry(1, "WRONG", "h1")];
    const r = verifyBatch(-1, "genesis", batch);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.index).toBe(1);
  });

  it("rejects a sequence gap", () => {
    const batch = [entry(0, "genesis", "h0"), entry(2, "h0", "h2")];
    const r = verifyBatch(-1, "genesis", batch);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/sequence gap/);
  });

  it("rejects a batch that does not continue the stored head", () => {
    const batch = [entry(5, "genesis", "h5")];
    expect(verifyBatch(2, "h2", batch).ok).toBe(false);
  });
});
