import { defineConfig } from "vitest/config";

// The control-plane logic is written against a small `Store` interface, so the
// full request handler is exercised offline against an in-memory store — no
// workerd, no D1 emulator, no network. The real D1-backed path is typechecked by
// `tsc` and deployed via wrangler.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
