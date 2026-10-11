import type { Env } from "./types.js";
import { D1Store } from "./store.js";
import { handle } from "./app.js";

// The Worker entry point: wire the D1-backed store into the shared handler. All the
// logic lives in `app.ts` (tested offline against an in-memory store); this file is
// only the production binding.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env, new D1Store(env.DB));
  },
} satisfies ExportedHandler<Env>;
