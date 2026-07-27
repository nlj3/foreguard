// Capture real MCP server tool catalogues into checked-in fixtures.
//
// The classifier's accuracy claim is only worth something if it is scored
// against what real servers actually declare, not against a list somebody typed
// out. This script speaks MCP over stdio to each server, runs the handshake,
// asks for `tools/list`, and records every tool name with the annotations the
// server published for it (`readOnlyHint`, `destructiveHint`, …).
//
//   node scripts/capture-catalogues.mjs            # all of them
//   node scripts/capture-catalogues.mjs filesystem # one, by slug
//
// Needs network and npx, so it is NOT part of CI. The fixtures it writes are
// committed, and `ecosystem_report` scores against those offline. That split is
// deliberate: capture is a manual, dated act against the live ecosystem;
// scoring has to be reproducible by anyone, forever, with no network.
//
// Re-run it when you want fresher data, and commit the diff. A changed
// catalogue is a real signal: it means a server changed what it claims about
// itself.

import { spawn } from 'node:child_process'
import { writeFile, mkdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(ROOT, 'catalogues')

// Candidates. Some will fail (renamed, removed, needs credentials before it
// will even list) and that is fine: whatever answers gets recorded, whatever
// does not is reported and skipped. Nothing here is invented; if a server does
// not respond it simply is not in the corpus.
const SERVERS = [
  { slug: 'filesystem', cmd: ['npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
  { slug: 'memory', cmd: ['npx', '-y', '@modelcontextprotocol/server-memory'] },
  { slug: 'everything', cmd: ['npx', '-y', '@modelcontextprotocol/server-everything'] },
  { slug: 'sequential-thinking', cmd: ['npx', '-y', '@modelcontextprotocol/server-sequential-thinking'] },
  { slug: 'puppeteer', cmd: ['npx', '-y', '@modelcontextprotocol/server-puppeteer'] },
  { slug: 'brave-search', cmd: ['npx', '-y', '@modelcontextprotocol/server-brave-search'] },
  { slug: 'github', cmd: ['npx', '-y', '@modelcontextprotocol/server-github'] },
  { slug: 'gitlab', cmd: ['npx', '-y', '@modelcontextprotocol/server-gitlab'] },
  { slug: 'slack', cmd: ['npx', '-y', '@modelcontextprotocol/server-slack'] },
  { slug: 'google-maps', cmd: ['npx', '-y', '@modelcontextprotocol/server-google-maps'] },
  { slug: 'postgres', cmd: ['npx', '-y', '@modelcontextprotocol/server-postgres', 'postgresql://localhost/postgres'] },
  { slug: 'sentry', cmd: ['npx', '-y', '@modelcontextprotocol/server-sentry'] },
  { slug: 'everart', cmd: ['npx', '-y', '@modelcontextprotocol/server-everart'] },
  { slug: 'aws-kb-retrieval', cmd: ['npx', '-y', '@modelcontextprotocol/server-aws-kb-retrieval'] },
  { slug: 'playwright', cmd: ['npx', '-y', '@playwright/mcp@latest'] },
  { slug: 'context7', cmd: ['npx', '-y', '@upstash/context7-mcp'] },
]

const HANDSHAKE_TIMEOUT_MS = 90_000 // npx may be downloading the package

/** One stdio MCP session: initialize, initialized, tools/list. */
function capture({ slug, cmd }) {
  return new Promise((resolve) => {
    const child = spawn(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'pipe'] })
    const pending = new Map()
    let buf = ''
    let done = false

    const finish = (value) => {
      if (done) return
      done = true
      clearTimeout(timer)
      child.kill('SIGKILL')
      resolve(value)
    }
    const timer = setTimeout(() => finish({ slug, error: 'timed out' }), HANDSHAKE_TIMEOUT_MS)

    child.on('error', (e) => finish({ slug, error: e.message }))
    child.stderr.on('data', () => {}) // servers chat on stderr; not our business

    child.stdout.on('data', (d) => {
      buf += d
      let i
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i)
        buf = buf.slice(i + 1)
        if (!line.trim()) continue
        let msg
        try {
          msg = JSON.parse(line)
        } catch {
          continue // some servers print non-JSON banners on stdout
        }
        const fn = pending.get(msg.id)
        if (fn) {
          pending.delete(msg.id)
          fn(msg)
        }
      }
    })

    let id = 0
    const send = (method, params) =>
      new Promise((res) => {
        const myId = ++id
        pending.set(myId, res)
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: myId, method, params }) + '\n')
      })

    ;(async () => {
      const init = await send('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'foreguard-capture', version: '0' },
      })
      if (init.error) return finish({ slug, error: `initialize: ${init.error.message}` })
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n')

      const list = await send('tools/list', {})
      if (list.error) return finish({ slug, error: `tools/list: ${list.error.message}` })

      const tools = (list.result?.tools ?? [])
        .map((t) => ({ name: t.name, annotations: t.annotations ?? null }))
        // Sorted so a re-capture diffs cleanly instead of reshuffling.
        .sort((a, b) => a.name.localeCompare(b.name))

      if (tools.length === 0) return finish({ slug, error: 'declared no tools' })

      finish({
        slug,
        command: cmd.join(' '),
        serverInfo: list.result?.serverInfo ?? init.result?.serverInfo ?? null,
        protocolVersion: init.result?.protocolVersion ?? null,
        tools,
      })
    })().catch((e) => finish({ slug, error: e.message }))
  })
}

const only = process.argv[2]
const targets = only ? SERVERS.filter((s) => s.slug === only) : SERVERS
if (targets.length === 0) {
  console.error(`no server matches "${only}"`)
  process.exit(2)
}

await mkdir(OUT, { recursive: true })

const ok = []
const failed = []
for (const s of targets) {
  process.stdout.write(`${s.slug} … `)
  const r = await capture(s)
  if (r.error) {
    console.log(`skipped (${r.error})`)
    failed.push({ slug: s.slug, error: r.error })
    continue
  }
  const withHints = r.tools.filter((t) => t.annotations && 'readOnlyHint' in t.annotations).length
  console.log(`${r.tools.length} tools, ${withHints} with readOnlyHint`)
  await writeFile(join(OUT, `${s.slug}.json`), JSON.stringify(r, null, 2) + '\n')
  ok.push(r)
}

console.log(
  `\ncaptured ${ok.length} servers, ${ok.reduce((n, r) => n + r.tools.length, 0)} tools` +
    (failed.length ? `; ${failed.length} unavailable: ${failed.map((f) => f.slug).join(', ')}` : ''),
)
