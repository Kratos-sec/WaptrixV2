import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { benchmark, catalog, cryptoPosture, domain, hostnames, lookalikes, seed, tools } from './model.mjs'
import { profileCatalog } from './profiles.mjs'
import { formats, renderReport, templates } from './reports.mjs'
import { createStore, demoOtp, fail, roles } from './state.mjs'

const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json; charset=utf-8',
}

function json(res, value, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(value))
}

async function body(req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > 24_000) fail(413, 'The request is too large.')
    chunks.push(chunk)
  }
  try {
    const input = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}
    if (!input || Array.isArray(input) || typeof input !== 'object') fail(400, 'Use a JSON object.')
    return input
  } catch {
    fail(400, 'Use a valid JSON object.')
  }
}

function isLocal(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  } catch {
    return false
  }
}

async function asset(res, root, path, method) {
  if (method !== 'GET' && method !== 'HEAD') fail(405, 'Use GET to open the demo.')
  const requested = path === '/' ? '/index.html' : path
  const file = resolve(root, '.' + requested)
  if (!file.startsWith(root + sep)) fail(404, 'Page not found.')
  try {
    const content = await readFile(file)
    res.writeHead(200, {
      'Content-Type': types[extname(file)] ?? 'application/octet-stream',
      'Cache-Control': requested.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-store',
    })
    res.end(method === 'HEAD' ? undefined : content)
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'EISDIR') throw error
    fail(404, requested === '/index.html' ? 'Run npm run build before opening the demo.' : 'Page not found.')
  }
}

export function createApp({ directory, dist, interval }) {
  const store = createStore({ directory, interval })
  const root = resolve(dist)
  const server = createServer(async (req, res) => {
    try {
      if (!isLocal('http://' + req.headers.host) || (req.headers.origin && !isLocal(req.headers.origin))) {
        fail(403, 'This demo is available on loopback.')
      }
      const url = new URL(req.url, 'http://127.0.0.1')
      let path
      try { path = decodeURIComponent(url.pathname) } catch { fail(400, 'Invalid request path.') }
      const { method } = req
      res.setHeader('X-Content-Type-Options', 'nosniff')
      res.setHeader('Referrer-Policy', 'no-referrer')
      if (!path.startsWith('/api/')) return await asset(res, root, path, method)

      const token = req.headers.authorization?.replace(/^Bearer /, '')
      const parts = path.split('/').slice(2)
      const [resource, id, action, detail] = parts
      if (method === 'GET' && parts.length === 1) {
        const resources = {
          health: () => ({ status: 'ok', simulated: true }),
          demo: () => ({ domain, hostnames, demoId: seed.id, suggestedTools: seed.request.tools, profiles: profileCatalog, roles, demoOtp }),
          rules: () => catalog,
          tools: () => tools,
          owasp: () => catalog.categories,
          benchmark: () => ({ simulated: true, results: benchmark }),
          lookalikes: () => ({ simulated: true, results: lookalikes }),
          audits: () => store.list(),
          deliveries: () => store.deliveries(),
        }
        if (Object.hasOwn(resources, resource)) return json(res, resources[resource]())
      }
      if (resource === 'assets' && action === 'history' && method === 'GET') return json(res, store.assetHistory(id))
      if (resource === 'audits') {
        if (!id && method === 'POST') return json(res, store.start(await body(req)), 202)
        if (!id) fail(404, 'Endpoint not found.')
        const record = store.get(id)
        if (!action && method === 'GET') return json(res, store.view(record))
        if (!action && method === 'DELETE') {
          store.remove(record)
          res.writeHead(204).end()
          return
        }
        if (action === 'stop' && method === 'POST') return json(res, store.stop(record))
        if (action === 'log' && method === 'GET') {
          const after = Number(url.searchParams.get('after') ?? 0)
          if (!Number.isInteger(after) || after < 0) fail(400, 'Use a non-negative log cursor.')
          return json(res, record.events.filter(event => event.seq > after))
        }
        if (action === 'subdomains' && method === 'GET') {
          const host = store.view(record).subdomains.find(entry => entry.subdomain === detail)
          if (!host) fail(404, 'Host not found in this audit.')
          return json(res, host)
        }
        if (action === 'posture' && method === 'GET') return json(res, cryptoPosture(store.view(record)))
        if (action === 'nuclei') {
          if (method === 'GET') return json(res, store.view(record).nuclei)
          if (method === 'POST' && !detail) return json(res, store.startNuclei(record, await body(req)), 202)
          if (method === 'POST' && detail && parts[4] === 'stop') return json(res, store.stopNuclei(record, detail))
        }
        if (action === 'export' && method === 'GET') {
          if (record.status !== 'completed') fail(409, 'Choose a completed audit to export.')
          const format = url.searchParams.get('format') ?? 'pdf'
          const template = url.searchParams.get('template') ?? 'executive'
          const host = url.searchParams.get('host')
          if (!formats.includes(format) || !templates.includes(template)) fail(400, 'Unknown report format or template.')
          if (host && !record.hosts.includes(host)) fail(404, 'Host not found in this audit.')
          const audit = store.view(host ? { ...record, hosts: [host] } : record)
          if (host) {
            audit.run_log = audit.run_log.filter(event => !event.subdomain || event.subdomain === host)
            audit.scope_rejections = []
            audit.nuclei = audit.nuclei.filter(run => run.hosts.includes(host)).map(run => ({ ...run, hosts: [host] }))
          }
          const report = renderReport(audit, format, template)
          res.writeHead(200, {
            'Content-Type': report.type,
            'Content-Disposition': 'attachment; filename="' + report.filename + '"',
            'Cache-Control': 'no-store',
          })
          return res.end(report.content)
        }
      }
      if (resource === 'deliveries' && !id && method === 'POST') {
        const input = await body(req)
        if (!templates.includes(input.template)) fail(400, 'Choose a report template.')
        return json(res, store.delivery(input), 201)
      }
      if (resource === 'session') {
        if (method === 'POST' && id === 'preview') return json(res, store.previewSession(), 201)
        if (method === 'POST' && id === 'login') return json(res, store.startSession(await body(req)))
        if (method === 'POST' && id === 'verify') return json(res, store.verifySession(await body(req)))
        if (method === 'POST' && id === 'signup') return json(res, store.signUp(await body(req)), 201)
        if (method === 'POST' && id === 'logout') return json(res, { signed_out: store.signOut(token) })
        if (method === 'POST' && id === 'reset') {
          store.resetSessions(store.current(token))
          return json(res, { signed_out: true })
        }
        if (!id && method === 'GET') return json(res, store.publicAccount(store.current(token)))
        if (!id && method === 'PATCH') return json(res, store.updateProfile(store.current(token), await body(req)))
      }
      if (resource === 'accounts') {
        const account = store.current(token)
        if (!id && method === 'GET') return json(res, store.admin(account))
        if (id && method === 'PATCH') return json(res, store.changeRole(account, id, (await body(req)).role))
        if (id && method === 'DELETE') {
          store.deleteAccount(account, id)
          return res.writeHead(204).end()
        }
      }
      fail(404, 'Endpoint not found.')
    } catch (error) {
      if (!error.status) console.error(error)
      if (res.headersSent) return res.end()
      return json(res, { error: error.status ? error.message : 'The local demo could not complete the request.' }, error.status ?? 500)
    }
  })
  server.on('close', store.close)
  return server
}
