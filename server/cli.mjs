import { mkdir, writeFile } from 'node:fs/promises'
import { basename, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { setTimeout } from 'node:timers/promises'

const [command = 'help', ...args] = process.argv.slice(2)
const base = 'http://127.0.0.1:' + Number(process.env.REQUIEM_PORT ?? 4173) + '/api'

async function request(path, data) {
  const response = await fetch(base + path, data === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
  })
  if (!response.ok) throw new Error((await response.json()).error)
  return response
}

const print = value => console.log(JSON.stringify(value, null, 2))
const auditPath = id => '/audits/' + encodeURIComponent(id)
const detail = async id => (await request(auditPath(id))).json()
const demo = async () => (await request('/demo')).json()
const summary = audit => ({ id: audit.id, status: audit.status, simulated: audit.simulated, ...audit.summary })

async function run() {
  if (command === 'help' || command === '--help') {
    console.log([
      'Requiem local demo CLI',
      'npm run cli -- demo [profile] | profiles | history | rules | tools | benchmark',
      'npm run cli -- audit [--domain acme-corp.example] [--hosts host1,host2] [--scope acme-corp.example] [--ref DEMO-2026]',
      'npm run cli -- show <audit-id> | log <audit-id> | stop <audit-id>',
      'npm run cli -- export <audit-id> [--format pdf|html|json|csv|sarif] [--host host] [--template executive] [--out directory]',
    ].join('\n'))
    return
  }
  if (command === 'serve') {
    await import('./index.mjs')
    return
  }
  const { values, positionals } = parseArgs({
    args, allowPositionals: true, options: {
      domain: { type: 'string' }, hosts: { type: 'string' }, ref: { type: 'string' }, scope: { type: 'string' },
      'no-wait': { type: 'boolean' }, format: { type: 'string' }, host: { type: 'string' },
      template: { type: 'string' }, out: { type: 'string' },
    },
  })
  const id = positionals[0] ?? 'demo-acme-corp'
  const paths = { history: '/audits', rules: '/rules', tools: '/tools', benchmark: '/benchmark', log: auditPath(id) + '/log' }
  if (Object.hasOwn(paths, command)) return print(await (await request(paths[command])).json())
  if (command === 'profiles') return print((await demo()).profiles.map(({ id, name, target, auditId, hostnames }) => ({
    id, name, target, auditId, hosts: hostnames.length,
  })))
  if (command === 'demo') {
    const sample = await demo()
    const profile = positionals[0] && sample.profiles.find(profile => [profile.id, profile.target, profile.auditId].includes(positionals[0]))
    if (positionals[0] && !profile) throw new Error('Choose a sample from npm run cli -- profiles.')
    return print(summary(await detail(profile?.auditId ?? sample.demoId)))
  }
  if (command === 'show') return print(summary(await detail(id)))
  if (command === 'stop') return print(summary(await (await request(auditPath(id) + '/stop', {})).json()))
  if (command === 'audit') {
    const sample = await demo()
    const started = await (await request('/audits', {
      mode: values.hosts ? 'hosts' : 'domain', domain: values.domain ?? sample.domain, hosts: values.hosts,
      authorization_ref: values.ref ?? 'DEMO-2026', scope_domains: values.scope,
    })).json()
    if (values['no-wait']) return print(started)
    let audit = await detail(started.id)
    while (audit.status === 'running') {
      await setTimeout(450)
      audit = await detail(started.id)
    }
    return print(summary(audit))
  }
  if (command === 'export') {
    const params = new URLSearchParams({ format: values.format ?? 'pdf', template: values.template ?? 'executive' })
    if (values.host) params.set('host', values.host)
    const response = await request(auditPath(id) + '/export?' + params)
    const filename = response.headers.get('content-disposition')?.match(/filename="([^"]+)"/)?.[1]
    const directory = resolve(values.out ?? '.')
    const path = resolve(directory, basename(filename ?? 'requiem-report'))
    await mkdir(directory, { recursive: true })
    await writeFile(path, Buffer.from(await response.arrayBuffer()))
    return console.log(path)
  }
  throw new Error('Unknown command. Use npm run cli -- help.')
}

run().catch(error => {
  console.error(error.cause?.code === 'ECONNREFUSED' ? 'Start the loopback server with npm start first.' : error.message)
  process.exitCode = 1
})
