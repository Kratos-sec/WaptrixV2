import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { test } from 'node:test'
import { setTimeout } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { createApp } from '../server/app.mjs'
import { owaspSeries, pqcSeries } from '../src/dashboard-data.mjs'

const run = promisify(execFile)
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const cli = fileURLToPath(new URL('../server/cli.mjs', import.meta.url))
const sample = '/audits/demo-acme-corp'
const adminHost = 'admin.acme-corp.example'
const sampleDomain = 'acme-corp.example'

async function localApp(t, interval = 100) {
  const directory = await mkdtemp(join(tmpdir(), 'requiem-demo-test-'))
  let server
  let base
  async function start() {
    server = createApp({ directory, dist, interval })
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
    base = 'http://127.0.0.1:' + server.address().port
  }
  const stop = () => new Promise(resolve => server.close(resolve))
  await start()
  t.after(async () => {
    await stop()
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()))
    assert.match(basename(directory), /^requiem-demo-test-/)
    await rm(directory, { recursive: true, force: true })
  })
  async function request(path, { method = 'GET', data, token } = {}) {
    const headers = {}
    if (data !== undefined) headers['Content-Type'] = 'application/json'
    if (token) headers.Authorization = 'Bearer ' + token
    return fetch(base + '/api' + path, { method, headers, body: data === undefined ? undefined : JSON.stringify(data) })
  }
  async function query(path, options) {
    const result = await request(path, options)
    assert.ok(result.ok, result.status + ' ' + path)
    return result.status === 204 ? null : result.json()
  }
  return {
    query, request, directory, port: () => server.address().port,
    restart: async () => { await stop(); await start() },
  }
}

async function waitFor(query, path, condition) {
  for (let attempt = 0; attempt < 70; attempt++) {
    const value = await query(path)
    if (condition(value)) return value
    await setTimeout(25)
  }
  assert.fail('Replay did not reach the expected state.')
}

test('the audit, host views, five export formats, and CLI share the bundled results', async t => {
  const { query, request, port, directory } = await localApp(t)
  const audit = await query(sample)
  assert.equal(audit.summary.overall_score, 42)
  assert.equal(audit.summary.total_findings, 65)
  assert.equal(audit.summary.severity_counts.high, 6)
  assert.equal(audit.simulated, true)
  assert.ok(audit.subdomains.every(host => host.categories.length === 10 && host.inventory.ports.length))
  assert.ok(audit.summary.categories.some(category => category.status === 'manual_review'))
  const owasp = owaspSeries(audit)
  assert.equal(owasp.severity.reduce((total, item) => total + item.value, 0), 65)
  assert.equal(owasp.categories.length, 10)
  assert.deepEqual(owasp.hosts.map(host => host.value), [0, 20, 43, 53, 94])
  const posture = await query(sample + '/posture')
  assert.equal(posture.rating, 440)
  const pqc = pqcSeries(posture.assets)
  assert.deepEqual(pqc.grade.map(point => point.value), [0, 3, 0, 2])
  assert.deepEqual(pqc.migration.map(point => point.value), [0, 3, 2])
  assert.deepEqual(pqc.risks.map(point => point.value), [1, 2, 2])
  assert.deepEqual(pqc.ipVersions.map(point => point.value), [5, 1])
  assert.deepEqual(pqc.expiry.map(point => point.value), [2, 2, 0, 0])
  assert.equal(pqc.inventory.reduce((total, item) => total + item.value, 0), 5)
  const admin = await query(sample + '/subdomains/' + adminHost)
  assert.equal(admin.tls.trusted, false)
  assert.ok(admin.inventory.dns.length)
  const expired = admin.findings.find(finding => finding.rule_id === 'TLS-CERT-EXPIRED')
  assert.ok(expired.owasp.includes('A04:2025'))
  assert.ok(expired.sources.includes('nuclei') && expired.evidence && expired.remediation)
  const pdf = await request(sample + '/export?format=pdf')
  assert.equal(pdf.headers.get('content-type'), 'application/pdf')
  assert.match(Buffer.from(await pdf.arrayBuffer()).toString('latin1'), /%PDF-[\s\S]*SIMULATED ASSESSMENT/)
  const html = await request(sample + '/export?format=html')
  assert.match(await html.text(), /Simulated assessment[\s\S]*65 findings/)
  const csv = await request(sample + '/export?format=csv')
  assert.match(await csv.text(), /^"simulated","audit_id","host"/)
  const sarif = await query(sample + '/export?format=sarif')
  assert.equal(sarif.runs[0].results.length, 65)
  assert.equal(sarif.runs[0].properties.simulated, true)
  const host = await query(sample + '/export?format=json&host=' + adminHost)
  assert.deepEqual(host.subdomains.map(item => item.subdomain), [adminHost])
  assert.equal(host.summary.total_findings, admin.findings.length)
  assert.ok(host.run_log.every(event => !event.subdomain || event.subdomain === adminHost))
  assert.ok(host.nuclei.every(run => run.hosts.length === 1 && run.hosts[0] === adminHost))

  const env = { ...process.env, REQUIEM_PORT: String(port()) }
  const { stdout } = await run(process.execPath, [cli, 'demo'], { env })
  assert.equal(JSON.parse(stdout).total_findings, audit.summary.total_findings)
  const result = await run(process.execPath, [cli, 'export', audit.id, '--format', 'json', '--host', adminHost, '--out', directory], { env })
  assert.equal(JSON.parse(await readFile(result.stdout.trim(), 'utf8')).summary.total_findings, admin.findings.length)
})

test('replays validate sample scope, support stop, and retain stage history after restart', async t => {
  const { query, request, restart } = await localApp(t, 150)
  const data = { mode: 'domain', domain: sampleDomain, authorization_ref: 'TEST-POC' }
  const outside = await request('/audits', { method: 'POST', data: { ...data, domain: 'different.example' } })
  assert.equal(outside.status, 400)

  const replay = await query('/audits', { method: 'POST', data })
  assert.equal(replay.status, 'running')
  const stopped = await query('/audits/' + replay.id + '/stop', { method: 'POST', data: {} })
  assert.equal(stopped.status, 'stopped')
  assert.equal(stopped.run_log.at(-1).status, 'skipped')

  const hostReplay = await query('/audits', { method: 'POST', data: {
    mode: 'hosts', hosts: [adminHost, adminHost, 'outside.example'],
    scope_domains: [sampleDomain], authorization_ref: 'HOST-ONLY', tools: ['sslyze'],
  } })
  const path = '/audits/' + hostReplay.id
  const completed = await waitFor(query, path, audit => audit.status === 'completed')
  assert.deepEqual(completed.subdomains.map(host => host.subdomain), [adminHost])
  assert.equal(completed.scope_rejections.length, 1)
  assert.equal(completed.stages.length, 6)
  assert.ok(completed.stages.every(stage => stage.status === 'completed'))
  assert.deepEqual(owaspSeries(completed).hosts.map(host => host.id), [adminHost])
  const scopedPqc = pqcSeries((await query(path + '/posture')).assets)
  assert.deepEqual(scopedPqc.grade.map(point => point.value), [0, 0, 0, 1])
  assert.deepEqual(scopedPqc.ipVersions.map(point => point.value), [1, 0])
  assert.deepEqual(scopedPqc.expiry.map(point => point.value), [1, 0, 0, 0])
  assert.ok((await query(path + '/log?after=1')).every(event => event.seq > 1))
  assert.deepEqual(completed.request.tools, ['waptrix', 'sslyze'])
  assert.ok(completed.subdomains[0].findings.every(finding => !finding.sources.includes('nuclei')))
  const nuclei = await query(path + '/nuclei', { method: 'POST', data: { hosts: [adminHost] } })
  await waitFor(query, path + '/nuclei', rows => rows.some(row => row.id === nuclei.id && row.status === 'completed'))
  assert.ok((await query(path)).subdomains[0].findings.some(finding => finding.sources.includes('nuclei')))

  await restart()
  const history = await query('/audits')
  assert.ok(history.some(record => record.id === replay.id && record.status === 'stopped'))
  assert.ok(history.some(record => record.id === hostReplay.id && record.status === 'completed'))
  const hostHistory = await query('/assets/' + adminHost + '/history')
  assert.ok(hostHistory.some(record => record.id === hostReplay.id && record.findings === 17))
})

test('PQC readiness uses explicit support, exclusive tiers, and unique IP addresses', () => {
  const fixture = {
    quantumRisk: 'Low', keyAlgorithm: 'RSA', keySize: 3072,
    host: { tls: { protocol: 'TLSv1.3' }, inventory: { type: 'Web app' }, ip_addresses: ['198.51.100.1'] },
  }
  const pqc = pqcSeries([fixture, { ...fixture, pqcSupported: true }, { ...fixture, keySize: 1024 },
    { ...fixture, pqcSupported: true, quantumRisk: 'High' }])
  assert.deepEqual(pqc.hosts.map(asset => asset.readiness), ['Standard', 'Elite', 'Legacy', 'Critical'])
  assert.deepEqual(pqc.grade.map(point => point.value), [1, 1, 1, 1])
  assert.deepEqual(pqc.migration.map(point => point.value), [1, 1, 2])
  assert.deepEqual(pqc.ipVersions.map(point => point.value), [1, 0])
})

test('bundled profiles open directly, keep their scopes fictional, and replay independently', async t => {
  const { query, request, restart } = await localApp(t)
  const config = await query('/demo')
  assert.deepEqual(config.hostnames, ['www', 'app', 'api', 'admin', 'legacy'].map(label => label + '.acme-corp.example'))
  assert.deepEqual(config.profiles.map(profile => [profile.target, profile.hostnames.length]), [
    ['acme-corp.example', 5], ['vupune.ac.in', 5], ['demo.owasp-juice.shop', 3], ['flipkart.com', 6], ['canva.com', 5], ['google.com', 200],
  ])
  for (const profile of config.profiles) {
    const audit = await query('/audits/' + profile.auditId)
    assert.equal(audit.simulated, true)
    assert.equal(audit.target_domain, profile.target)
    assert.equal(audit.summary.subdomains_total, profile.hostnames.length)
    assert.ok(audit.subdomains.every(host => host.subdomain.endsWith('.example') && host.categories.length === 10))
  }
  const lastGoogleHost = config.profiles.find(profile => profile.id === 'google').hostnames.at(-1)
  const posture = await query('/audits/demo-google/posture')
  assert.equal(pqcSeries(posture.assets).hosts.length, 200)
  const hostReport = await query('/audits/demo-google/export?format=json&host=' + lastGoogleHost)
  assert.equal(hostReport.target_domain, 'google.com')
  assert.deepEqual(hostReport.subdomains.map(host => host.subdomain), [lastGoogleHost])
  const replay = await query('/audits', { method: 'POST', data: { domain: 'canva.com', authorization_ref: 'CANVA-DEMO' } })
  const completed = await waitFor(query, '/audits/' + replay.id, value => value.status === 'completed')
  assert.equal(completed.profile_id, 'canva')
  assert.ok(completed.subdomains.every(host => host.subdomain.endsWith('.canva.example')))
  const leak = await request('/audits', { method: 'POST', data: {
    profile_id: 'canva', mode: 'hosts', hosts: [lastGoogleHost], authorization_ref: 'OTHER-PROFILE',
  } })
  assert.equal(leak.status, 400)
  await restart()
  const history = await query('/audits')
  assert.equal(history.filter(audit => audit.sample).length, 6)
  assert.ok(history.some(audit => audit.id === replay.id && audit.profile_id === 'canva'))
})

test('scheduled and on-demand deliveries, synthetic benchmark, and demo account controls operate locally', async t => {
  const { query, request } = await localApp(t)
  const report = { audit_id: 'demo-acme-corp', template: 'executive', channels: ['email', 'slack'] }
  const delivery = await query('/deliveries', { method: 'POST', data: report })
  assert.equal(delivery.status, 'simulated delivery')
  const schedule = await query('/deliveries', { method: 'POST', data: {
    ...report, template: 'on-demand', host: adminHost, run_at: new Date(Date.now() + 86_400_000).toISOString(),
  } })
  assert.equal(schedule.status, 'scheduled')
  assert.equal((await query('/deliveries')).length, 2)
  const benchmark = await query('/benchmark')
  assert.equal(benchmark.simulated, true)
  assert.equal(benchmark.results.length, 5)
  assert.ok(benchmark.results.every(result => result.f1 > 0 && result.f1 < 1))

  const preview = await query('/session/preview', { method: 'POST', data: {} })
  const login = await query('/session/login', { method: 'POST', data: { email: 'itadmin@acme-corp.example', password: 'requiem-demo' } })
  assert.equal(login.requires_totp, true)
  const session = await query('/session/verify', { method: 'POST', data: { challenge: login.challenge, code: '184026' } })
  assert.equal(session.account.role, 'itadmin')
  assert.equal((await request('/accounts', { token: session.token })).status, 403)
  const signup = await query('/session/signup', { method: 'POST', data: {
    email: 'qa@acme-corp.example', name: 'Demo QA', password: 'local-demo-qa',
  } })
  assert.equal(signup.account.role, 'viewer')
  assert.equal('passwordHash' in signup.account, false)
  const updated = await query('/accounts/' + signup.account.id, {
    method: 'PATCH', token: preview.token, data: { role: 'auditor' },
  })
  assert.equal(updated.role, 'auditor')
  await query('/session/reset', { method: 'POST', data: {}, token: session.token })
  assert.equal((await request('/session', { token: session.token })).status, 401)
})
