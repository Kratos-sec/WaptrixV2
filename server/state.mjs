import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { seed, stages, subset, tools } from './model.mjs'
import { fixtureFor, fixtures } from './profiles.mjs'

const defaultAccount = { id: 'presenter', name: 'Demo Presenter', email: 'demo@acme-corp.example', role: 'admin', totp: false }
export const roles = ['admin', 'itadmin', 'auditor', 'viewer']
export const demoPassword = 'requiem-demo'
export const demoOtp = '184026'
const defaultTools = seed.request.tools
const clock = () => new Date().toISOString()

export function fail(status, message) {
  throw Object.assign(new Error(message), { status })
}

function sampleRecord(fixture) {
  return {
    id: fixture.id, profile_id: fixture.profile_id, mode: 'domain', status: 'completed', step: stages.length,
    hosts: fixture.subdomains.map(host => host.subdomain), authorization_ref: fixture.authorization_ref, scope: [fixture.domain],
    tools: [...defaultTools], started_at: fixture.created_at, completed_at: fixture.completed_at, sample: true, events: fixture.run_log,
  }
}

function initialState() {
  return {
    audits: [], deliveries: [], accounts: [{ ...defaultAccount },
      { id: 'itadmin', name: 'Demo IT Administrator', email: 'itadmin@acme-corp.example', role: 'itadmin', totp: true },
      { id: 'auditor', name: 'Demo Auditor', email: 'auditor@acme-corp.example', role: 'auditor', totp: false },
      { id: 'viewer', name: 'Demo Viewer', email: 'viewer@acme-corp.example', role: 'viewer', totp: false }],
    nuclei: [],
  }
}

function addBundledSamples(data) {
  for (const fixture of fixtures) {
    if (data.audits.some(record => record.id === fixture.id)) continue
    const record = sampleRecord(fixture)
    data.audits.push(record)
    data.nuclei.push({
      id: fixture.id === seed.id ? 'nuclei-sample' : 'nuclei-' + fixture.id, audit_id: fixture.id, status: 'completed',
      hosts: record.hosts, at: fixture.completed_at,
    })
  }
}

function normalizedHost(value) {
  return String(value ?? '').trim().toLowerCase().replace(/\.$/, '')
}

function asList(value) {
  return (Array.isArray(value) ? value : String(value ?? '').split(/[\s,]+/)).map(normalizedHost).filter(Boolean)
}

function validateAudit(input) {
  const mode = input.mode ?? 'domain'
  if (!['domain', 'hosts'].includes(mode)) fail(400, 'Choose domain discovery or host list.')
  const fixture = fixtureFor(input.profile_id ?? input.domain ?? (mode === 'hosts' ? 'acme' : ''))
  if (!fixture || (mode === 'domain' && input.domain && fixtureFor(input.domain) !== fixture)) {
    fail(400, 'Choose a bundled demo profile or its reference domain.')
  }
  const hostnames = fixture.subdomains.map(host => host.subdomain)
  const known = new Set(hostnames)
  const ref = String(input.authorization_ref ?? '').trim()
  if (ref.length < 3 || ref.length > 80 || /[\r\n]/.test(ref)) fail(400, 'Enter an authorization reference of 3 to 80 characters.')
  const scope = [...new Set(asList(input.scope_domains ?? [fixture.domain]).map(value => fixtureFor(value) === fixture ? fixture.domain : value))]
  if (!scope.length || scope.length > 10 || scope.some(value => value !== fixture.domain && !known.has(value))) {
    fail(400, 'Scope must use the selected sample domain or its bundled hosts.')
  }
  const requested = [...new Set(mode === 'domain' ? hostnames : asList(input.hosts))]
  const limit = Math.max(30, hostnames.length)
  if (!requested.length || requested.length > limit) fail(400, 'Enter between one and ' + limit + ' sample hosts.')
  const hosts = requested.filter(host => known.has(host) && scope.some(value => host === value || host.endsWith('.' + value)))
  if (!hosts.length) fail(400, 'No bundled hosts match the declared scope.')
  const scope_rejections = requested.filter(host => !hosts.includes(host)).map(raw => ({ raw, reason: 'Outside the bundled demo scope' }))
  const chosen = input.tools ?? defaultTools
  if (!Array.isArray(chosen) || chosen.some(id => !tools.some(tool => tool.id === id))) fail(400, 'Choose tools from the demo catalog.')
  const selectedTools = [...new Set(['waptrix', ...chosen])]
  return { mode, profile_id: fixture.profile_id, authorization_ref: ref, scope, hosts, scope_rejections, tools: selectedTools }
}

export function createStore({ directory, interval = 1050 }) {
  const file = join(directory, 'state.json')
  let data
  try {
    data = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    data = initialState()
  }
  addBundledSamples(data)
  const timers = new Map()

  function save() {
    mkdirSync(dirname(file), { recursive: true })
    const temp = file + '.tmp'
    writeFileSync(temp, JSON.stringify(data, null, 2))
    renameSync(temp, file)
  }

  let recovered = false
  for (const record of [...data.audits, ...data.nuclei]) {
    if (record.status !== 'running') continue
    record.status = 'stopped'
    record.completed_at = clock()
    if (record.events) event(record, 'skipped', null, 'Replay interrupted when the local server exited')
    recovered = true
  }
  if (recovered) save()

  function event(record, status, host, detail, step = record.step) {
    const stage = stages[Math.min(step, stages.length - 1)][0]
    record.events.push({ seq: record.events.length + 1, at: clock(), stage, status, subdomain: host, round: 0, detail })
  }

  function get(id) {
    const record = data.audits.find(entry => entry.id === id)
    if (!record) fail(404, 'Audit not found.')
    return record
  }

  function listItem(record, scopedSummary) {
    const { id, status, mode, started_at, completed_at, hosts, authorization_ref, sample } = record
    const fixture = fixtureFor(record.profile_id ?? 'acme')
    const summary = scopedSummary ?? subset(fixture, hosts).summary
    return { id, status, mode, started_at, completed_at, hosts: hosts.length, authorization_ref, sample: Boolean(sample),
      profile_id: fixture.profile_id, profile_name: fixture.profile_name, target_domain: fixture.target_domain,
      score: status === 'completed' ? summary.overall_score : null, step: record.step }
  }

  function assetHistory(hostname) {
    const host = fixtures.flatMap(fixture => fixture.subdomains).find(item => item.subdomain === hostname)
    if (!host) fail(404, 'Host not found.')
    return data.audits.filter(record => record.hosts.includes(hostname)).map(record => ({
      ...listItem(record),
      findings: record.status === 'completed' ? host.findings.length : null,
      hostScore: record.status === 'completed' ? host.score : null,
    }))
  }

  function view(record) {
    const fixture = subset(fixtureFor(record.profile_id ?? 'acme'), record.hosts)
    const nucleiHosts = new Set(data.nuclei.filter(run => run.audit_id === record.id && run.status === 'completed').flatMap(run => run.hosts))
    const subdomains = fixture.subdomains.map(host => ({
      ...host,
      tool_runs: record.tools.map(id => ({
        tool: id, simulated: true,
        status: record.status === 'completed' ? 'completed' : record.status === 'stopped' ? 'skipped' : 'pending',
        findings: host.findings.filter(finding => finding.sources.includes(id) && (id !== 'nuclei' || nucleiHosts.has(host.subdomain))).length,
      })),
      findings: host.findings.map(finding => ({
        ...finding, sources: finding.sources.filter(source => source !== 'nuclei' || nucleiHosts.has(host.subdomain)),
      })),
    }))
    return {
      ...fixture, ...listItem(record, fixture.summary), subdomains, snapshot_at: fixture.created_at,
      request: { ...fixture.request, authorization_ref: record.authorization_ref, scope_domains: record.scope, subdomains: record.hosts, tools: record.tools },
      scope_rejections: record.scope_rejections ?? fixture.scope_rejections,
      stages: record.sample ? fixture.stages : stages.map(([stage, name], index) => ({
        stage, name, status: index < record.step ? 'completed' : index === record.step && record.status === 'running' ? 'started' :
          record.status === 'stopped' ? 'skipped' : 'pending',
      })),
      run_log: record.events,
      nuclei: data.nuclei.filter(run => run.audit_id === record.id).slice().reverse(),
    }
  }

  function clearTimer(id) {
    clearInterval(timers.get(id))
    timers.delete(id)
  }

  function start(input) {
    if (data.audits.some(record => record.status === 'running')) fail(409, 'An audit replay is already running.')
    const record = { ...validateAudit(input), id: randomUUID(), status: 'running', step: 0, started_at: clock(), completed_at: null, events: [] }
    event(record, 'started', null, stages[0][1])
    data.audits.unshift(record)
    save()
    timers.set(record.id, setInterval(() => {
      event(record, 'completed', null, stages[record.step][1])
      if (record.step > 0 && record.step < stages.length - 1) {
        for (const host of record.hosts) event(record, 'completed', host, 'Sample result recorded')
      }
      record.step++
      if (record.step === stages.length) {
        record.status = 'completed'
        record.completed_at = clock()
        if (record.tools.includes('nuclei')) data.nuclei.push({
          id: randomUUID(), audit_id: record.id, status: 'completed', hosts: record.hosts, at: record.completed_at,
        })
        clearTimer(record.id)
      } else {
        event(record, 'started', null, stages[record.step][1])
      }
      save()
    }, interval))
    return listItem(record)
  }

  function stop(record) {
    if (record.status !== 'running') fail(409, 'Only a running audit can be stopped.')
    record.status = 'stopped'
    record.completed_at = clock()
    event(record, 'skipped', null, 'Replay stopped by presenter')
    clearTimer(record.id)
    save()
    return view(record)
  }

  function remove(record) {
    if (record.sample || record.status === 'running') fail(409, 'The bundled snapshot and running audits are kept in history.')
    data.audits = data.audits.filter(item => item !== record)
    data.nuclei = data.nuclei.filter(run => run.audit_id !== record.id)
    save()
  }

  function startNuclei(record, input) {
    if (record.status !== 'completed') fail(409, 'Choose a completed audit.')
    if (data.nuclei.some(run => run.audit_id === record.id && run.status === 'running')) fail(409, 'A Nuclei replay is already running.')
    const hosts = [...new Set(asList(input.hosts ?? record.hosts))]
    if (!hosts.length || hosts.some(host => !record.hosts.includes(host))) fail(400, 'Choose one or more hosts from this audit.')
    const run = { id: randomUUID(), audit_id: record.id, status: 'running', hosts, at: clock() }
    data.nuclei.push(run)
    save()
    timers.set(run.id, setTimeout(() => {
      run.status = 'completed'
      run.completed_at = clock()
      timers.delete(run.id)
      save()
    }, interval * 2))
    return run
  }

  function stopNuclei(record, id) {
    const run = data.nuclei.find(item => item.audit_id === record.id && item.id === id)
    if (!run) fail(404, 'Nuclei replay not found.')
    if (run.status !== 'running') fail(409, 'Only a running replay can be stopped.')
    clearTimer(id)
    run.status = 'stopped'
    run.completed_at = clock()
    save()
    return run
  }

  function deliveries() {
    let changed = false
    for (const row of data.deliveries) {
      if (row.status !== 'scheduled' || row.run_at > clock()) continue
      row.status = 'simulated delivery'
      row.completed_at = clock()
      changed = true
    }
    if (changed) save()
    return data.deliveries
  }

  function delivery(input) {
    const record = get(input.audit_id)
    if (record.status !== 'completed') fail(409, 'Choose a completed audit.')
    const channels = [...new Set(Array.isArray(input.channels) ? input.channels : [])]
    if (!channels.length || channels.some(channel => !['email', 'slack'].includes(channel))) fail(400, 'Choose email or Slack.')
    if (input.host && !record.hosts.includes(input.host)) fail(400, 'Choose a host from this audit.')
    const scheduled = Boolean(input.run_at)
    const at = scheduled ? new Date(input.run_at) : new Date()
    if (!Number.isFinite(at.valueOf()) || (scheduled && at <= new Date())) fail(400, 'Choose a future date and time.')
    const row = {
      id: randomUUID(), audit_id: record.id, host: input.host || null, channels, run_at: at.toISOString(),
      template: input.template, status: scheduled ? 'scheduled' : 'simulated delivery',
      completed_at: scheduled ? null : clock(), simulated: true,
    }
    data.deliveries.unshift(row)
    save()
    return row
  }

  const sessions = new Map()
  const challenges = new Map()
  function accountById(id) {
    const account = data.accounts.find(user => user.id === id)
    if (!account) fail(404, 'Demo account not found.')
    return account
  }
  function openSession(account) {
    const token = randomUUID()
    sessions.set(token, account.id)
    return { token, account: publicAccount(account) }
  }
  function current(token) {
    if (!sessions.has(token)) fail(401, 'Sign in to the demo workspace.')
    return accountById(sessions.get(token))
  }
  function startSession(input) {
    const account = data.accounts.find(user => user.email === normalizedHost(input.email))
    if (!account || !matchesPassword(account, input.password)) fail(401, 'Check the demo email and password.')
    if (!account.totp) return openSession(account)
    const challenge = randomUUID()
    challenges.set(challenge, { id: account.id, expires: Date.now() + 180_000 })
    return { challenge, requires_totp: true }
  }
  function verifySession(input) {
    const challenge = challenges.get(input.challenge)
    if (!challenge || challenge.expires < Date.now() || input.code !== demoOtp) fail(400, 'Use the displayed demo authenticator code.')
    challenges.delete(input.challenge)
    return openSession(accountById(challenge.id))
  }
  function profile(input, existing) {
    const name = String(input.name ?? existing?.name ?? '').trim()
    const email = normalizedHost(input.email ?? existing?.email)
    if (name.length < 2 || name.length > 50) fail(400, 'Enter a name of 2 to 50 characters.')
    if (!/^[a-z0-9_.+-]+@acme-corp\.example$/.test(email) || email.length > 100) fail(400, 'Use an @acme-corp.example demo address.')
    if (data.accounts.some(user => user.email === email && user !== existing)) fail(409, 'That demo address is already in use.')
    return { name, email }
  }
  function signUp(input) {
    const account = { id: randomUUID(), ...profile(input), role: 'viewer', totp: false }
    if (input.password) updatePasswordHash(account, input.password)
    data.accounts.push(account)
    save()
    return openSession(account)
  }
  function updateProfile(account, input) {
    const changes = profile(input, account)
    if (typeof input.totp === 'boolean' && input.totp !== account.totp) {
      if (input.code !== demoOtp) fail(400, 'Enter the displayed demo authenticator code.')
      changes.totp = input.totp
    }
    if (input.new_password) {
      if (!matchesPassword(account, input.current_password)) fail(400, 'Check the current demo password.')
      updatePasswordHash(account, input.new_password)
    }
    Object.assign(account, changes)
    save()
    return publicAccount(account)
  }
  function updatePasswordHash(account, password) {
    if (typeof password !== 'string' || password.length < 8 || password.length > 72) fail(400, 'Use 8 to 72 characters for the demo password.')
    account.passwordSalt = randomBytes(16).toString('hex')
    account.passwordHash = scryptSync(password, account.passwordSalt, 32).toString('hex')
  }
  function matchesPassword(account, password) {
    if (typeof password !== 'string' || password.length > 72) return false
    if (!account.passwordHash) return password === demoPassword
    return timingSafeEqual(scryptSync(password, account.passwordSalt, 32), Buffer.from(account.passwordHash, 'hex'))
  }
  function resetSessions(account) {
    for (const [token, id] of sessions) if (id === account.id) sessions.delete(token)
  }
  function admin(account) {
    if (account.role !== 'admin') fail(403, 'Use an admin demo account.')
    return data.accounts.map(publicAccount)
  }
  function changeRole(account, id, role) {
    admin(account)
    const user = accountById(id)
    if (!roles.includes(role) || user.id === 'presenter' || user === account) fail(400, 'Choose a valid editable demo account and role.')
    user.role = role
    save()
    return publicAccount(user)
  }
  function deleteAccount(account, id) {
    admin(account)
    const user = accountById(id)
    if (user.id === 'presenter' || user === account) fail(400, 'Choose an editable demo account.')
    resetSessions(user)
    data.accounts = data.accounts.filter(item => item !== user)
    save()
  }

  return {
    list: () => data.audits.map(record => listItem(record)), get, view, assetHistory, start, stop, remove, startNuclei, stopNuclei, deliveries, delivery,
    previewSession: () => openSession(accountById('presenter')),
    current, publicAccount, startSession, verifySession, signUp, updateProfile, resetSessions, admin, changeRole, deleteAccount,
    signOut: token => sessions.delete(token), close: () => { for (const id of timers.keys()) clearTimer(id) },
  }
}

function publicAccount({ id, name, email, role, totp }) {
  return { id, name, email, role, totp }
}
