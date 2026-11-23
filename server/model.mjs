import { readFileSync } from 'node:fs'

function readFixture(file) {
  return JSON.parse(readFileSync(new URL('../data/' + file, import.meta.url), 'utf8'))
}

const original = readFixture('audit.json')
export const catalog = readFixture('rules.json')
export const domain = 'acme-corp.example'
export const hostnames = original.subdomains.map(host => host.subdomain)
export const severities = ['critical', 'high', 'medium', 'low', 'info']
export const stages = [
  ['S1', 'Scope & authorization'],
  ['S2', 'Discovery & TLS'],
  ['S3', 'Application mapping'],
  ['S4', 'Vulnerability assessment'],
  ['S5', 'Finding correlation'],
  ['S6', 'OWASP scoring & reports'],
]
export const tools = [
  ['waptrix', 'WAPTrix checks', 'HTTP, TLS, and OWASP observations'],
  ['subfinder', 'Subfinder', 'Subdomain discovery'],
  ['httpx', 'httpx', 'HTTP reachability'],
  ['nmap', 'Nmap', 'Port and service inventory'],
  ['sslyze', 'SSLyze', 'TLS and certificate posture'],
  ['nuclei', 'Nuclei', 'Template-based finding records'],
  ['whatweb', 'WhatWeb', 'Technology inventory'],
  ['testssl', 'testssl.sh', 'TLS cross-checks'],
  ['retire', 'Retire.js', 'JavaScript library inventory'],
  ['zap', 'OWASP ZAP', 'Web assessment records'],
  ['nikto', 'Nikto', 'Web server assessment records'],
  ['wapiti', 'Wapiti', 'Web assessment records'],
  ['sqlmap', 'sqlmap', 'Assessment provenance'],
].map(([id, name, purpose]) => ({ id, name, purpose, mode: 'Recorded fixture' }))

const inventory = [
  ['Public website', 'Web app', 'nginx 1.26', 'RSA', 3072],
  ['Customer portal', 'Web app', 'nginx 1.24', 'EC', 256],
  ['Public API', 'API', 'Envoy 1.30', 'EC', 256],
  ['Administration', 'Admin portal', 'Apache 2.4', 'RSA', 2048],
  ['Legacy portal', 'Web app', 'Apache 2.2', null, null],
]
const nucleiRules = new Set(['TLS-CERT-EXPIRED', 'TLS-CERT-HOSTNAME-MISMATCH', 'TLS-NO-HTTPS', 'HDR-HSTS-MISSING'])

export const seed = structuredClone(original)
seed.simulated = true
seed.domain = domain
seed.mode = 'domain'
seed.request.tools = tools.slice(0, 6).map(tool => tool.id)
for (const [index, host] of seed.subdomains.entries()) {
  const [label, type, serviceVersion, keyAlgorithm, keySize] = inventory[index]
  const quantumRisk = !host.tls?.protocol || keySize === 2048 ? 'High' : keyAlgorithm === 'EC' ? 'Medium' : 'Low'
  const ports = [{ port: 80, service: 'HTTP', version: serviceVersion }]
  if (host.tls?.protocol) ports.push({ port: 443, service: 'HTTPS', version: serviceVersion })
  host.inventory = {
    label, type, ports, dns: host.ip_addresses.map(ip => ({ type: ip.includes(':') ? 'AAAA' : 'A', value: ip })),
  }
  host.cbom = { keyAlgorithm, keySize, quantumRisk, status: host.tls?.protocol ? 'Observed TLS' : 'No HTTPS' }
  for (const finding of host.findings) {
    if (nucleiRules.has(finding.rule_id)) finding.sources = [...new Set([...(finding.sources ?? []), 'nuclei'])]
  }
  host.tool_runs = seed.request.tools.map(tool => ({
    tool,
    status: 'completed',
    findings: host.findings.filter(finding => finding.sources?.includes(tool)).length,
    simulated: true,
  }))
}

export const lookalikes = [
  { domain: 'acme-c0rp.example', relatedHost: hostnames[0], pattern: 'Character substitution', dns: 'A record', mx: 'MX record', risk: 'High' },
  { domain: 'acmecorp.example', relatedHost: hostnames[1], pattern: 'Hyphen omission', dns: 'A record', mx: 'None observed', risk: 'Medium' },
  { domain: 'acme-corps.example', relatedHost: hostnames[2], pattern: 'Character insertion', dns: 'Unresolved', mx: 'None observed', risk: 'Low' },
]

export const benchmark = [
  ['DVWA', 18, 3, 4],
  ['OWASP Juice Shop', 24, 4, 7],
  ['WebGoat', 20, 3, 5],
  ['bWAPP', 16, 4, 6],
  ['Mutillidae II', 22, 5, 7],
].map(([name, tp, fp, fn]) => ({
  name, tp, fp, fn, precision: tp / (tp + fp), recall: tp / (tp + fn), f1: 2 * tp / (2 * tp + fp + fn),
}))

export function findingsOf(audit) {
  return audit.subdomains.flatMap(host => host.findings)
}

export function priorityFindings(audit) {
  return findingsOf(audit).sort((a, b) =>
    severities.indexOf(a.severity) - severities.indexOf(b.severity) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0),
  )
}

export function grade(score) {
  if (score === null) return 'N/A'
  return [[90, 'A'], [80, 'B'], [70, 'C'], [60, 'D']].find(([minimum]) => score >= minimum)?.[1] ?? 'F'
}

export function subset(audit, selectedHosts) {
  const wanted = new Set(selectedHosts)
  const subdomains = audit.subdomains.filter(host => wanted.has(host.subdomain))
  if (subdomains.length === audit.subdomains.length) return audit
  return {
    ...audit,
    subdomains,
    run_log: audit.run_log.filter(event => !event.subdomain || wanted.has(event.subdomain)),
    summary: summarize(subdomains, audit.summary.categories),
  }
}

export function summarize(subdomains, categoryCatalog) {
  const findings = subdomains.flatMap(host => host.findings)
  const scores = subdomains.filter(host => host.reachable && host.score !== null).map(host => host.score)
  const score = scores.length ? Math.round(scores.reduce((total, value) => total + value, 0) / scores.length) : null
  const statusOrder = ['manual_review', 'pass', 'warning', 'fail']
  const categories = categoryCatalog.map(category => {
    const cells = subdomains.filter(host => host.reachable).map(host => host.categories.find(cell => cell.id === category.id))
    const matched = findings.filter(finding => finding.owasp.includes(category.id))
    const rated = cells.filter(cell => cell.status !== 'manual_review')
    return {
      ...category,
      status: statusOrder[Math.max(0, ...cells.map(cell => statusOrder.indexOf(cell.status)))],
      finding_count: matched.length,
      max_severity: severities.find(severity => matched.some(finding => finding.severity === severity)) ?? null,
      rule_ids: [...new Set(matched.map(finding => finding.rule_id))].sort(),
      pass_rate: rated.length ? rated.filter(cell => cell.status === 'pass').length / rated.length : null,
    }
  })
  const topRules = new Map()
  for (const finding of findings) {
    const group = topRules.get(finding.rule_id) ?? { ...finding, count: 0, hosts: new Set() }
    group.count++
    group.hosts.add(finding.subdomain)
    topRules.set(finding.rule_id, group)
  }
  return {
    overall_score: score, grade: grade(score), subdomains_total: subdomains.length,
    subdomains_reachable: subdomains.filter(host => host.reachable).length,
    total_findings: findings.length, total_retest: subdomains.reduce((count, host) => count + host.retest_queue.length, 0),
    severity_counts: Object.fromEntries(severities.map(severity => [severity, findings.filter(finding => finding.severity === severity).length])),
    grade_distribution: Object.fromEntries(['A', 'B', 'C', 'D', 'F', 'N/A'].map(value => [value, subdomains.filter(host => host.grade === value).length])),
    categories,
    top_rules: [...topRules.values()]
      .sort((a, b) => severities.indexOf(a.severity) - severities.indexOf(b.severity) || b.count - a.count)
      .slice(0, 10).map(({ rule_id, title, severity, count, hosts }) => ({ rule_id, title, severity, count, subdomains: hosts.size })),
  }
}

export function cryptoPosture(audit) {
  const assets = audit.subdomains.map(host => ({ host, ...host.cbom }))
  const points = assets.map(asset => {
    const tls = asset.host.tls
    const cipher = tls?.cipher ?? ''
    return Math.max(0, (tls?.protocol === 'TLSv1.3' ? 40 : 0) + (/AES|CHACHA20/i.test(cipher) ? 40 : 0) + (asset.quantumRisk === 'High' ? -30 : 20))
  })
  const rating = points.length ? Math.floor(points.reduce((sum, value) => sum + value, 0) / points.length) * 10 : 0
  const tier = rating >= 850 ? 'Elite' : rating >= 700 ? 'Standard' : rating >= 500 ? 'Legacy' : 'Critical'
  const mappings = assets.flatMap(({ host, quantumRisk }) => {
    const checks = []
    if (quantumRisk === 'High') checks.push(['Cryptographic migration review', 'High', ['NIST PQC', 'ISO 27001']])
    if (host.tls?.days_to_expiry < 30) checks.push(['Certificate lifecycle review', 'High', ['ISO 27001', 'GDPR']])
    if (!host.tls?.protocol || host.tls.legacy_protocols_accepted?.length) checks.push(['Transport encryption review', 'High', ['NIST PQC', 'ISO 27001', 'GDPR']])
    return checks.map(([control, risk, frameworks]) => ({ host: host.subdomain, control, risk, frameworks }))
  })
  return { rating, tier, assets, mappings }
}
