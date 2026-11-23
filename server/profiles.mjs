import { catalog, grade, seed, severities, stages, summarize } from './model.mjs'

const permissions = 'HDR-PERMISSIONS-MISSING'
const referrer = 'HDR-REFERRER-MISSING'
const framing = 'HDR-XFO-MISSING'
const hsts = 'HDR-HSTS-MISSING'
const csp = 'HDR-CSP-MISSING'
const expiry = 'TLS-CERT-EXPIRING'
const noHttps = 'TLS-NO-HTTPS'
const findingsByRule = new Map(seed.subdomains.flatMap(host => host.findings).map(finding => [finding.rule_id, finding]))
const weights = { critical: 30, high: 15, medium: 8, low: 3, info: 0 }
const categories = Object.entries(catalog.categories).map(([id, { name, coverage }]) => ({ id, name, coverage }))
const alphabet = ['Web app', 'API', 'Admin portal']

const definitions = [
  {
    id: 'vupune', name: 'Vishwakarma University', target: 'vupune.ac.in',
    rows: [['www', [hsts, permissions]], ['admissions', [expiry]], ['student-portal', [csp, framing]], ['library', [noHttps, referrer]], ['api', []]],
  },
  {
    id: 'juice-shop', name: 'OWASP Juice Shop', target: 'demo.owasp-juice.shop',
    aliases: ['owaspjuiecshop', 'owaspjuiceshop', 'owasp-juice.shop'],
    rows: [['storefront', [csp, hsts, framing, permissions, referrer]], ['api', [hsts, permissions]], ['admin', [noHttps, framing]]],
  },
  {
    id: 'flipkart', name: 'Flipkart', target: 'flipkart.com',
    rows: [['storefront', []], ['catalog', [permissions]], ['checkout', [expiry, referrer]], ['orders', []], ['seller', [hsts]], ['support', [framing]]],
  },
  {
    id: 'canva', name: 'Canva', target: 'canva.com',
    rows: [['editor', [referrer]], ['assets', []], ['api', [expiry]], ['templates', [permissions]], ['help', []]],
  },
  {
    id: 'google', name: 'Google', target: 'google.com',
    rows: Array.from({ length: 200 }, (_, index) => {
      const ordinal = index + 1
      const rules = []
      if (ordinal % 17 === 0) rules.push(permissions)
      if (ordinal % 27 === 0) rules.push(referrer)
      if (ordinal % 37 === 0) rules.push(expiry)
      if (ordinal % 53 === 0) rules.push(hsts)
      return ['host-' + String(ordinal).padStart(3, '0'), rules]
    }),
  },
]

function hostFixture(domain, [label, rules], index, snapshot) {
  const subdomain = label + '.' + domain
  const secure = !rules.includes(noHttps)
  const url = (secure ? 'https://' : 'http://') + subdomain + '/'
  const findings = rules.map(rule => {
    const meta = catalog.rules[rule]
    return {
      id: subdomain + ':' + rule, rule_id: rule, title: meta.title, severity: meta.severity, confidence: 'firm', subdomain, url,
      description: meta.description, evidence: 'Synthetic demo observation: ' + meta.title + '.',
      remediation: meta.remediation, cwe: meta.cwe, cwe_name: meta.cwe_name, wstg: meta.wstg,
      owasp: meta.owasp, cvss_vector: meta.cvss_vector, cvss_score: findingsByRule.get(rule)?.cvss_score ?? null,
      sources: [hsts, expiry].includes(rule) ? ['waptrix', 'nuclei'] : ['waptrix'],
    }
  })
  const score = 100 - findings.reduce((total, finding) => total + weights[finding.severity], 0)
  const ip_addresses = ['198.51.100.' + (index + 1)]
  if (index % 7 === 0) ip_addresses.push('2001:db8::' + (index + 1).toString(16))
  const type = label === 'api' ? 'API' : label === 'admin' ? 'Admin portal' : alphabet[index % alphabet.length]
  const algorithm = index % 3 === 0 ? 'RSA' : 'EC'
  const days = rules.includes(expiry) ? 12 : 45 + index % 100
  const headers = {
    'content-type': type === 'API' ? 'application/json' : 'text/html; charset=utf-8',
    'content-security-policy': "default-src 'self'",
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=()',
    'x-frame-options': 'DENY',
    'strict-transport-security': 'max-age=31536000',
  }
  for (const [rule, name] of [[csp, 'content-security-policy'], [referrer, 'referrer-policy'],
    [permissions, 'permissions-policy'], [framing, 'x-frame-options'], [hsts, 'strict-transport-security']]) {
    if (rules.includes(rule)) delete headers[name]
  }
  if (!secure) delete headers['strict-transport-security']
  const response = { url, final_url: url, status_code: 200, headers, redirect_chain: [], error: null }
  return {
    subdomain, reachable: true, scheme: secure ? 'https' : 'http', status_code: 200, final_url: url, ip_addresses,
    https_redirect: secure, https: secure ? response : null, http: secure ? null : response,
    tls: secure ? {
      protocol: index % 4 === 0 ? 'TLSv1.2' : 'TLSv1.3', cipher: index % 4 === 0 ? 'ECDHE-RSA-AES128-GCM-SHA256' : 'TLS_AES_128_GCM_SHA256',
      cipher_bits: 128, cert_issuer: 'Synthetic Demo CA', cert_subject: subdomain,
      cert_not_after: new Date(Date.parse(snapshot) + days * 86_400_000).toISOString(), days_to_expiry: days,
      trusted: true, hostname_match: true, legacy_protocols_accepted: [],
    } : null,
    findings, score: Math.max(0, score), grade: grade(Math.max(0, score)), retest_queue: [], technologies: [],
    categories: categories.map(category => {
      const matching = findings.filter(finding => finding.owasp.includes(category.id))
      const severity = severities.find(value => matching.some(finding => finding.severity === value))
      const status = category.coverage === 'manual' ? 'manual_review' :
        severity && weights[severity] >= weights.medium ? 'fail' :
          severity === 'low' ? 'warning' : ['high', 'partial'].includes(category.coverage) ? 'pass' : 'manual_review'
      return { ...category, status, finding_count: matching.length }
    }),
    app_map: { endpoints: [{ url, method: 'GET', params: [], source: 'page' }], truncated: false },
    inventory: {
      label, type, ports: (secure ? [80, 443] : [80]).map(port => ({ port, service: port === 443 ? 'HTTPS' : 'HTTP', version: 'Sample service' })),
      dns: ip_addresses.map(value => ({ type: value.includes(':') ? 'AAAA' : 'A', value })),
    },
    cbom: {
      keyAlgorithm: secure ? algorithm : null, keySize: secure ? algorithm === 'RSA' ? 3072 : 256 : null,
      quantumRisk: !secure ? 'High' : index % 3 === 0 ? 'Medium' : 'Low', status: secure ? 'Observed TLS' : 'No HTTPS',
    },
  }
}

function createProfile(definition) {
  const domain = definition.id + '.example'
  const snapshot = seed.created_at
  const subdomains = definition.rows.map((row, index) => hostFixture(domain, row, index, snapshot))
  const run_log = stages.map(([stage, detail], index) => ({ seq: index + 1, at: snapshot, stage, status: 'completed', detail, subdomain: null }))
  return {
    id: 'demo-' + definition.id, domain, target_domain: definition.target, profile_id: definition.id, profile_name: definition.name,
    simulated: true, status: 'completed', mode: 'domain', created_at: snapshot, completed_at: snapshot, authorization_ref: 'DEMO-' + definition.id.toUpperCase(),
    subdomains, scope_rejections: [], run_log, stages: stages.map(([stage, name]) => ({ stage, name, status: 'completed' })),
    request: { tools: seed.request.tools, scope_domains: [domain], subdomains: subdomains.map(host => host.subdomain) },
    summary: summarize(subdomains, categories),
  }
}

const acme = { ...seed, profile_id: 'acme', profile_name: 'Acme Corp', target_domain: seed.domain }
export const fixtures = [acme, ...definitions.map(createProfile)]
export const profileCatalog = fixtures.map(fixture => ({
  id: fixture.profile_id, name: fixture.profile_name, target: fixture.target_domain, domain: fixture.domain,
  auditId: fixture.id, hostnames: fixture.subdomains.map(host => host.subdomain),
}))

export function fixtureFor(value) {
  const key = String(value ?? '').trim().toLowerCase().replace(/\.$/, '').replace(/^www\./, '')
  const alias = definitions.find(definition => definition.aliases?.includes(key))
  return fixtures.find(fixture =>
    [fixture.profile_id, fixture.id, fixture.domain, fixture.target_domain].includes(key) || fixture.profile_id === alias?.id)
}
