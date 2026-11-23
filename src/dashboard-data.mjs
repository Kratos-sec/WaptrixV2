const severityColors = {
  critical: '#791535', high: '#af3e61', medium: '#bd8434', low: '#5d8c77', info: '#887998',
}
export const statusColors = {
  pass: '#5d8c77', warning: '#bd8434', fail: '#af3e61', manual_review: '#887998',
}
const gradeColors = { A: '#4d806d', B: '#709078', C: '#b78033', D: '#c66c4a', F: '#af3e61' }
const tiers = [
  ['Elite', 'Elite / PQC Ready', '#4d806d'],
  ['Standard', 'Standard', '#b78033'],
  ['Legacy', 'Legacy', '#c66c4a'],
  ['Critical', 'Critical', '#af3e61'],
]
const riskLevels = [['Low', '#5d8c77'], ['Medium', '#bd8434'], ['High', '#af3e61']]
const expiryBuckets = [
  ['Expired / 0–30 days', 30, '#af3e61', '≤30d'],
  ['31–60 days', 60, '#c66c4a', '31–60d'],
  ['61–90 days', 90, '#bd8434', '61–90d'],
  ['Over 90 days', Infinity, '#5d8c77', '>90d'],
]
const typeColors = ['#763450', '#577d9c', '#bb8a3d', '#658f7b']

export function owaspSeries(audit) {
  const severity = Object.entries(severityColors).map(([id, fill]) => ({
    id, name: id === 'info' ? 'Info' : id[0].toUpperCase() + id.slice(1), value: audit.summary.severity_counts[id] ?? 0, fill,
  }))
  const categories = audit.summary.categories.map(category => ({
    id: category.id, name: category.id.split(':')[0], detail: category.name, value: category.finding_count,
    fill: statusColors[category.status],
  }))
  const hosts = [...audit.subdomains].sort((a, b) => (a.score ?? -1) - (b.score ?? -1)).map(host => ({
    id: host.subdomain, name: host.subdomain.endsWith('.' + audit.domain)
      ? host.subdomain.slice(0, -(audit.domain.length + 1)) : host.subdomain,
    detail: host.subdomain, value: host.score ?? 0, rated: host.score != null, fill: gradeColors[host.grade] ?? '#887998',
  }))
  return { severity, categories, hosts }
}

function readiness(asset) {
  if (asset.quantumRisk === 'High') return 'Critical'
  if (asset.pqcSupported === true) return 'Elite'
  const tls = asset.host.tls
  const protocols = [tls?.protocol, ...(tls?.legacy_protocols_accepted ?? [])]
  const oldProtocol = protocols.some(protocol => /^TLSv?1(?:\.0|\.1)?$/i.test(protocol ?? ''))
  const weakCipher = /(?:^|[_-])(?:3DES|DES|RC4|MD5|SHA1|NULL)(?:[_-]|$)/i.test(tls?.cipher ?? '')
  const shortRsa = asset.keyAlgorithm === 'RSA' && asset.keySize > 0 && asset.keySize < 2048
  return oldProtocol || weakCipher || shortRsa ? 'Legacy' : 'Standard'
}

export function pqcSeries(assets) {
  const hosts = assets.map(asset => ({ ...asset, readiness: readiness(asset) }))
  const grade = tiers.map(([id, name, fill]) => ({
    id, name, axisLabel: id, fill, value: hosts.filter(asset => asset.readiness === id).length,
  }))
  const [elite, standard, legacy, critical] = grade
  const migration = [
    { name: 'Secure / PQC ready', value: elite.value, fill: elite.fill },
    { name: 'Moderate / Transition', value: standard.value, fill: standard.fill },
    { name: 'High risk / Vulnerable', value: critical.value + legacy.value, fill: critical.fill },
  ]
  const risks = riskLevels.map(([name, fill]) => ({
    name, fill, value: hosts.filter(asset => asset.quantumRisk === name).length,
  }))
  const types = new Map()
  const addresses = new Set()
  const expiry = expiryBuckets.map(([name, , fill, axisLabel]) => ({ name, fill, axisLabel, value: 0 }))
  for (const { host } of hosts) {
    const type = host.inventory.type
    types.set(type, (types.get(type) ?? 0) + 1)
    for (const ip of host.ip_addresses) addresses.add(ip)
    const days = host.tls?.days_to_expiry
    if (Number.isFinite(days)) expiry[expiryBuckets.findIndex(([, limit]) => days <= limit)].value++
  }
  const inventory = [...types].sort(([a], [b]) => a.localeCompare(b)).map(([name, value], index) => ({
    name, value, fill: typeColors[index % typeColors.length],
  }))
  const ipv6 = [...addresses].filter(ip => ip.includes(':')).length
  const ipVersions = [
    { name: 'IPv4', value: addresses.size - ipv6, fill: '#577d9c' },
    { name: 'IPv6', value: ipv6, fill: '#8b6d9b' },
  ]
  return { hosts, grade, migration, risks, inventory, expiry, ipVersions }
}
