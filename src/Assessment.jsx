import React, { useEffect, useState } from 'react'
import { AppWindow, BookOpen, FileText, Globe2, List, Play, Radar, Search, ShieldCheck, Square, Workflow } from 'lucide-react'
import {
  api, allFindings, Badge, byPriority, Button, categoryCode, date, dateTime, Definitions, Dialog, Empty,
  ErrorText, ExportLink, Field, hostLabel, PageTitle, Pager, Panel, Select, severityOrder, Status, Table, usePages, word,
} from './ui.jsx'

export function Assets({ audit, inspect, navigate }) {
  const [view, setView] = useState('list')
  const [query, setQuery] = useState('')
  const [type, setType] = useState('')
  const hosts = audit.subdomains.filter(host => {
    const haystack = [host.subdomain, host.inventory.label, ...host.ip_addresses, ...host.technologies.map(tech => tech.name)]
    return (!type || host.inventory.type === type) && haystack.join(' ').toLowerCase().includes(query.trim().toLowerCase())
  })
  const hostPage = usePages(hosts, 12)
  return <>
    <PageTitle eyebrow="DISCOVERY" title="Asset inventory" subtitle={'DNS, liveness, services, and certificates across ' + audit.domain + '.'} />
    <Panel title="Discovered assets" description={hosts.length + ' of ' + audit.subdomains.length + ' hosts in this assessment'}
      action={<div className="segmented" aria-label="Inventory view">
        <button type="button" aria-pressed={view === 'list'} onClick={() => setView('list')}><List size={17} /> List</button>
        <button type="button" aria-pressed={view === 'graph'} onClick={() => setView('graph')}><Workflow size={17} /> Graph</button>
      </div>}>
      <div className="filters">
        <Field label="Search assets" placeholder="Host, IP address, technology…" value={query} onChange={event => { setQuery(event.target.value); hostPage.goTo(0) }} />
        <Select label="Asset type" value={type} onChange={event => { setType(event.target.value); hostPage.goTo(0) }}
          options={[['', 'All types'], ...new Set(audit.subdomains.map(host => host.inventory.type))]} />
      </div>
      {!hosts.length ? <Empty>No assets match these filters.</Empty> : view === 'list' ?
        <Table headings={['Asset', 'IP addresses', 'HTTP', 'TLS / certificate', 'Ports', 'Grade']}>
          {hostPage.visible.map(host => <tr key={host.subdomain}>
            <th scope="row"><button type="button" className="text-button" onClick={() => inspect(host)}>{host.subdomain}</button><small>{host.inventory.label} · {host.inventory.type}</small></th>
            <td><code>{host.ip_addresses.join(', ') || '—'}</code></td>
            <td><Badge tone={host.status_code >= 400 ? 'warning' : host.reachable ? 'pass' : 'neutral'}>{host.status_code ?? 'Unreachable'}</Badge></td>
            <td>{host.tls?.protocol ?? 'No HTTPS'}<small>{host.tls?.protocol ? host.tls.trusted ? 'Trusted certificate' : 'Certificate review' : 'HTTP only'}</small></td>
            <td>{host.inventory.ports.map(port => port.port).join(', ')}</td>
            <td><Badge tone={host.grade === 'A' ? 'pass' : 'warning'}>{host.grade}</Badge></td>
          </tr>)}
        </Table> :
        <div className="topology">
          <div className="topology-root"><Globe2 size={22} /><strong>{audit.domain}</strong></div>
          <div className="topology-branches" style={{ '--nodes': hostPage.visible.length }}>{hostPage.visible.map(host => <div className="topology-branch" key={host.subdomain}>
            <button type="button" aria-label={'Open asset ' + host.subdomain} onClick={() => inspect(host)}>
              <AppWindow size={20} /><strong>{hostLabel(host.subdomain, audit.domain)}</strong><span>{host.inventory.type}</span>
              <Badge tone={host.grade === 'A' ? 'pass' : 'warning'}>Grade {host.grade}</Badge>
            </button>
          </div>)}</div>
        </div>}
      <Pager pagination={hostPage} label="Assets" />
    </Panel>
    <Panel title="Discovery evidence" description="DNS records, open ports, TLS posture, and tool provenance are available on each host."
      action={<Button icon={Radar} onClick={() => navigate('workflow')}>View run</Button>} />
  </>
}

export function AssetDetail({ host, audit, onClose, showFindings, selectAudit, canReport }) {
  const [tab, setTab] = useState('posture')
  const [history, setHistory] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (tab !== 'history') return
    let cancelled = false
    api('/assets/' + encodeURIComponent(host.subdomain) + '/history')
      .then(rows => { if (!cancelled) setHistory(rows) })
      .catch(error => { if (!cancelled) setError(error.message) })
    return () => { cancelled = true }
  }, [host.subdomain, tab])
  const tls = host.tls
  const headerEntries = Object.entries(host.https?.headers ?? host.http?.headers ?? {})
  return <Dialog title={host.subdomain} subtitle={host.inventory.label + ' · ' + host.inventory.type} onClose={onClose} wide>
    <div className="actions detail-actions">
      <Badge tone={host.grade === 'A' ? 'pass' : 'warning'}>Grade {host.grade} · {host.score ?? '—'}/100</Badge>
      <Button icon={List} onClick={showFindings}>View {host.findings.length} findings</Button>
      {canReport && <ExportLink audit={audit} host={host.subdomain}>Host PDF</ExportLink>}
    </div>
    <div className="segmented detail-tabs" aria-label="Asset detail view">
      {[['posture', 'Posture'], ['map', 'Application map'], ['evidence', 'HTTP evidence'], ['tools', 'Tool results'], ['history', 'Finding history']].map(([value, label]) =>
        <button key={value} type="button" aria-pressed={tab === value} onClick={() => setTab(value)}>{label}</button>)}
    </div>
    {tab === 'posture' && <>
      <Definitions entries={[
        ['Reachability', host.reachable ? 'Reachable' : 'Unreachable'], ['HTTP status', host.status_code],
        ['DNS records', host.inventory.dns.map(item => item.type + ' ' + item.value).join(', ')],
        ['Negotiated TLS', tls?.protocol ?? 'No HTTPS'], ['Cipher', tls?.cipher], ['Cipher strength', tls?.cipher_bits ? tls.cipher_bits + ' bit' : null],
        ['Issuer', tls?.cert_issuer], ['Subject', tls?.cert_subject], ['Expires at snapshot', date(tls?.cert_not_after)],
        ['Trust', tls?.protocol ? tls.trusted ? 'Trusted' : tls.verify_error ?? 'Review' : 'No HTTPS'],
        ['Hostname match', tls?.protocol ? tls.hostname_match ? 'Matches' : 'Does not match' : '—'],
        ['Legacy protocols', tls?.legacy_protocols_accepted?.join(', ') || 'None observed'],
      ]} />
      <h3>Ports and services</h3>
      <Table headings={['Port', 'Service', 'Version']}>{host.inventory.ports.map(port => <tr key={port.port}><td>{port.port}</td><td>{port.service}</td><td>{port.version}</td></tr>)}</Table>
      <h3>OWASP results</h3>
      <div className="tags">{host.categories.map(category => <span className="category-pill" key={category.id}>{categoryCode(category.id)} <Status status={category.status} short /></span>)}</div>
    </>}
    {tab === 'map' && (host.app_map?.endpoints?.length ?
      <Table headings={['Method', 'Endpoint', 'Parameters', 'Observed in']}>{host.app_map.endpoints.map((endpoint, index) =>
        <tr key={index}><td><Badge>{endpoint.method}</Badge></td><td><code>{endpoint.url}</code></td><td>{endpoint.params.join(', ') || '—'}</td><td>{word(endpoint.source)}</td></tr>)}</Table> :
      <Empty>No application routes were recorded for this host.</Empty>)}
    {tab === 'evidence' && <>
      <Definitions entries={ [['Final URL', host.final_url], ['Response code', host.status_code],
        ['HTTPS redirect', host.https_redirect ? 'Observed' : 'Not observed'],
        ['Technologies', host.technologies.map(tech => [tech.name, tech.version].filter(Boolean).join(' ')).join(', ') || '—']] } />
      <h3>Observed response headers</h3>
      {headerEntries.length ? <Table headings={['Header', 'Observed value']}>{headerEntries.map(([key, value]) =>
        <tr key={key}><th scope="row">{key}</th><td><code>{Array.isArray(value) ? value.join(', ') : String(value)}</code></td></tr>)}</Table> : <Empty />}
    </>}
    {tab === 'tools' && <>
      <Table headings={['Tool', 'Recorded state', 'Findings']}>{host.tool_runs.map(run =>
        <tr key={run.tool}><th scope="row">{run.tool}</th><td><Badge tone={run.status === 'completed' ? 'pass' : 'neutral'}>{word(run.status)}</Badge></td><td>{run.findings}</td></tr>)}</Table>
      <h3>Correlation review</h3>
      {host.retest_queue.length ? <ul className="compact-list">{host.retest_queue.map(item => <li key={item.id}>{item.title} · {word(item.confidence)} confidence</li>)}</ul> :
        <Empty>No candidates are queued for manual review.</Empty>}
    </>}
    {tab === 'history' && <>
      <ErrorText>{error}</ErrorText>
      {history ? <Table headings={['Run', 'Score', 'Findings', 'Status']}>{history.map(row => <tr key={row.id}>
        <th scope="row"><button type="button" className="text-button" onClick={() => selectAudit(row.id).catch(error => setError(error.message))}>
          {row.sample ? 'Bundled assessment' : row.authorization_ref}
        </button><small>{dateTime(row.started_at)}</small></th>
        <td>{row.hostScore ?? '—'}</td><td>{row.findings ?? '—'}</td><td><Badge tone={row.status === 'completed' ? 'pass' : 'warning'}>{word(row.status)}</Badge></td>
      </tr>)}</Table> : !error && <Empty>Loading host history…</Empty>}
    </>}
  </Dialog>
}

function FindingRows({ findings, inspect, domain }) {
  return <Table headings={['Finding', 'Asset', 'Severity', 'CVSS', 'OWASP', 'Source']}>
    {findings.map(finding => <tr key={finding.id}>
      <th scope="row"><button type="button" className="text-button" onClick={() => inspect(finding)}>{finding.title}</button><small>{finding.rule_id}</small></th>
      <td>{hostLabel(finding.subdomain, domain)}</td>
      <td><Badge tone={finding.severity}>{word(finding.severity)}</Badge></td><td>{finding.cvss_score?.toFixed(1) ?? '—'}</td>
      <td>{finding.owasp.map(categoryCode).join(', ') || '—'}</td>
      <td>{finding.sources.map(word).join(', ')}</td>
    </tr>)}
  </Table>
}

export function Findings({ audit, initial, inspect, lookalikes, refresh, canEdit }) {
  const [tab, setTab] = useState(initial.tab || 'explorer')
  const [filters, setFilters] = useState({ query: '', host: '', severity: '', category: '', source: '', ...initial })
  const [grouped, setGrouped] = useState(false)
  const [nucleiHost, setNucleiHost] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const all = allFindings(audit)
  const sources = [...new Set(['nuclei', ...all.flatMap(finding => finding.sources)])].sort()
  const visible = all.filter(finding =>
    (!filters.host || finding.subdomain === filters.host) &&
    (!filters.severity || finding.severity === filters.severity ||
      (filters.severity === 'high-or-critical' && ['high', 'critical'].includes(finding.severity))) &&
    (!filters.category || finding.owasp.includes(filters.category)) && (!filters.source || finding.sources.includes(filters.source)) &&
    [finding.title, finding.description, finding.rule_id, finding.cwe, finding.evidence].join(' ').toLowerCase().includes(filters.query.trim().toLowerCase()),
  ).sort(byPriority)
  const groups = new Map()
  for (const finding of visible) {
    const entries = groups.get(finding.rule_id) ?? []
    entries.push(finding)
    groups.set(finding.rule_id, entries)
  }
  const matchedLookalikes = lookalikes.filter(record => audit.subdomains.some(host => host.subdomain === record.relatedHost))
  const running = audit.nuclei.find(run => run.status === 'running')
  const field = name => ({ value: filters[name], onChange: event => setFilters(previous => ({ ...previous, [name]: event.target.value })) })
  async function replay(stop) {
    setBusy(true)
    setError('')
    try {
      const path = '/audits/' + audit.id + '/nuclei' + (stop ? '/' + running.id + '/stop' : '')
      await api(path, { method: 'POST', data: nucleiHost ? { hosts: [nucleiHost] } : {} })
      await refresh(audit.id)
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(false)
    }
  }
  return <>
    <PageTitle eyebrow="VULNERABILITY ASSESSMENT" title="Findings explorer" subtitle="Inspect vulnerability evidence and prioritize remediation."
      actions={<Button icon={BookOpen} onClick={() => { window.location.hash = 'rules' }}>Rule catalog</Button>} />
    <div className="segmented feature-tabs" aria-label="Finding workspace">
      {[['explorer', 'All findings'], ['nuclei', 'Nuclei runs'], ['lookalikes', 'Lookalike domains']].map(([value, label]) =>
        <button key={value} type="button" aria-pressed={tab === value} onClick={() => setTab(value)}>{label}</button>)}
    </div>
    {tab === 'explorer' && <Panel title="Assessment findings" description={visible.length + ' of ' + all.length + ' findings'}
      action={<label className="checkbox"><input type="checkbox" checked={grouped} onChange={event => setGrouped(event.target.checked)} /> Group by rule</label>}>
      <div className="filters">
        <Field label="Search findings" placeholder="Title, CWE, evidence…" {...field('query')} />
        <Select label="Host" options={[['', 'All hosts'], ...audit.subdomains.map(host => [host.subdomain, host.subdomain])]} {...field('host')} />
        <Select label="Severity" options={[['', 'All severities'], ['high-or-critical', 'High / critical'], ...severityOrder.map(value => [value, word(value)])]} {...field('severity')} />
        <Select label="OWASP category" options={[['', 'All categories'], ...audit.summary.categories.map(category => [category.id, categoryCode(category.id) + ' · ' + category.name])]} {...field('category')} />
        <Select label="Source" options={[['', 'All sources'], ...sources.map(source => [source, word(source)])]} {...field('source')} />
      </div>
      {!visible.length ? <Empty>No findings match these filters. Manual-review results may need evidence outside this assessment.</Empty> :
        grouped ? <div className="rule-groups">{[...groups].map(([rule, findings]) => <details key={rule}>
          <summary>{findings[0].title} <Badge>{findings.length} {findings.length === 1 ? 'instance' : 'instances'}</Badge></summary>
          <FindingRows findings={findings} inspect={inspect} domain={audit.domain} />
        </details>)}</div> : <FindingRows findings={visible} inspect={inspect} domain={audit.domain} />}
    </Panel>}
    {tab === 'nuclei' && <Panel title="Nuclei run history" description="Replay recorded findings for the whole audit or a selected asset."
      action={<Button icon={Search} onClick={() => { setFilters(previous => ({ ...previous, source: 'nuclei' })); setTab('explorer') }}>Show findings</Button>}>
      <div className="filters actions">
        <Select label="Host scope" options={[['', 'All audit hosts'], ...audit.subdomains.map(host => host.subdomain)]} value={nucleiHost} onChange={event => setNucleiHost(event.target.value)} />
        <Button kind="primary" icon={running ? Square : Play} disabled={busy || !canEdit || audit.status !== 'completed'} onClick={() => replay(Boolean(running))}>{running ? 'Stop replay' : 'Replay Nuclei'}</Button>
      </div>
      <ErrorText>{error}</ErrorText>
      {audit.nuclei.length ? <Table headings={['Run', 'Hosts', 'Started', 'Status']}>{audit.nuclei.map(run =>
        <tr key={run.id}><th scope="row">{run.id === 'nuclei-sample' ? 'Bundled run' : run.id.slice(0, 8)}</th><td>{run.hosts.length}</td><td>{dateTime(run.at)}</td><td><Badge tone={run.status === 'completed' ? 'pass' : 'warning'}>{word(run.status)}</Badge></td></tr>)}</Table> : <Empty>No Nuclei replays for this audit.</Empty>}
    </Panel>}
    {tab === 'lookalikes' && <Panel title="Lookalike domains" description="Recorded domain similarity, DNS, and mail indicators.">
      {matchedLookalikes.length ? <Table headings={['Domain', 'Related asset', 'Pattern', 'DNS', 'Mail', 'Risk']}>{matchedLookalikes.map(record =>
        <tr key={record.domain}><th scope="row">{record.domain}</th><td>{record.relatedHost}</td><td>{record.pattern}</td><td>{record.dns}</td><td>{record.mx}</td><td><Badge tone={record.risk.toLowerCase()}>{record.risk}</Badge></td></tr>)}</Table> :
        <Empty>No lookalike records for these hosts.</Empty>}
    </Panel>}
  </>
}

export function FindingDetail({ finding, onClose }) {
  const correlation = finding.correlation
  return <Dialog title={finding.title} subtitle={finding.subdomain + ' · ' + finding.rule_id} onClose={onClose} wide>
    <div className="tags detail-actions"><Badge tone={finding.severity}>{word(finding.severity)}</Badge>
      <Badge>CVSS {finding.cvss_score?.toFixed(1) ?? '—'}</Badge>{finding.owasp.map(category => <Badge key={category}>{category}</Badge>)}</div>
    <p className="detail-copy">{finding.description}</p>
    <Definitions entries={[
      ['URL', finding.url], ['CWE', [finding.cwe, finding.cwe_name].filter(Boolean).join(' · ') || '—'],
      ['WSTG', finding.wstg], ['CVSS vector', finding.cvss_vector], ['Sources', finding.sources.map(word).join(', ')], ['Confidence', word(finding.confidence)],
    ]} />
    <h3><FileText size={18} /> Observed evidence</h3><pre className="evidence">{finding.evidence || 'No evidence excerpt was recorded.'}</pre>
    <div className="remediation"><h3><ShieldCheck size={19} /> Recommended action</h3><p>{finding.remediation}</p></div>
    {correlation && <><h3>Correlation</h3><Definitions entries={[
      ['Outcome', correlation.confirmed ? 'Corroborated' : 'Recorded evidence'],
      ['Confidence score', correlation.score ?? finding.correlation_score],
      ['Threshold', correlation.threshold], ['Detectors', correlation.detectors?.join(', ')],
    ]} /></>}
  </Dialog>
}

export function Rules({ catalog }) {
  const [query, setQuery] = useState('')
  const entries = Object.entries(catalog.rules).filter((([id, rule]) =>
    [id, rule.title, rule.cwe, rule.wstg, ...rule.owasp].join(' ').toLowerCase().includes(query.trim().toLowerCase())))
  return <>
    <PageTitle eyebrow="ASSESSMENT REFERENCE" title="Rule catalog" subtitle="Built-in checks, OWASP category mappings, and remediation." />
    <Panel title="OWASP rule catalog" description={entries.length + ' matching rules'}>
      <div className="filters"><Field label="Search rules" value={query} onChange={event => setQuery(event.target.value)} placeholder="Rule, category, CWE, or WSTG" /></div>
      {entries.length ? <div className="rule-groups">{entries.map(([id, rule]) => <details key={id}>
        <summary>{rule.title} <Badge tone={rule.severity}>{word(rule.severity)}</Badge><small>{id}</small></summary>
        <div className="rule-body"><p>{rule.description}</p><div className="tags">{[...rule.owasp, rule.cwe, rule.wstg].filter(Boolean).map(value => <Badge key={value}>{value}</Badge>)}</div><p><strong>Recommended action</strong> {rule.remediation}</p></div>
      </details>)}</div> : <Empty />}
    </Panel>
  </>
}
