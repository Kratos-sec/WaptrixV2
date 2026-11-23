import React, { useEffect, useState } from 'react'
import { CalendarDays, CircleCheck, ClipboardCheck, Clock, FileText, FlaskConical, Mail, MessageSquare, Play, Square, Trash2 } from 'lucide-react'
import PqcDashboard from './PqcDashboard.jsx'
import {
  api, allFindings, Badge, byPriority, Button, date, dateTime, Definitions, Dialog, Empty, ErrorText, ExportLink, Field,
  PageTitle, Pager, Panel, percent, Select, stageStatus, Table, Timeline, usePages, word,
} from './ui.jsx'

export function ScanForm({ config, activeProfile, tools, onClose, onSubmit }) {
  const [mode, setMode] = useState('domain')
  const [profile, setProfile] = useState(activeProfile)
  const [hosts, setHosts] = useState(activeProfile.hostnames.join('\n'))
  const [scope, setScope] = useState(activeProfile.domain)
  const [reference, setReference] = useState('DEMO-2026')
  const [selectedTools, setSelectedTools] = useState(config.suggestedTools)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await onSubmit({ mode, profile_id: profile.id, domain: profile.target, hosts, scope_domains: scope, authorization_ref: reference, tools: selectedTools })
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(false)
    }
  }
  return <Dialog title="Replay assessment" subtitle="Replay the bundled results for a synthetic profile." onClose={onClose} wide>
    <form onSubmit={submit} className="form-stack">
      <Select label="Replay profile" value={profile.id} options={config.profiles.map(item => [item.id, item.name + ' · ' + item.target])}
        onChange={event => {
          const next = config.profiles.find(item => item.id === event.target.value)
          setProfile(next)
          setHosts(next.hostnames.join('\n'))
          setScope(next.domain)
        }} />
      <div className="segmented" aria-label="Scope input">
        <button type="button" aria-pressed={mode === 'domain'} onClick={() => setMode('domain')}>Domain discovery</button>
        <button type="button" aria-pressed={mode === 'hosts'} onClick={() => setMode('hosts')}>Explicit host list</button>
      </div>
      {mode === 'domain' ? <p className="help">{profile.hostnames.length} bundled assets in the fictional scope <code>{profile.domain}</code>.</p> :
        <label className="field"><span>Sample hosts, one per line</span><textarea rows="5" value={hosts} onChange={event => setHosts(event.target.value)} required /></label>}
      <div className="form-grid">
        <Field label="Scope allowlist" value={scope} onChange={event => setScope(event.target.value)} required />
        <Field label="Authorization reference" value={reference} onChange={event => setReference(event.target.value)} minLength={3} maxLength={80} required />
      </div>
      <details className="options-details"><summary>Simulated tools <Badge>{selectedTools.length} selected</Badge></summary>
        <div className="tool-checks">{tools.map(tool => <label className="checkbox" key={tool.id}>
          <input type="checkbox" checked={selectedTools.includes(tool.id)} disabled={tool.id === 'waptrix'} onChange={event =>
            setSelectedTools(previous => event.target.checked ? [...previous, tool.id] : previous.filter(id => id !== tool.id))} />{tool.name}
        </label>)}</div>
      </details>
      <ErrorText>{error}</ErrorText>
      <div className="actions form-actions"><Button onClick={onClose}>Cancel</Button><Button kind="primary" icon={Play} type="submit" disabled={busy}>Start replay</Button></div>
    </form>
  </Dialog>
}

export function WorkflowPage({ audit, run, history, selectAudit, stop, removeAudit, onStart, canEdit }) {
  const [useRunning, setUseRunning] = useState(true)
  const active = (useRunning && run) || audit
  const [host, setHost] = useState('')
  const [stage, setStage] = useState('')
  const [showStarts, setShowStarts] = useState(false)
  const [error, setError] = useState('')
  const notices = active.run_log.filter(event =>
    (!host || event.subdomain === host) && (!stage || event.stage === stage) && (showStarts || event.status !== 'started'))
  const logPage = usePages([...notices].reverse(), 30)
  async function runAction(action) {
    setError('')
    try { await action() } catch (error) { setError(error.message) }
  }
  return <>
    <PageTitle eyebrow="ASSESSMENT OPERATIONS" title="Audit workflow" subtitle="Trace stage progress, scope decisions, and recorded tool activity."
      actions={run ? <Button icon={Square} onClick={() => runAction(stop)} disabled={!canEdit}>Stop replay</Button> :
        <Button kind="primary" icon={Play} onClick={onStart} disabled={!canEdit}>Replay scan</Button>} />
    <ErrorText>{error}</ErrorText>
    <Panel title={active.sample ? 'Bundled assessment' : active.authorization_ref} description={(active.profile_name ?? 'Acme Corp') + ' · ' + active.subdomains.length + ' hosts · ' + word(active.mode)}
      action={<Badge tone={active.status === 'completed' ? 'pass' : 'warning'}>{word(active.status)}</Badge>}>
      <Timeline stages={active.stages} />
      <div className="workflow-scope"><Definitions entries={[['Authorization', active.authorization_ref], ['Scope', active.request.scope_domains.join(', ')],
        ['Tools', active.request.tools.map(word).join(', ')], ['Started', dateTime(active.started_at)]]} />
        {active.scope_rejections.length > 0 && <details className="options-details"><summary>{active.scope_rejections.length} scope rejections</summary>
          <ul className="compact-list">{active.scope_rejections.map((item, index) => <li key={index}>{item.raw} · {item.reason}</li>)}</ul></details>}
      </div>
    </Panel>
    <Panel title="Run history" description="Open an assessment to review its results and logs.">
      <Table headings={['Assessment', 'Mode', 'Hosts', 'Score', 'Status', 'Actions']}>
        {history.map(item => <tr key={item.id}>
          <th scope="row"><button type="button" className="text-button" onClick={() => runAction(async () => {
            setUseRunning(item.id === run?.id)
            await selectAudit(item.id)
            setHost('')
            setStage('')
            logPage.goTo(0)
          })}>{item.sample ? (item.profile_name ?? 'Acme Corp') + ' sample' : item.authorization_ref}</button><small>{dateTime(item.started_at)}</small></th>
          <td>{item.mode === 'hosts' ? 'Explicit hosts' : 'Domain discovery'}</td><td>{item.hosts}</td><td>{item.score ?? '—'}</td>
          <td><Badge tone={item.status === 'completed' ? 'pass' : 'warning'}>{word(item.status)}</Badge></td>
          <td>{!item.sample && item.status !== 'running' && <button className="icon-button" type="button" aria-label={'Delete audit ' + item.authorization_ref} disabled={!canEdit}
            onClick={() => { if (window.confirm('Delete this demo audit from history?')) runAction(() => removeAudit(item.id)) }}><Trash2 size={16} /></button>}</td>
        </tr>)}
      </Table>
    </Panel>
    <Panel title="Run log" description="Inspect recorded events for this assessment.">
      <div className="filters">
        <Select label="Host" value={host} onChange={event => { setHost(event.target.value); logPage.goTo(0) }} options={[['', 'All events'], ...active.subdomains.map(item => item.subdomain)]} />
        <Select label="Stage" value={stage} onChange={event => { setStage(event.target.value); logPage.goTo(0) }} options={[['', 'All stages'], ...active.stages.map(item => [item.stage, item.name])]} />
        <label className="checkbox"><input type="checkbox" checked={showStarts} onChange={event => { setShowStarts(event.target.checked); logPage.goTo(0) }} /> Include start events</label>
      </div>
      {notices.length ? <Table headings={['Stage', 'Host', 'State', 'Detail', 'Time']}>{logPage.visible.map(event =>
        <tr key={event.seq}><th scope="row">{event.stage}</th><td>{event.subdomain ?? 'Engagement'}</td><td>{stageStatus(event.status)}</td>
          <td>{event.detail || '—'}</td><td>{dateTime(event.at)}</td></tr>)}</Table> : <Empty>No events match the filters.</Empty>}
      <Pager pagination={logPage} label="Events" />
    </Panel>
  </>
}

export function Posture({ audit, data, inspectHost, inspectFinding }) {
  const [tab, setTab] = useState('pqc')
  const tabNames = [['pqc', 'Readiness overview'], ['cbom', 'CBOM'], ['rating', 'Cyber Rating'], ['mappings', 'Compliance Mappings']]
  const title = <PageTitle eyebrow="CRYPTOGRAPHIC INTELLIGENCE" title="PQC Dashboard" subtitle={'Sample post-quantum readiness and cryptographic posture for ' + (audit.target_domain ?? audit.domain) + '.'} />
  if (!data) return <>{title}<Panel><Empty>Loading cryptographic inventory…</Empty></Panel></>
  const high = data.assets.filter(asset => asset.quantumRisk === 'High').length
  return <>
    {title}
    <div className="segmented feature-tabs" aria-label="Posture view">
      {tabNames.map(([key, title]) => <button type="button" key={key} aria-pressed={tab === key} onClick={() => setTab(key)}>{title}</button>)}
    </div>
    {tab === 'cbom' && <Panel title="Cryptographic bill of materials" description="Per-host protocols, ciphers, key inventory, and certificate health.">
      <Table headings={['Asset', 'Protocol', 'Cipher', 'Key', 'Issuer', 'Expiry']}>{data.assets.map(({ host, keyAlgorithm, keySize }) =>
        <tr key={host.subdomain}><th scope="row"><button type="button" className="text-button" onClick={() => inspectHost(host)}>{host.subdomain}</button></th>
          <td>{host.tls?.protocol ?? 'No HTTPS'}</td><td><code>{host.tls?.cipher ?? '—'}</code></td>
          <td>{[keyAlgorithm, keySize].filter(Boolean).join(' ') || '—'}</td><td>{host.tls?.cert_issuer ?? '—'}</td><td>{date(host.tls?.cert_not_after)}</td></tr>)}</Table>
    </Panel>}
    {tab === 'pqc' && <PqcDashboard key={audit.id} assets={data.assets} inspectHost={inspectHost} inspectFinding={inspectFinding} />}
    {tab === 'rating' && <Panel title="Requiem cyber rating" description="Based on transport, cipher strength, and PQC risk signals.">
      <div className="rating-readout"><strong>{data.rating}</strong><span>/ 1000</span><Badge tone={data.tier === 'Critical' ? 'warning' : 'neutral'}>{data.tier}</Badge></div>
      <div className="rating-meter" role="meter" aria-label="Cyber rating" aria-valuemin={0} aria-valuemax={1000} aria-valuenow={data.rating}>
        <span style={{ width: data.rating / 10 + '%' }} />
      </div>
      <Definitions entries={ [['Assets assessed', data.assets.length], ['High PQC risk', high], ['Rating scale', 'Critical · Legacy · Standard · Elite']] } />
    </Panel>}
    {tab === 'mappings' && <Panel title="Cryptographic compliance mappings" description="Review indicators associated with NIST PQC, ISO 27001, and GDPR.">
      {data.mappings.length ? <Table headings={['Asset', 'Control', 'Priority', 'Frameworks']}>{data.mappings.map(mapping =>
        <tr key={mapping.host + mapping.control}><th scope="row">{mapping.host}</th><td>{mapping.control}</td>
          <td><Badge tone="high">{mapping.risk}</Badge></td><td><div className="tags">{mapping.frameworks.map(value => <Badge key={value}>{value}</Badge>)}</div></td></tr>)}</Table> :
        <Empty>No mapping indicators in this assessment.</Empty>}
    </Panel>}
  </>
}

const reportOptions = [['executive', 'Executive assessment'], ['technical', 'Technical audit'], ['on-demand', 'On-demand assessment']]
const formats = [['pdf', 'PDF'], ['html', 'HTML'], ['json', 'JSON'], ['csv', 'CSV'], ['sarif', 'SARIF']]

export function Reports({ audit, canEdit, initialHost = '' }) {
  const [tab, setTab] = useState('builder')
  const [template, setTemplate] = useState('executive')
  const [format, setFormat] = useState('pdf')
  const [host, setHost] = useState(initialHost)
  const [channels, setChannels] = useState(['email'])
  const [runAt, setRunAt] = useState('')
  const [deliveries, setDeliveries] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (tab !== 'delivery') return
    let cancelled = false
    async function refresh() {
      try {
        const rows = await api('/deliveries')
        if (!cancelled) setDeliveries(rows)
      } catch (error) { if (!cancelled) setError(error.message) }
    }
    refresh()
    const timer = setInterval(refresh, 3000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [tab])
  const sampleHost = audit.subdomains.find(item => item.subdomain === host)
  const scopedFindings = sampleHost?.findings ?? allFindings(audit)
  const label = reportOptions.find(([id]) => id === template)[1]
  async function deliver(event) {
    event.preventDefault()
    setError('')
    setNotice('')
    setBusy(true)
    try {
      const row = await api('/deliveries', { method: 'POST', data: {
        audit_id: audit.id, host, template, channels, run_at: runAt ? new Date(runAt).toISOString() : null,
      } })
      setDeliveries(previous => [row, ...previous.filter(item => item.id !== row.id)])
      setNotice(runAt ? 'Demo delivery scheduled.' : 'Delivery recorded in the simulation log.')
    } catch (error) {
      setError(error.message)
    } finally {
      setBusy(false)
    }
  }
  return <>
    <PageTitle eyebrow="REPORTING" title="Assessment reports" subtitle="Prepare an executive summary or evidence-focused export." />
    <div className="segmented feature-tabs" aria-label="Reporting view">
      <button type="button" aria-pressed={tab === 'builder'} onClick={() => setTab('builder')}><FileText size={17} /> Report builder</button>
      <button type="button" aria-pressed={tab === 'delivery'} onClick={() => setTab('delivery')}><CalendarDays size={17} /> Delivery & schedule</button>
    </div>
    <div className="report-grid">
      <Panel title={tab === 'builder' ? 'Configure export' : 'Configure delivery'} className="report-config">
        <form className="form-stack inset" onSubmit={deliver}>
          <Select label="Template" value={template} onChange={event => setTemplate(event.target.value)} options={reportOptions} />
          <Select label="Scope" value={host} onChange={event => setHost(event.target.value)}
            options={[['', 'Entire assessment'], ...audit.subdomains.map(item => item.subdomain)]} />
          {tab === 'builder' ? <>
            <Select label="Format" value={format} onChange={event => setFormat(event.target.value)} options={formats} />
            <ExportLink audit={audit} format={format} host={host} template={template} kind="primary">Download {formats.find(([id]) => id === format)[1]}</ExportLink>
          </> : <>
            <Field label="Delivery time (optional)" type="datetime-local" value={runAt} onChange={event => setRunAt(event.target.value)} />
            <fieldset className="channel-field"><legend>Sample channels</legend>{[['email', Mail], ['slack', MessageSquare]].map(([channel, Icon]) =>
              <label className="checkbox" key={channel}><input type="checkbox" checked={channels.includes(channel)} onChange={event =>
                setChannels(previous => event.target.checked ? [...previous, channel] : previous.filter(value => value !== channel))} /><Icon size={15} />{word(channel)}</label>)}</fieldset>
            <Button kind="primary" type="submit" icon={CalendarDays} disabled={busy || !canEdit || !channels.length || audit.status !== 'completed'}>
              {runAt ? 'Schedule demo delivery' : 'Simulate delivery'}
            </Button>
            <ErrorText>{error}</ErrorText>{notice && <p className="success-text" role="status"><CircleCheck size={16} />{notice}</p>}
          </>}
        </form>
      </Panel>
      <Panel title="Report preview" description="A summary of the selected assessment scope.">
        <article className="report-preview">
          <div><span><FlaskConical size={14} /> Simulated assessment</span><h3>{label}</h3><p>{sampleHost?.subdomain ?? audit.domain}</p></div>
          <Definitions entries={[['OWASP score', (sampleHost?.score ?? audit.summary.overall_score) + '/100'],
            ['Assets', sampleHost ? 1 : audit.subdomains.length], ['Findings', scopedFindings.length], ['Snapshot', date(audit.snapshot_at)]]} />
          <div className="preview-priorities"><strong>Priority recommendations</strong>
            <ul className="compact-list">{[...scopedFindings].sort(byPriority).slice(0, 3).map(finding => <li key={finding.id}>{finding.title}</li>)}</ul></div>
        </article>
      </Panel>
    </div>
    {tab === 'delivery' && <Panel title="Local delivery log" description="Scheduled and simulated outcomes for this workspace.">
      {deliveries.length ? <Table headings={['Template', 'Scope', 'Channels', 'Time', 'Status']}>{deliveries.map(row =>
        <tr key={row.id}><th scope="row">{reportOptions.find(([id]) => id === row.template)?.[1]}</th><td>{row.host || 'Entire assessment'}</td>
          <td>{row.channels.map(word).join(', ')}</td><td>{dateTime(row.run_at)}</td>
          <td><Badge tone={row.status === 'scheduled' ? 'warning' : 'pass'}>{word(row.status)}</Badge></td></tr>)}</Table> : <Empty>No demo deliveries recorded.</Empty>}
    </Panel>}
  </>
}

export function Benchmark({ results }) {
  const sizes = results.reduce((sum, row) => ({ tp: sum.tp + row.tp, fp: sum.fp + row.fp, fn: sum.fn + row.fn }), { tp: 0, fp: 0, fn: 0 })
  const scores = [['Precision', sizes.tp / (sizes.tp + sizes.fp)], ['Recall', sizes.tp / (sizes.tp + sizes.fn)],
    ['F1 score', 2 * sizes.tp / (2 * sizes.tp + sizes.fp + sizes.fn)]]
  return <>
    <PageTitle eyebrow="ASSESSMENT QUALITY" title="Benchmark lab" subtitle="Fixture metrics illustrate comparison against labeled ground truth."
      actions={<Badge tone="warning"><FlaskConical size={14} /> Sample benchmark</Badge>} />
    <div className="stat-row">{scores.map(([name, value]) => <Panel title={name} key={name}><strong className="metric-number">{percent(value)}</strong></Panel>)}</div>
    <Panel title="Recorded evaluation sample" description="Synthetic counts for the five applications in the original benchmark inventory.">
      <Table headings={['Application', 'True positive', 'False positive', 'False negative', 'Precision', 'Recall', 'F1']}>{results.map(row =>
        <tr key={row.name}><th scope="row">{row.name}</th><td>{row.tp}</td><td>{row.fp}</td><td>{row.fn}</td>
          <td>{percent(row.precision)}</td><td>{percent(row.recall)}</td><td>{percent(row.f1)}</td></tr>)}</Table>
    </Panel>
    <Panel title="Evaluation tools" description="The local CLI and API expose the same demo metrics."
      action={<ClipboardCheck size={21} />}><code className="command">npm run cli -- benchmark</code></Panel>
  </>
}
