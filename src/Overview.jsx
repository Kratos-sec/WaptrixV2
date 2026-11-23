import React from 'react'
import { Layers3, ListChecks, Network, Radar, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Bars, ChartKey } from './DashboardCharts.jsx'
import { owaspSeries, statusColors } from './dashboard-data.mjs'
import { allFindings, Badge, Button, categoryCode, date, Empty, ExportLink, hostLabel, PageTitle, Pager, Panel, percent, Status, statuses, Table, usePages, word } from './ui.jsx'

const statusKey = Object.entries(statuses).map(([id, status]) => ({ name: status.label, fill: statusColors[id] }))
const coverageLabels = { high: 'High', partial: 'Partial', indicators: 'Indicators only', manual: 'Manual review' }

function Kpi({ label, value, context, icon: Icon, onClick }) {
  return <button type="button" className="dashboard-kpi panel" onClick={onClick}>
    <span><Icon size={16} aria-hidden="true" />{label}</span><strong>{value}</strong><small>{context}</small>
  </button>
}

export default function Overview({ audit, start, running, canEdit, canReport, navigate }) {
  const { summary } = audit
  const high = summary.severity_counts.high + summary.severity_counts.critical
  const distinctRules = new Set(allFindings(audit).map(finding => finding.rule_id)).size
  const series = owaspSeries(audit)
  const hostPage = usePages(series.hosts, 8)
  const visibleHosts = new Set(hostPage.visible.map(host => host.id))
  const focus = (host, category) => navigate('findings', { host, category })
  const openAsset = host => navigate('assets', { host })
  return <>
    <PageTitle eyebrow="2025 ASSESSMENT" title="OWASP Top 10 Dashboard"
      subtitle={<>Sample web application security posture for <strong>{audit.target_domain ?? audit.domain}</strong></>}
      actions={<>{canReport && <ExportLink audit={audit} />}<Button kind="primary" icon={Radar} onClick={start} disabled={running || !canEdit}>Replay scan</Button></>} />

    <div className="dashboard-metrics">
      <section className="score-card" aria-label="OWASP posture score">
        <div className="score-copy">
          <div className="score-kicker"><ShieldCheck size={16} /> OWASP POSTURE</div>
          <h2>{summary.overall_score < 60 ? 'Needs attention' : 'Security posture'}</h2>
          <p>Grade <strong>{summary.grade}</strong> across {summary.subdomains_total} assessed {summary.subdomains_total === 1 ? 'host' : 'hosts'}.</p>
          <span className="snapshot"><span /> Snapshot · {date(audit.snapshot_at)}</span>
        </div>
        <div className="score-ring" style={{ '--score': (summary.overall_score ?? 0) + '%' }}>
          <div><strong>{summary.overall_score ?? '—'}</strong><span>OUT OF 100</span></div>
        </div>
      </section>
      <Kpi label="Subdomains" value={summary.subdomains_reachable + '/' + summary.subdomains_total} icon={Network}
        context={(summary.subdomains_total - summary.subdomains_reachable) + ' unreachable · ' + audit.scope_rejections.length + ' rejected'}
        onClick={() => navigate('assets')} />
      <Kpi label="Findings" value={summary.total_findings} icon={ListChecks}
        context={distinctRules + ' rules · ' + summary.total_retest + ' awaiting re-test'} onClick={() => navigate('findings')} />
      <Kpi label="High / critical" value={high} icon={ShieldAlert}
        context={summary.severity_counts.medium + ' medium · ' + summary.severity_counts.low + ' low · ' + summary.severity_counts.info + ' info'}
        onClick={() => navigate('findings', { severity: 'high-or-critical' })} />
    </div>

    <div className="dashboard-grid charts-row">
      <Bars title="Findings by Severity" points={series.severity} unit=" findings" />
      <Bars title="Findings per OWASP Category" points={series.categories} unit=" findings"
        onSelect={point => focus('', point.id)} getLabel={point => 'View ' + point.id + ' ' + point.detail + ' findings, ' + point.value}>
        <ChartKey points={statusKey} showValues={false} />
      </Bars>
      <Bars title="Score by Subdomain" points={hostPage.visible} unit=" / 100" horizontal
        onSelect={point => openAsset(point.id)} getLabel={point => 'Open asset ' + point.id + ', ' + (point.rated ? 'score ' + point.value + ' out of 100' : 'unrated')}>
        <Pager pagination={hostPage} label="Hosts" />
      </Bars>
    </div>

    <Panel title="OWASP coverage matrix" description="Select a result to explore findings by host and category."
      action={<span className="panel-tag"><Layers3 size={15} /> {summary.categories.length} categories</span>} className="matrix-panel">
      <div className="matrix" tabIndex={0} role="region" aria-label="Subdomains and OWASP categories">
        <table>
          <thead><tr><th scope="col">Asset</th><th scope="col" className="matrix-grade">Grade</th>{summary.categories.map(category => <th key={category.id} scope="col" title={category.name}>
            <button type="button" onClick={() => focus('', category.id)} aria-label={category.id + ' ' + category.name}>{categoryCode(category.id)}</button>
          </th>)}</tr></thead>
          <tbody>{audit.subdomains.filter(host => visibleHosts.has(host.subdomain)).map(host => <tr key={host.subdomain}>
            <th scope="row" title={host.subdomain}><button type="button" className="matrix-host" onClick={() => openAsset(host.subdomain)}>
              <span className="host-dot" />{hostLabel(host.subdomain, audit.domain)}
            </button><small>{host.reachable ? (host.score ?? '—') + '/100 · ' + host.findings.length + ' findings' : 'Unreachable'}</small></th>
            <td className="matrix-grade"><Badge tone={host.grade === 'A' ? 'pass' : 'neutral'}>{host.grade}</Badge></td>
            {host.categories.map(category => <td key={category.id}>
              <button type="button" className="matrix-cell" aria-label={host.subdomain + ' ' + category.id + ' ' + statuses[category.status]?.label}
                title={category.name + ' · ' + statuses[category.status]?.label} onClick={() => focus(host.subdomain, category.id)}>
                <Status status={category.status} short />
              </button>
            </td>)}
          </tr>)}</tbody>
        </table>
      </div>
      <div className="matrix-legend">{Object.keys(statuses).map(status => <Status key={status} status={status} />)}</div>
      <Pager pagination={hostPage} label="Matrix rows" />
    </Panel>

    <div className="dashboard-grid owasp-details">
      <Panel title="OWASP Top 10 Compliance" description="A finding can appear in more than one category.">
        <Table headings={['Category', 'Pass rate', 'Findings', 'Result']}>{summary.categories.map(category => <tr key={category.id}>
          <th scope="row"><button type="button" className="text-button" onClick={() => focus('', category.id)}>
            {categoryCode(category.id)} · {category.name}
          </button><small>{coverageLabels[category.coverage] ?? word(category.coverage)} coverage</small></th>
          <td>{category.pass_rate == null ? '—' : percent(category.pass_rate)}</td><td>{category.finding_count}</td><td><Status status={category.status} /></td>
        </tr>)}</Table>
      </Panel>
      <Panel title="Most Significant Issues" description="Grouped by rule across the selected hosts.">
        {summary.top_rules.length ? <Table headings={['Issue', 'Severity', 'Instances']}>{summary.top_rules.map(rule => <tr key={rule.rule_id}>
          <th scope="row"><button type="button" className="text-button" onClick={() => navigate('findings', { query: rule.rule_id })}>
            {rule.title}
          </button><small>{rule.rule_id}</small></th>
          <td><Badge tone={rule.severity}>{word(rule.severity)}</Badge></td>
          <td>{rule.count}<small>{rule.subdomains} {rule.subdomains === 1 ? 'host' : 'hosts'}</small></td>
        </tr>)}</Table> : <Empty>No findings in this scope.</Empty>}
      </Panel>
    </div>
  </>
}
