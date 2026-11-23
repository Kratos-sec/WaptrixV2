import React, { useState } from 'react'
import { AppWindow, Network, ShieldAlert, ShieldCheck, Target } from 'lucide-react'
import { Bars, Distribution } from './DashboardCharts.jsx'
import { pqcSeries } from './dashboard-data.mjs'
import { Badge, Button, byPriority, date, Definitions, Empty, Pager, Panel, percent, usePages, word } from './ui.jsx'

const riskTones = { Low: 'pass', Medium: 'warning', High: 'high' }
const transitionActions = {
  Elite: 'Track the deployed PQC configuration and verify interoperability during upgrades.',
  Standard: 'Inventory key exchange dependencies and plan a post-quantum migration.',
  Legacy: 'Retire deprecated cryptography before starting the post-quantum migration.',
  Critical: 'Resolve the current transport and certificate risks before starting the post-quantum migration.',
}

function MigrationReadiness({ groups, total }) {
  return <Panel title="Migration Readiness" className="dashboard-chart">
    <div className="migration-list">
      {groups.map(group => <div className="migration-item" key={group.name}>
        <div><strong>{group.name}</strong><span>{group.value} <small>({percent(total ? group.value / total : 0)})</small></span></div>
        <progress aria-label={group.name} aria-valuetext={group.value + ' of ' + total + ' assets'}
          value={group.value} max={total || 1} style={{ '--chart-color': group.fill }} />
      </div>)}
    </div>
  </Panel>
}

function AssetDeepDive({ asset, inspectHost }) {
  if (!asset) return <Panel title="Asset Deep Dive"><Empty>Select an asset to inspect its posture.</Empty></Panel>
  const { host, readiness, quantumRisk, keyAlgorithm, keySize } = asset
  return <Panel title="Asset Deep Dive" action={<Badge tone={riskTones[quantumRisk]}>{quantumRisk} risk</Badge>}>
    <div className="pqc-detail inset">
      <div className="pqc-selected"><AppWindow size={20} aria-hidden="true" /><div><strong>{host.subdomain}</strong>
        <small>{host.ip_addresses.join(', ') || 'No IP addresses recorded'}</small></div></div>
      <Definitions entries={[
        ['Asset type', host.inventory.type], ['Readiness tier', readiness], ['TLS', host.tls?.protocol ?? 'No HTTPS'],
        ['Observed key', [keyAlgorithm, keySize].filter(Boolean).join(' ') || '—'],
        ['Certificate expiry', date(host.tls?.cert_not_after)], ['Open ports', host.inventory.ports.map(item => item.port).join(', ') || '—'],
      ]} />
      <Button icon={Network} onClick={() => inspectHost(host)}>Open asset details</Button>
    </div>
  </Panel>
}

function PriorityActions({ asset, inspectFinding }) {
  if (!asset) return <Panel title="Priority Actions"><Empty>No asset selected.</Empty></Panel>
  const { host, readiness, quantumRisk } = asset
  const priorities = host.findings.filter(finding => finding.owasp.includes('A04:2025')).sort(byPriority).slice(0, 3)
  return <Panel title="Priority Actions" description={host.subdomain}>
    <div className="pqc-actions inset">
      {priorities.map(finding => <button type="button" className="pqc-action" onClick={() => inspectFinding(finding)} key={finding.id}>
        <strong>{finding.title}</strong><Badge tone={finding.severity}>{word(finding.severity)}</Badge>
        <span>{finding.remediation}</span>
      </button>)}
      <div className="pqc-action guidance"><strong>PQC migration</strong><Badge tone={riskTones[quantumRisk]}>{quantumRisk} risk</Badge>
        <span>{transitionActions[readiness]}</span></div>
    </div>
  </Panel>
}

export default function PqcDashboard({ assets, inspectHost, inspectFinding }) {
  const [selected, setSelected] = useState('')
  const series = pqcSeries(assets)
  const hostPage = usePages(series.hosts, 12)
  const active = series.hosts.find(asset => asset.host.subdomain === selected) ?? series.hosts[0]
  return <>
    <section className="pqc-banner" aria-label="PQC readiness counts">
      <div className="pqc-banner-title"><ShieldCheck size={21} aria-hidden="true" /><div><h2>PQC Readiness</h2>
        <p>{series.hosts.length} assets in this assessment</p></div></div>
      <dl>{series.grade.map(point => <div key={point.id} style={{ '--chart-color': point.fill }}>
        <dt>{point.name}</dt><dd>{point.value}</dd>
      </div>)}</dl>
    </section>

    <div className="dashboard-grid charts-row">
      <Bars title="Assets by Grade" points={series.grade} unit=" assets" />
      <Distribution title="Application Status" points={series.grade} unit=" assets" doughnut totalLabel="Assets" />
      <MigrationReadiness groups={series.migration} total={series.hosts.length} />
    </div>

    <div className="dashboard-grid pqc-workbench">
      <Panel title="Asset Inventory" description="Select a host to review its posture.">
        {series.hosts.length ? <div className="pqc-assets">{hostPage.visible.map(asset => <button type="button" key={asset.host.subdomain}
          aria-pressed={active?.host.subdomain === asset.host.subdomain} onClick={() => setSelected(asset.host.subdomain)}>
          <Target size={17} aria-hidden="true" /><span><strong>{asset.host.subdomain}</strong><small>{asset.host.ip_addresses.join(', ') || 'No IP addresses recorded'}</small></span>
          <Badge tone={riskTones[asset.quantumRisk]}>{asset.readiness}</Badge>
        </button>)}</div> : <Empty>No assets in this scope.</Empty>}
        <Pager pagination={hostPage} label="PQC assets" />
      </Panel>
      <AssetDeepDive asset={active} inspectHost={inspectHost} />
      <PriorityActions asset={active} inspectFinding={inspectFinding} />
    </div>

    <section className="pqc-infrastructure" aria-label="Infrastructure charts">
      <div className="section-heading"><ShieldAlert size={19} aria-hidden="true" /><h2>Infrastructure overview</h2></div>
      <div className="dashboard-grid infrastructure-charts">
        <Distribution title="Asset Distribution" points={series.inventory} unit=" assets" />
        <Bars title="Risk Distribution" points={series.risks} unit=" assets" />
        <Bars title="Certificate Expiry Timeline" points={series.expiry} unit=" certificates" description="Days from the assessment snapshot." />
        <Distribution title="IP Version Breakdown" points={series.ipVersions} unit=" addresses" doughnut totalLabel="Addresses" empty="No IP addresses in this scope." />
      </div>
    </section>
  </>
}
