import { jsPDF } from 'jspdf'
import { autoTable } from 'jspdf-autotable'
import { cryptoPosture, findingsOf, priorityFindings } from './model.mjs'

export const formats = ['pdf', 'html', 'json', 'csv', 'sarif']
export const templates = ['executive', 'technical', 'on-demand']
const titles = { executive: 'Executive assessment', technical: 'Technical audit', 'on-demand': 'On-demand assessment' }
const demoNote = 'Simulated assessment | Sample data | OWASP Top 10 (2025)'
const display = value => String(value ?? '—').replaceAll('_', ' ')
const reportScope = audit => audit.subdomains.length === 1 ? audit.subdomains[0].subdomain : audit.domain
const referenceNote = audit => audit.target_domain && audit.target_domain !== audit.domain ? 'Reference: ' + audit.target_domain + ' | Fictional scope: ' : ''

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char])
}

function escapeCsv(value) {
  let text = String(value ?? '')
  if (/^[\s]*[=+\-@]|^[\t\r\n]/.test(text)) text = "'" + text
  return '"' + text.replaceAll('"', '""') + '"'
}

function pdf(audit, template) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4', putOnlyUsedFonts: true })
  const { summary } = audit
  const colors = { burgundy: [93, 23, 49], dark: [47, 22, 34], gold: [244, 207, 123] }
  doc.setProperties({ title: 'Requiem · ' + titles[template], subject: demoNote, author: 'Requiem' })
  doc.setFillColor(...colors.dark)
  doc.rect(0, 0, 596, 177, 'F')
  doc.setTextColor(...colors.gold)
  doc.setFont('helvetica', 'bold')
  doc.setFontSize(11)
  doc.text('REQUIEM  /  ASSESSMENT REPORT', 42, 42)
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(28)
  doc.text(titles[template], 42, 80)
  doc.setFontSize(13)
  doc.text(referenceNote(audit) + reportScope(audit), 42, 106, { maxWidth: 505 })
  doc.setFont('helvetica', 'normal')
  doc.setFontSize(10)
  doc.text(demoNote, 42, 131)
  doc.text('Snapshot: ' + audit.created_at.slice(0, 10) + '  |  Reference: ' + audit.authorization_ref, 42, 149, { maxWidth: 505 })
  const tableStyle = {
    margin: { left: 42, right: 42, top: 42, bottom: 43 },
    styles: { fontSize: 9, cellPadding: 6, overflow: 'linebreak' },
    headStyles: { fillColor: colors.burgundy },
    alternateRowStyles: { fillColor: [250, 246, 242] },
  }
  const table = (head, body, startY, columnStyles) =>
    autoTable(doc, { ...tableStyle, startY, head: [head], body, columnStyles })
  const heading = (label, gap = 27) => {
    let y = (doc.lastAutoTable?.finalY ?? 177) + gap
    if (y > 760) {
      doc.addPage()
      y = 49
    }
    doc.setTextColor(...colors.dark)
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(15)
    doc.text(label, 42, y)
    return y + 10
  }
  const counts = summary.severity_counts
  table(['OWASP score', 'Assets', 'Total findings', 'High / critical', 'Cyber rating'],
    [[display(summary.overall_score) + '/100 (' + summary.grade + ')', summary.subdomains_total, summary.total_findings, counts.high + counts.critical, cryptoPosture(audit).rating + '/1000']], 194)
  table(['Category', 'Coverage', 'Result', 'Findings'], summary.categories.map(category =>
    [category.id + '  ' + category.name, display(category.coverage), display(category.status), category.finding_count]), heading('OWASP coverage'))
  table(['Priority finding', 'Host', 'Recommended action'], priorityFindings(audit).slice(0, template === 'technical' ? 6 : 3).map(finding =>
    [finding.title, finding.subdomain, finding.remediation]), heading('Recommended actions'), { 2: { cellWidth: 225 } })
  table(['Host', 'HTTP', 'TLS', 'Certificate issuer', 'Condition'], audit.subdomains.map(host =>
    [host.subdomain, display(host.status_code), host.tls?.protocol ?? 'No HTTPS', display(host.tls?.cert_issuer), host.tls?.trusted ? 'Trusted' : host.tls?.protocol ? 'Review' : 'No HTTPS']), heading('Asset and certificate inventory'))
  const findings = findingsOf(audit)
  table(['Finding', 'Host', 'Severity', 'CVSS', 'OWASP'], findings.map(finding =>
    [finding.title, finding.subdomain, finding.severity, display(finding.cvss_score), finding.owasp.join(', ')]), heading('Findings appendix'))
  if (template === 'technical') {
    table(['Finding', 'Evidence', 'Remediation'], findings.map(finding =>
      [finding.rule_id + ' / ' + finding.subdomain, finding.evidence || '—', finding.remediation || '—']), heading('Technical evidence'), { 0: { cellWidth: 140 } })
  }
  const count = doc.getNumberOfPages()
  for (let page = 1; page <= count; page++) {
    doc.setPage(page)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(9)
    doc.setTextColor(109, 92, 100)
    doc.text('REQUIEM  /  SIMULATED ASSESSMENT', 42, 816)
    doc.text(page + ' / ' + count, 553, 816, { align: 'right' })
  }
  return Buffer.from(doc.output('arraybuffer'))
}

function html(audit, template) {
  const { summary } = audit
  const table = (headers, rows) =>
    '<table><thead><tr>' + headers.map(label => '<th>' + escapeHtml(label) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(row => '<tr>' + row.map(value => '<td>' + escapeHtml(value) + '</td>').join('') + '</tr>').join('') + '</tbody></table>'
  const coverage = table(['Category', 'Coverage', 'Status', 'Findings'], summary.categories.map(category =>
    [category.id + ' ' + category.name, category.coverage, display(category.status), category.finding_count]))
  const inventory = table(['Host', 'HTTP', 'TLS', 'Certificate issuer'], audit.subdomains.map(host =>
    [host.subdomain, host.status_code, host.tls?.protocol ?? 'No HTTPS', host.tls?.cert_issuer]))
  const findings = table(['Finding', 'Host', 'Severity', 'CVSS', 'Evidence', 'Remediation'], findingsOf(audit).map(finding =>
    [finding.title, finding.subdomain, finding.severity, finding.cvss_score, finding.evidence, finding.remediation]))
  return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Requiem assessment</title>' +
    '<style>body{max-width:86rem;margin:3rem auto;padding:0 2rem;background:#f8f5f0;color:#321826;font:16px system-ui}h1,h2{color:#651f38}table{width:100%;border-collapse:collapse;background:white;margin-bottom:2rem}td,th{border:1px solid #e7dbda;padding:.6rem;text-align:left;overflow-wrap:anywhere}th{background:#651f38;color:white}@media print{tr{break-inside:avoid}thead{display:table-header-group}}</style>' +
    '<p>REQUIEM · ' + escapeHtml(demoNote) + '</p><h1>' + escapeHtml(titles[template]) + '</h1><p>' +
    escapeHtml(referenceNote(audit) + reportScope(audit)) + ' · ' +
    escapeHtml(audit.created_at.slice(0, 10)) + '</p><p>OWASP score ' + escapeHtml(summary.overall_score) +
    '/100 · Grade ' + escapeHtml(summary.grade) + ' · ' + summary.subdomains_total + ' assets · ' + summary.total_findings +
    ' findings</p><h2>OWASP coverage</h2>' + coverage + '<h2>Inventory</h2>' + inventory +
    '<h2>Findings and recommendations</h2>' + findings + '</html>'
}

function csv(audit) {
  return [
    ['simulated', 'audit_id', 'host', 'rule_id', 'title', 'severity', 'cvss', 'owasp', 'sources', 'evidence', 'remediation', 'profile_reference'],
    ...findingsOf(audit).map(finding => [
      true, audit.id, finding.subdomain, finding.rule_id, finding.title, finding.severity, finding.cvss_score,
      finding.owasp.join(' | '), finding.sources.join(' | '), finding.evidence, finding.remediation, audit.target_domain,
    ]),
  ].map(row => row.map(escapeCsv).join(',')).join('\r\n') + '\r\n'
}

function sarif(audit) {
  const findings = findingsOf(audit)
  const rules = new Map(findings.map(finding => [finding.rule_id, {
    id: finding.rule_id, shortDescription: { text: finding.title },
    help: { text: finding.remediation || 'See the assessment record.' },
  }]))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Requiem', version: '1.0.0', rules: [...rules.values()] } },
      properties: { simulated: true, profileReference: audit.target_domain, auditId: audit.id, score: audit.summary.overall_score, assetCount: audit.summary.subdomains_total },
      results: findings.map(finding => ({
        ruleId: finding.rule_id,
        level: ['critical', 'high'].includes(finding.severity) ? 'error' : finding.severity === 'info' ? 'note' : 'warning',
        message: { text: finding.title },
        locations: [{ physicalLocation: { artifactLocation: { uri: finding.url || 'https://' + finding.subdomain + '/' } } }],
        properties: { simulated: true, owasp: finding.owasp, evidence: finding.evidence, sources: finding.sources },
      })),
    }],
  }
}

export function renderReport(audit, format, template = 'executive') {
  const scope = reportScope(audit)
  const filename = 'requiem-' + scope + '-' + template + '.' + (format === 'sarif' ? 'sarif.json' : format)
  const encoders = {
    pdf: ['application/pdf', () => pdf(audit, template)],
    html: ['text/html; charset=utf-8', () => html(audit, template)],
    json: ['application/json; charset=utf-8', () => JSON.stringify(audit, null, 2)],
    csv: ['text/csv; charset=utf-8', () => csv(audit)],
    sarif: ['application/sarif+json; charset=utf-8', () => JSON.stringify(sarif(audit), null, 2)],
  }
  const [type, encode] = encoders[format]
  return { filename, type, content: encode() }
}
