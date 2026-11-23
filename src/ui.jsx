import React, { useEffect, useRef, useState } from 'react'
import { ArrowDownToLine, CircleAlert, CircleCheck, CircleMinus, CircleX, Clock, FlaskConical, ShieldCheck, X } from 'lucide-react'

export const stageNames = [
  'Scope & authorization', 'Discovery & TLS', 'Application map', 'Vulnerability assessment', 'Correlation', 'Risk & reporting',
]
export const categoryCode = value => value.split(':')[0]
export const word = value => String(value ?? '—').replaceAll('_', ' ').replace(/^./, character => character.toUpperCase())
export const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
export const allFindings = audit => audit.subdomains.flatMap(host => host.findings)
export const byPriority = (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0)
export const hostLabel = (host, domain) => host.endsWith('.' + domain) ? host.slice(0, -(domain.length + 1)) : host
export const percent = value => new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 }).format(value)
export const date = value => value ? new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(new Date(value)) : '—'
export const dateTime = value => value ? new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(value)) : '—'
export const stageStatus = value => ({ started: 'In progress', completed: 'Completed', skipped: 'Skipped', pending: 'Pending', failed: 'Failed' })[value] ?? word(value)

export async function api(path, options = {}) {
  const { data, token, ...init } = options
  const headers = {}
  if (data !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = 'Bearer ' + token
  const response = await fetch('/api' + path, { ...init, headers, body: data === undefined ? undefined : JSON.stringify(data) })
  if (!response.ok) throw new Error((await response.json()).error)
  return response.status === 204 ? null : response.json()
}

export function exportUrl(id, format = 'pdf', { host, template = 'executive' } = {}) {
  const parameters = new URLSearchParams({ format, template })
  if (host) parameters.set('host', host)
  return '/api/audits/' + encodeURIComponent(id) + '/export?' + parameters
}

export function Button({ children, icon: Icon, kind = 'secondary', className = '', type = 'button', ...props }) {
  return <button type={type} className={'button ' + kind + ' ' + className} {...props}>{Icon && <Icon size={17} aria-hidden="true" />}{children}</button>
}

export function ExportLink({ audit, format = 'pdf', host, template, children = 'Download PDF', kind = 'secondary' }) {
  if (audit.status !== 'completed') return <Button icon={ArrowDownToLine} kind={kind} disabled>{children}</Button>
  return <a className={'button ' + kind} href={exportUrl(audit.id, format, { host, template })} download>
    <ArrowDownToLine size={17} aria-hidden="true" />{children}
  </a>
}

export function PageTitle({ eyebrow, title, subtitle, actions }) {
  return <header className="page-title">
    <div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1>{subtitle && <p>{subtitle}</p>}</div>
    {actions && <div className="actions page-actions">{actions}</div>}
  </header>
}

export function Panel({ title, description, action, children, className = '' }) {
  return <section className={'panel ' + className}>
    {title && <header className="panel-head"><div><h2>{title}</h2>{description && <p>{description}</p>}</div>{action}</header>}
    {children}
  </section>
}

export function Badge({ children, tone = 'neutral' }) {
  return <span className={'badge ' + tone}>{children}</span>
}

export const statuses = {
  pass: { label: 'Pass', short: 'Pass', icon: CircleCheck },
  warning: { label: 'Warning', short: 'Warn', icon: CircleAlert },
  fail: { label: 'Fail', short: 'Fail', icon: CircleX },
  manual_review: { label: 'Manual review', short: 'Review', icon: CircleMinus },
}

export function Status({ status, short = false }) {
  const { label, short: compact, icon: Icon } = statuses[status] ?? statuses.manual_review
  return <span className={'cell-status ' + status}><Icon size={13} aria-hidden="true" />{short ? compact : label}</span>
}

export function DemoLabel() {
  return <span className="demo-label"><FlaskConical size={15} aria-hidden="true" /> Demo mode</span>
}

export function Mark({ className = '' }) {
  return <span className={'mark ' + className}><ShieldCheck size={24} strokeWidth={1.75} aria-hidden="true" /></span>
}

export function Empty({ children = 'No matching records.' }) {
  return <div className="empty"><CircleMinus size={22} aria-hidden="true" /><p>{children}</p></div>
}

export function usePages(items, size) {
  const [requested, goTo] = useState(0)
  const pages = Math.max(1, Math.ceil(items.length / size))
  const page = Math.min(requested, pages - 1)
  const start = page * size
  return { page, pages, goTo, start, end: Math.min(start + size, items.length), total: items.length, visible: items.slice(start, start + size) }
}

export function Pager({ pagination, label = 'Rows' }) {
  const { page, pages, goTo, start, end, total } = pagination
  if (pages < 2) return null
  return <nav className="table-pager" aria-label={label + ' pagination'}>
    <span aria-live="polite">{label} {start + 1}–{end} of {total}</span>
    <Button onClick={() => goTo(page - 1)} disabled={page === 0} aria-label={'Previous ' + label.toLowerCase()}>Previous</Button>
    <Button onClick={() => goTo(page + 1)} disabled={page + 1 === pages} aria-label={'Next ' + label.toLowerCase()}>Next</Button>
  </nav>
}

export function ErrorText({ children }) {
  return children ? <p className="error-text" role="alert"><CircleAlert size={16} aria-hidden="true" />{children}</p> : null
}

export function Select({ label, options, ...props }) {
  return <label className="field"><span>{label}</span><select {...props}>{options.map(option => {
    const [value, title] = Array.isArray(option) ? option : [option, option]
    return <option key={value} value={value}>{title}</option>
  })}</select></label>
}

export function Field({ label, ...props }) {
  return <label className="field"><span>{label}</span><input {...props} /></label>
}

export function Table({ headings, children, className = '' }) {
  return <div className={'scroll-table ' + className}><table><thead><tr>{headings.map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>{children}</tbody></table></div>
}

export function Definitions({ entries }) {
  return <dl className="definitions">{entries.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? '—'}</dd></div>)}</dl>
}

export function Dialog({ title, subtitle, children, onClose, wide = false }) {
  const ref = useRef(null)
  useEffect(() => {
    const dialog = ref.current
    if (!dialog.open) dialog.showModal()
    return () => { if (dialog.open) dialog.close() }
  }, [])
  return <dialog ref={ref} className={'dialog ' + (wide ? 'wide' : '')} aria-label={title} onCancel={event => { event.preventDefault(); onClose() }}>
    <header className="dialog-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>
      <button type="button" className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={20} /></button>
    </header>
    <div className="dialog-body">{children}</div>
  </dialog>
}

export function Timeline({ stages }) {
  return <ol className="timeline">{stages.map((stage, index) => <li key={stage.stage} className={stage.status}>
    <span className="timeline-icon">{stage.status === 'completed' ? <CircleCheck size={18} /> : <Clock size={18} />}</span>
    <strong>{stageNames[index]}</strong><span>{stageStatus(stage.status)}</span>
  </li>)}</ol>
}
