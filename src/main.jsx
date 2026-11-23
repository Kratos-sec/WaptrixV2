import React, { useCallback, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, BookOpen, ChevronRight, ClipboardList, FileText, FlaskConical, Globe2, LayoutDashboard,
  Menu, Network, Radar, Settings as SettingsIcon, ShieldAlert, ShieldCheck, Square, X,
} from 'lucide-react'
import Overview from './Overview.jsx'
import { Assets, AssetDetail, Findings, FindingDetail, Rules } from './Assessment.jsx'
import { Benchmark, Posture, Reports, ScanForm, WorkflowPage } from './Operations.jsx'
import { roleNames, Settings, SignIn } from './Accounts.jsx'
import { api, Button, DemoLabel, ErrorText, Mark, Select, stageNames } from './ui.jsx'
import './style.css'

const navigation = [
  ['Assessment', [
    ['overview', 'OWASP Top 10', LayoutDashboard],
    ['assets', 'Asset inventory', Network],
    ['findings', 'Findings', ShieldAlert],
    ['workflow', 'Audit workflow', Activity],
  ]],
  ['Security posture', [
    ['posture', 'PQC Dashboard', ShieldCheck],
    ['reports', 'Reports', FileText],
  ]],
  ['Workspace', [
    ['rules', 'Rule catalog', BookOpen],
    ['benchmark', 'Benchmark lab', FlaskConical],
    ['settings', 'Settings', SettingsIcon],
  ]],
]
const labels = Object.fromEntries(navigation.flatMap(([, links]) => links.map(([route, label]) => [route, label])))
const auditPath = id => '/audits/' + encodeURIComponent(id)
const sessionKey = 'requiem-demo-session'
const profileKey = 'requiem-demo-profile'

function readRoute() {
  const [raw = '', query = ''] = window.location.hash.slice(1).split('?')
  return { page: Object.hasOwn(labels, raw) ? raw : 'overview', query: Object.fromEntries(new URLSearchParams(query)), key: raw + '?' + query }
}

function isVisible(role, page) {
  if (page === 'reports') return ['admin', 'auditor'].includes(role)
  return true
}

function App() {
  const [route, setRoute] = useState(readRoute)
  const [configuration, setConfiguration] = useState(null)
  const [audit, setAudit] = useState(null)
  const [history, setHistory] = useState([])
  const [run, setRun] = useState(null)
  const [session, setSession] = useState(null)
  const [ready, setReady] = useState(false)
  const [error, setError] = useState('')
  const [toast, setToast] = useState('')
  const [scanOpen, setScanOpen] = useState(false)
  const [drawer, setDrawer] = useState(null)
  const [menu, setMenu] = useState(false)
  const [posture, setPosture] = useState(null)
  const [switching, setSwitching] = useState(false)
  const role = session?.account.role
  const canEdit = ['admin', 'itadmin'].includes(role)
  const canDeliver = ['admin', 'auditor'].includes(role)
  const page = isVisible(role, route.page) ? route.page : 'overview'

  const navigate = useCallback((name, filters = {}) => {
    const query = new URLSearchParams(Object.entries(filters).filter(([, value]) => value)).toString()
    window.location.hash = name + (query ? '?' + query : '')
    setMenu(false)
  }, [])
  useEffect(() => {
    function change() { setRoute(readRoute()); setDrawer(null); setMenu(false) }
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  useEffect(() => { window.scrollTo(0, 0) }, [page])
  const acceptSession = useCallback(result => {
    sessionStorage.setItem(sessionKey, result.token)
    setSession(result)
  }, [])
  useEffect(() => {
    let cancelled = false
    async function setup() {
      try {
        const [config, tools, catalog, lab, threats, history] = await Promise.all([
          api('/demo'), api('/tools'), api('/rules'), api('/benchmark'), api('/lookalikes'), api('/audits'),
        ])
        const profiles = config.profiles ?? [{ id: 'acme', name: 'Acme Corp', target: config.domain, domain: config.domain, hostnames: config.hostnames, auditId: config.demoId }]
        const requested = readRoute().query.profile ?? sessionStorage.getItem(profileKey)
        const selected = profiles.find(profile => profile.id === requested) ?? profiles[0]
        const current = history.find(record => record.status === 'running')
        const [assessment, replay] = await Promise.all([api(auditPath(selected.auditId)), current ? api(auditPath(current.id)) : null])
        if (cancelled) return
        setConfiguration({ config: { ...config, profiles }, tools, catalog, lab, threats })
        setAudit(assessment)
        setHistory(history)
        setRun(replay)
        const token = sessionStorage.getItem(sessionKey)
        if (token === '-') return
        let result
        if (token) {
          try { result = { token, account: await api('/session', { token }) } } catch { sessionStorage.removeItem(sessionKey) }
        }
        if (!result) result = await api('/session/preview', { method: 'POST', data: {} })
        if (!cancelled) acceptSession(result)
      } catch (error) {
        if (!cancelled) setError(error.message)
      } finally {
        if (!cancelled) setReady(true)
      }
    }
    setup()
    return () => { cancelled = true }
  }, [acceptSession])

  const refreshHistory = useCallback(async () => {
    const rows = await api('/audits')
    setHistory(rows)
    return rows
  }, [])
  const refreshAudit = useCallback(async id => {
    const record = await api(auditPath(id))
    setAudit(record)
    return record
  }, [])
  const runId = run?.id
  useEffect(() => {
    if (!runId) return
    let cancelled = false
    let waiting = false
    const timer = setInterval(async () => {
      if (waiting) return
      waiting = true
      try {
        const record = await api(auditPath(runId))
        if (cancelled) return
        if (record.status === 'running') setRun(record)
        else {
          setRun(null)
          if (record.status === 'completed') {
            setAudit(record)
            setToast('Assessment replay completed.')
          }
          await refreshHistory()
        }
      } catch (error) {
        if (!cancelled) setError(error.message)
      } finally { waiting = false }
    }, 400)
    return () => { cancelled = true; clearInterval(timer) }
  }, [runId, refreshHistory])
  const hasNuclei = audit?.nuclei.some(item => item.status === 'running')
  const auditId = audit?.id
  const profileId = audit?.profile_id
  useEffect(() => {
    if (profileId) sessionStorage.setItem(profileKey, profileId)
  }, [profileId])
  useEffect(() => {
    if (!hasNuclei) return
    let cancelled = false
    const timer = setInterval(() => {
      api(auditPath(auditId)).then(record => { if (!cancelled) setAudit(record) }).catch(error => { if (!cancelled) setError(error.message) })
    }, 500)
    return () => { cancelled = true; clearInterval(timer) }
  }, [auditId, hasNuclei])
  useEffect(() => {
    if (page !== 'posture' || !auditId) return
    let cancelled = false
    api(auditPath(auditId) + '/posture').then(value => { if (!cancelled) setPosture({ id: auditId, value }) })
      .catch(error => { if (!cancelled) setError(error.message) })
    return () => { cancelled = true }
  }, [page, auditId])
  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(() => setToast(''), 5000)
    return () => clearTimeout(timer)
  }, [toast])
  const requestedHost = route.query.host
  useEffect(() => {
    if (page !== 'assets' || !requestedHost || !audit) return
    const host = audit.subdomains.find(value => value.subdomain === requestedHost)
    if (host) setDrawer({ host })
  }, [page, requestedHost, audit])

  async function start(data) {
    const record = await api('/audits', { method: 'POST', data })
    const active = await api(auditPath(record.id))
    setRun(active)
    setScanOpen(false)
    await refreshHistory()
    setToast('Assessment replay started.')
  }
  async function stop() {
    await api(auditPath(run.id) + '/stop', { method: 'POST', data: {} })
    setRun(null)
    if (audit.id === run.id) await refreshAudit(configuration.config.demoId)
    await refreshHistory()
    setToast('Replay stopped. Results remain in run history.')
  }
  async function removeAudit(id) {
    await api(auditPath(id), { method: 'DELETE' })
    if (audit.id === id) await refreshAudit(configuration.config.demoId)
    await refreshHistory()
    setToast('Demo audit removed from history.')
  }
  async function openProfile(id) {
    const profile = configuration.config.profiles.find(item => item.id === id)
    setError('')
    setSwitching(true)
    try {
      await refreshAudit(profile.auditId)
      setDrawer(null)
      navigate('overview')
    } catch (error) { setError(error.message) } finally { setSwitching(false) }
  }
  async function signOut(all) {
    await api('/session/' + (all ? 'reset' : 'logout'), { method: 'POST', token: session.token, data: {} })
    sessionStorage.setItem(sessionKey, '-')
    setSession(null)
    navigate('overview')
  }

  if (!ready || !configuration || !audit) return <main className="loading-screen">
    <Mark /><h1>Requiem</h1><p>{ready ? 'The assessment workspace could not open.' : 'Opening the assessment workspace…'}</p>
    <ErrorText>{error}</ErrorText>{ready && <Button onClick={() => window.location.reload()}>Retry</Button>}
  </main>
  if (!session) return <SignIn config={configuration.config} onSession={acceptSession} />

  const inspectHost = host => setDrawer({ host })
  const inspectFinding = finding => setDrawer({ finding })
  const dismissDrawer = () => {
    setDrawer(null)
    if (page === 'assets' && requestedHost) navigate('assets')
  }
  const openScan = () => setScanOpen(true)
  const account = session.account
  const profiles = configuration.config.profiles
  const profile = profiles.find(item => item.id === profileId) ?? profiles[0]
  return <div className="shell">
    <a href="#workspace" className="skip" onClick={event => { event.preventDefault(); document.getElementById('workspace').focus() }}>Skip to workspace</a>
    {menu && <button className="menu-backdrop" type="button" aria-label="Close navigation" onClick={() => setMenu(false)} />}
    <aside className={'sidebar' + (menu ? ' open' : '')}>
      <a href="#overview" className="brand" aria-label="Requiem overview"><Mark /><span><strong>Requiem</strong><small>Security assessment</small></span></a>
      <nav aria-label="Workspace navigation">
        {navigation.map(([section, links]) => <section className="nav-group" key={section}>
          <div>{section}</div>
          {links.filter(([name]) => isVisible(role, name)).map(([name, label, Icon]) =>
            <a key={name} href={'#' + name} onClick={() => setMenu(false)} aria-current={page === name ? 'page' : undefined}><Icon size={18} />{label}</a>)}
        </section>)}
      </nav>
      <div className="sidebar-footer"><span className="sidebar-footer-icon"><Globe2 size={18} /></span>
        <span><strong>{profile.name}</strong><small>Sample workspace</small></span></div>
    </aside>
    <div className="shell-main">
      <header className="topbar">
        <div className="breadcrumbs"><button type="button" className="icon-button menu-toggle" aria-label="Open navigation" aria-expanded={menu} onClick={() => setMenu(value => !value)}><Menu size={23} /></button>
          <span>Workspace</span><ChevronRight size={15} aria-hidden="true" /><strong>{labels[page]}</strong></div>
        <div className="topbar-actions"><DemoLabel />
          <button type="button" className="profile" onClick={() => navigate('settings')} aria-label={'Settings for ' + account.name}>
            <span className="avatar">{account.name.split(/\s+/).slice(0, 2).map(word => word.charAt(0).toUpperCase()).join('')}</span>
            <span><strong>{account.name}</strong><small>{roleNames[role]}</small></span>
          </button></div>
      </header>
      <main id="workspace" className="workspace" tabIndex={-1}>
        <ErrorText>{error}</ErrorText>
        <div className="profile-strip">
          <Select label="Demo profile" value={profile.id} disabled={switching || Boolean(run)}
            options={profiles.map(item => [item.id, item.name + ' · ' + item.target])} onChange={event => openProfile(event.target.value)} />
          <div><strong>{profile.target === profile.domain ? 'Bundled Acme sample' : 'Synthetic scenario for ' + profile.target}</strong>
            <small>Fictional hosts, findings, and posture data</small></div>
          {audit.id !== profile.auditId && <Button disabled={switching || Boolean(run)} onClick={() => openProfile(profile.id)}>Open full sample</Button>}
        </div>
        {run && <div className="run-banner" role="status"><Radar size={21} className="running-icon" /><div>
          <strong>Replay in progress</strong><small>{stageNames[run.step]} · Stage {run.step + 1} of {stageNames.length}</small></div>
          <Button icon={ClipboardList} onClick={() => navigate('workflow')}>View workflow</Button>
          <Button icon={Square} disabled={!canEdit} onClick={() => stop().catch(error => setError(error.message))}>Stop</Button>
        </div>}
        {page === 'overview' && <Overview key={audit.id} audit={audit} start={openScan} running={Boolean(run)} canEdit={canEdit} canReport={canDeliver} navigate={navigate} />}
        {page === 'assets' && <Assets key={audit.id} audit={audit} inspect={inspectHost} navigate={navigate} />}
        {page === 'findings' && <Findings key={route.key + audit.id} audit={audit} initial={route.query}
          inspect={inspectFinding} lookalikes={configuration.threats.results} refresh={refreshAudit} canEdit={canEdit} />}
        {page === 'workflow' && <WorkflowPage audit={audit} run={run} history={history} selectAudit={refreshAudit} stop={stop}
          removeAudit={removeAudit} onStart={openScan} canEdit={canEdit} />}
        {page === 'posture' && <Posture audit={audit} data={posture?.id === audit.id ? posture.value : null} inspectHost={inspectHost} inspectFinding={inspectFinding} />}
        {page === 'reports' && <Reports key={audit.id} audit={audit} canEdit={canDeliver} initialHost={route.query.host} />}
        {page === 'rules' && <Rules catalog={configuration.catalog} />}
        {page === 'benchmark' && <Benchmark results={configuration.lab.results} />}
        {page === 'settings' && <Settings key={account.id} session={session} config={configuration.config} signOut={signOut}
          onAccount={next => setSession(previous => ({ ...previous, account: next }))} />}
      </main>
    </div>
    {scanOpen && <ScanForm config={configuration.config} activeProfile={profile} tools={configuration.tools} onClose={() => setScanOpen(false)} onSubmit={start} />}
    {drawer?.host && <AssetDetail key={drawer.host.subdomain} host={drawer.host} audit={audit} onClose={dismissDrawer} canReport={canDeliver}
      selectAudit={async id => { await refreshAudit(id); dismissDrawer(); navigate('workflow') }}
      showFindings={() => navigate('findings', { host: drawer.host.subdomain })} />}
    {drawer?.finding && <FindingDetail finding={drawer.finding} onClose={dismissDrawer} />}
    {toast && <div className="toast" role="status"><ShieldCheck size={19} />{toast}<button className="icon-button" type="button" aria-label="Dismiss notification" onClick={() => setToast('')}><X size={16} /></button></div>}
  </div>
}

createRoot(document.getElementById('root')).render(<App />)
