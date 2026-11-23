import React, { useEffect, useState } from 'react'
import { KeyRound, LogIn, LogOut, ShieldCheck, Trash2, UserPlus } from 'lucide-react'
import { api, Badge, Button, DemoLabel, ErrorText, Field, Mark, PageTitle, Panel, Select, Table } from './ui.jsx'

export const roleNames = { admin: 'Administrator', itadmin: 'IT Administrator', auditor: 'Compliance Auditor', viewer: 'Viewer' }

export function SignIn({ config, onSession }) {
  const [mode, setMode] = useState('login')
  const [email, setEmail] = useState('demo@acme-corp.example')
  const [password, setPassword] = useState('requiem-demo')
  const [name, setName] = useState('')
  const [challenge, setChallenge] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event, preview = false) {
    event?.preventDefault()
    setBusy(true)
    setError('')
    try {
      const path = preview ? 'preview' : challenge ? 'verify' : mode
      const data = preview ? {} : challenge ? { challenge, code } : { email, password, name }
      const result = await api('/session/' + path, { method: 'POST', data })
      if (result.requires_totp) setChallenge(result.challenge)
      else onSession(result)
    } catch (error) { setError(error.message) } finally { setBusy(false) }
  }
  return <main className="auth-page">
    <section className="auth-hero"><div className="brand"><Mark /><span><strong>Requiem</strong><small>Security assessment</small></span></div>
      <div><div className="eyebrow">OWASP TOP 10 · 2025</div><h1>Web application security posture</h1><p>Review the Acme assessment and its supporting evidence in a local demo workspace.</p></div>
      <DemoLabel />
    </section>
    <div className="auth-content">
      <Panel title={challenge ? 'Verify demo authenticator' : mode === 'signup' ? 'Create a demo account' : 'Sign in'}
        description={challenge ? 'Use the sample code to complete this demonstration.' : 'Use a sample identity from the demo workspace.'}>
        <form className="form-stack inset" onSubmit={submit}>
          {challenge ? <>
            <Field label="Authenticator code" value={code} onChange={event => setCode(event.target.value)} inputMode="numeric" maxLength={6} required />
            <p className="help">Sample code <code>{config.demoOtp}</code></p>
          </> : <>
            {mode === 'signup' && <Field label="Display name" value={name} onChange={event => setName(event.target.value)} required />}
            <Field label="Demo email" type="email" value={email} onChange={event => setEmail(event.target.value)} required />
            <Field label="Demo password" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} required />
            {mode === 'login' && <p className="help">IT administrator with sample TOTP <code>itadmin@acme-corp.example</code></p>}
          </>}
          <ErrorText>{error}</ErrorText>
          <Button kind="primary" type="submit" icon={challenge ? KeyRound : mode === 'signup' ? UserPlus : LogIn} disabled={busy}>
            {challenge ? 'Verify code' : mode === 'signup' ? 'Create account' : 'Sign in'}
          </Button>
          <button className="text-button" type="button" disabled={busy} onClick={() => {
            setError('')
            if (challenge) { setChallenge(''); return }
            if (mode === 'login') { setMode('signup'); setEmail('') }
            else setMode('login')
          }}>{challenge ? 'Back to sign-in' : mode === 'signup' ? 'Back to sign-in' : 'Create an account'}</button>
          <Button icon={ShieldCheck} onClick={() => submit(null, true)} disabled={busy}>Open presenter session</Button>
        </form>
      </Panel>
    </div>
  </main>
}

export function Settings({ session, config, onAccount, signOut }) {
  const { account, token } = session
  const [name, setName] = useState(account.name)
  const [email, setEmail] = useState(account.email)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [code, setCode] = useState('')
  const [users, setUsers] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (account.role !== 'admin') return
    let cancelled = false
    api('/accounts', { token }).then(rows => { if (!cancelled) setUsers(rows) }).catch(error => { if (!cancelled) setError(error.message) })
    return () => { cancelled = true }
  }, [account.role, token])

  async function action(task, success) {
    setError('')
    setNotice('')
    setBusy(true)
    try { await task(); setNotice(success) } catch (error) { setError(error.message) } finally { setBusy(false) }
  }
  async function update(data) {
    const next = await api('/session', { token, method: 'PATCH', data })
    onAccount(next)
    setUsers(previous => previous.map(user => user.id === next.id ? next : user))
  }
  return <>
    <PageTitle eyebrow="WORKSPACE" title="Settings" subtitle="Manage your demo profile, second factor, and workspace access." />
    <ErrorText>{error}</ErrorText>{notice && <p className="success-text status-card" role="status">{notice}</p>}
    <div className="report-grid settings-grid">
      <Panel title="Profile" action={<Badge tone="warning">{roleNames[account.role]}</Badge>}>
        <form className="form-stack inset" onSubmit={event => { event.preventDefault(); action(() => update({ name, email }), 'Demo profile updated.') }}>
          <Field label="Display name" value={name} onChange={event => setName(event.target.value)} required />
          <Field label="Demo email" type="email" value={email} onChange={event => setEmail(event.target.value)} required />
          <Button kind="primary" type="submit" disabled={busy}>Save profile</Button>
        </form>
      </Panel>
      <Panel title="Demo authenticator" description="Enable or disable the sample TOTP challenge." action={<Badge tone={account.totp ? 'pass' : 'neutral'}>{account.totp ? 'Enabled' : 'Disabled'}</Badge>}>
        <form className="form-stack inset" onSubmit={event => {
          event.preventDefault()
          action(async () => { await update({ totp: !account.totp, code }); setCode('') }, account.totp ? 'Demo authenticator disabled.' : 'Demo authenticator enabled.')
        }}>
          <Field label={'Sample code · ' + config.demoOtp} inputMode="numeric" value={code} onChange={event => setCode(event.target.value)} maxLength={6} required />
          <Button type="submit" icon={KeyRound} disabled={busy}>{account.totp ? 'Disable authenticator' : 'Enable authenticator'}</Button>
        </form>
      </Panel>
      <Panel title="Demo password" description="Use a password created for this local workspace.">
        <form className="form-stack inset" onSubmit={event => {
          event.preventDefault()
          action(async () => { await update({ current_password: currentPassword, new_password: newPassword }); setCurrentPassword(''); setNewPassword('') }, 'Demo password updated.')
        }}>
          <Field label="Current password" type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} required />
          <Field label="New password" type="password" autoComplete="new-password" value={newPassword} onChange={event => setNewPassword(event.target.value)} minLength={8} maxLength={72} required />
          <Button type="submit" disabled={busy}>Change password</Button>
        </form>
      </Panel>
      <Panel title="Sessions" description="Reset all local sessions for this demo account.">
        <div className="inset actions"><Button icon={LogOut} onClick={() => action(() => signOut(true), '')} disabled={busy}>Reset sessions</Button>
          <Button onClick={() => action(() => signOut(false), '')} disabled={busy}>Sign out</Button></div>
      </Panel>
    </div>
    {account.role === 'admin' && <Panel title="User administration" description={users.length + ' local demo accounts'}>
      <Table headings={['Account', 'Email', 'Authenticator', 'Role', 'Actions']}>{users.map(user => {
        const locked = user.id === account.id || user.id === 'presenter'
        return <tr key={user.id}><th scope="row">{user.name}</th><td>{user.email}</td><td>{user.totp ? 'Enabled' : 'Disabled'}</td>
          <td>{locked ? roleNames[user.role] : <Select label={'Role for ' + user.name} value={user.role}
            options={config.roles.map(role => [role, roleNames[role]])} disabled={busy} onChange={event => {
              const role = event.target.value
              action(async () => {
                const next = await api('/accounts/' + user.id, { token, method: 'PATCH', data: { role } })
                setUsers(previous => previous.map(item => item.id === next.id ? next : item))
              }, 'Demo account role updated.')
            }} />}</td>
          <td>{!locked && <button type="button" className="icon-button" aria-label={'Delete ' + user.name} disabled={busy} onClick={() => {
            if (window.confirm('Delete this local demo account?')) action(async () => {
              await api('/accounts/' + user.id, { token, method: 'DELETE' })
              setUsers(previous => previous.filter(item => item.id !== user.id))
            }, 'Demo account deleted.')
          }}><Trash2 size={17} /></button>}</td>
        </tr>
      })}</Table>
    </Panel>}
  </>
}
