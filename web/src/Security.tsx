import { useState } from 'react';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { api } from './api';
import type { Me } from './types';
import { Feedback, Field, PageTitle, formData, submitForm } from './ui';

type Notify = (message: string, kind?: 'error' | 'success') => void;

export default function SecurityPage({ me, notify, onPasswordChanged }: { me: Me; notify: Notify; onPasswordChanged: () => void }) {
  const [busy, setBusy] = useState(false); const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null); const [recovery, setRecovery] = useState<string[]>([]); const [error, setError] = useState('');
  const begin = async () => { setBusy(true); setError(''); try { setSetup(await api('/api/auth/totp/setup', { method: 'POST', body: '{}' })); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Configuration impossible'); } finally { setBusy(false); } };
  const enable = async (event: React.FormEvent<HTMLFormElement>) => { const data = formData(event); setBusy(true); try { const result = await api<{ recovery_codes: string[] }>('/api/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code: data.get('code') }) }); setRecovery(result.recovery_codes); setSetup(null); notify('TOTP activé', 'success'); } catch (reason) { notify(reason instanceof Error ? reason.message : 'Activation impossible', 'error'); } finally { setBusy(false); } };
  const disable = async (event: React.FormEvent<HTMLFormElement>) => { const data = formData(event); await submitForm(() => api('/api/auth/totp/disable', { method: 'POST', body: JSON.stringify({ code: data.get('disable_code') }) }), setBusy, notify, 'TOTP désactivé'); };
  const password = async (event: React.FormEvent<HTMLFormElement>) => { const data = formData(event); await submitForm(() => api('/api/auth/password', { method: 'POST', body: JSON.stringify({ current: data.get('current'), next: data.get('next') }) }), setBusy, notify, 'Mot de passe modifié'); onPasswordChanged(); };
  return <section><PageTitle eyebrow="COMPTE" title="Sécurité de l’accès" description="Argon2id pour le mot de passe, TOTP RFC 6238 et huit codes de récupération à usage unique." /><Feedback message={error} kind="error" />
    <div className="two-columns"><div className="work-form"><h2><ShieldCheck size={18} />Second facteur</h2>{me.totp_enabled ? <form onSubmit={disable}><p>TOTP est activé pour ce compte.</p><Field label="Code TOTP courant"><input name="disable_code" inputMode="numeric" required pattern="[0-9]{6}" /></Field><button className="secondary" disabled={busy}>Désactiver TOTP</button></form> : <><p>TOTP n’est pas encore activé.</p><button className="secondary" onClick={() => void begin()} disabled={busy}><ShieldCheck size={16} />Préparer TOTP</button>{setup && <form onSubmit={enable} className="stack"><Field label="Secret à saisir dans l’application"><input className="mono" readOnly value={setup.secret} onFocus={(e) => e.target.select()} /></Field><Field label="URI otpauth"><textarea className="mono" readOnly value={setup.uri} rows={3} /></Field><Field label="Code à 6 chiffres"><input name="code" inputMode="numeric" pattern="[0-9]{6}" required /></Field><button className="primary" disabled={busy}>Activer</button></form>}</>}{recovery.length > 0 && <div className="recovery"><h3>Codes de récupération, affichés une fois</h3>{recovery.map((code) => <code key={code}>{code}</code>)}</div>}</div>
      <form className="work-form" onSubmit={password}><h2><KeyRound size={18} />Mot de passe</h2><Field label="Mot de passe actuel"><input name="current" type="password" autoComplete="current-password" required /></Field><Field label="Nouveau mot de passe" hint="12 caractères minimum. Toutes les sessions sont révoquées."><input name="next" type="password" autoComplete="new-password" minLength={12} required /></Field><button className="primary" disabled={busy}>Modifier</button></form>
    </div>
  </section>;
}
