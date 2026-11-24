import { useState } from 'react';
import { ArrowRight, KeyRound, Radar, ShieldCheck } from 'lucide-react';
import { api, deviceFingerprint } from './api';
import type { Me } from './types';
import { Feedback, Field, formData } from './ui';

export default function Login({ onLogin }: { onLogin: (me: Me) => void }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    const data = formData(event);
    setBusy(true); setError('');
    try {
      await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ identity: data.get('identity'), password: data.get('password'), code: data.get('code'), device_fingerprint: deviceFingerprint() }) });
      onLogin(await api<Me>('/api/auth/me'));
      window.location.hash = 'dashboard';
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Connexion impossible'); } finally { setBusy(false); }
  };
  return <main className="login-shell">
    <section className="login-manifesto">
      <div className="brand-large"><Radar size={34} aria-hidden="true" /> HYDRA</div>
      <div className="login-copy"><div className="eyebrow">SURFACE / CONTRÔLE / REMÉDIATION</div><h1>Voir ce qui est exposé.<br /><span>Sans diffuser les secrets.</span></h1><p>Un poste de contrôle dense pour vos actifs autorisés. Chaque preuve est rédigée avant stockage.</p></div>
      <div className="login-principles"><span><ShieldCheck size={16} /> Périmètre confirmé</span><span><KeyRound size={16} /> Argon2id + TOTP</span></div>
    </section>
    <section className="login-panel">
      <form onSubmit={submit} className="login-form">
        <div className="eyebrow">ACCÈS OPÉRATEUR</div><h2>Connexion</h2><p>Session signée, cookie HttpOnly et appareil enregistré.</p>
        <Feedback message={error} kind="error" />
        <Field label="Email ou utilisateur"><input name="identity" autoComplete="username" required autoFocus placeholder="admin" /></Field>
        <Field label="Mot de passe"><input name="password" type="password" autoComplete="current-password" required /></Field>
        <Field label="Second facteur" hint="Requis seulement si TOTP est activé. Un code de récupération est accepté."><input name="code" inputMode="numeric" autoComplete="one-time-code" placeholder="000000" /></Field>
        <button className="primary full" disabled={busy}>{busy ? 'Vérification…' : 'Ouvrir la console'}<ArrowRight size={17} /></button>
        <div className="login-links"><a href="/">Accueil public</a><a href="/lists">Téléchargements</a><a href="/status">Statut</a></div>
      </form>
    </section>
  </main>;
}
