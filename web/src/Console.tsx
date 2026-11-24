import { useEffect, useState } from 'react';
import { Activity, BellRing, Blocks, Gauge, KeyRound, Library, ListChecks, LogOut, MailCheck, Radar, Route, ScanSearch, Settings, ShieldCheck, ShieldEllipsis } from 'lucide-react';
import { api } from './api';
import type { Me } from './types';
import DashboardPage from './Dashboard';
import { ListsPage, PathsPage, ScansPage } from './Inventory';
import { AddonsPage, HitsPage } from './Hits';
import { LicensePage, NotificationsPage, SendPage } from './Settings';
import SecurityPage from './Security';
import AdminPage from './Admin';
import { Feedback } from './ui';

const navigation = [
  { id: 'dashboard', label: 'Vue d’ensemble', icon: Gauge },
  { id: 'lists', label: 'Listes', icon: ListChecks },
  { id: 'paths', label: 'Chemins', icon: Route },
  { id: 'scans', label: 'Scans', icon: ScanSearch },
  { id: 'hits', label: 'Expositions', icon: Library },
  { id: 'addons', label: 'Registre', icon: Blocks },
  { id: 'notifications', label: 'Notifications', icon: BellRing },
  { id: 'send', label: 'Envoi contrôle', icon: MailCheck },
  { id: 'license', label: 'Licence', icon: KeyRound },
  { id: 'security', label: 'Sécurité', icon: ShieldCheck },
  { id: 'admin', label: 'Administration', icon: Settings, admin: true },
];

export default function Console({ me, onLogout, onMe }: { me: Me; onLogout: () => void; onMe: (me: Me) => void }) {
  const initial = window.location.hash.slice(1) || 'dashboard';
  const [route, setRoute] = useState(initial); const [message, setMessage] = useState(''); const [kind, setKind] = useState<'error' | 'success'>('success'); const [refreshKey, setRefreshKey] = useState(0);
  useEffect(() => { const change = () => setRoute(window.location.hash.slice(1) || 'dashboard'); window.addEventListener('hashchange', change); return () => window.removeEventListener('hashchange', change); }, []);
  useEffect(() => { document.title = `HYDRA — ${navigation.find((item) => item.id === route)?.label || 'Console'}`; window.scrollTo(0, 0); }, [route]);
  const notify = (text: string, level: 'error' | 'success' = 'success') => { setMessage(text); setKind(level); window.setTimeout(() => setMessage(''), 7000); if (level === 'success') onMeRefresh(); };
  const onMeRefresh = () => { api<Me>('/api/auth/me').then(onMe).catch(() => undefined); };
  const logout = async () => { try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); } finally { onLogout(); } };
  const page = () => {
    switch (route) {
      case 'lists': return <ListsPage notify={notify} onChanged={() => setRefreshKey((value) => value + 1)} />;
      case 'paths': return <PathsPage notify={notify} />;
      case 'scans': return <ScansPage notify={notify} />;
      case 'hits': return <HitsPage />;
      case 'addons': return <AddonsPage />;
      case 'notifications': return <NotificationsPage notify={notify} />;
      case 'send': return <SendPage notify={notify} />;
      case 'license': return <LicensePage />;
      case 'security': return <SecurityPage me={me} notify={notify} onPasswordChanged={onLogout} />;
      case 'admin': return me.user.role === 'admin' ? <AdminPage notify={notify} /> : <Feedback message="Rôle administrateur requis." kind="error" />;
      default: return <DashboardPage refreshKey={refreshKey} />;
    }
  };
  return <div className="console-shell">
    <header className="topbar"><a className="brand" href="#dashboard"><Radar size={23} />HYDRA<span>NX</span></a><div className="live-indicator"><span className="status-dot" />MONITEUR ACTIF</div><div className="operator"><span>{me.user.username}<small>{me.user.role}</small></span><button className="icon-button" onClick={() => void logout()} aria-label="Déconnexion"><LogOut size={18} /></button></div></header>
    <aside className="sidebar"><nav aria-label="Navigation principale">{navigation.filter((item) => !item.admin || me.user.role === 'admin').map((item) => { const Icon = item.icon; return <a key={item.id} href={`#${item.id}`} className={route === item.id ? 'active' : ''}><Icon size={17} /><span>{item.label}</span></a>; })}</nav><div className="sidebar-foot"><a href="/lists" target="_blank" rel="noreferrer">Dépôt public</a><span>corpus 2026.11</span></div></aside>
    <main className="workspace"><Feedback message={message} kind={kind} />{page()}</main>
    <aside className="intel-rail"><div className="rail-title"><Activity size={16} />ÉTAT OPÉRATEUR</div><dl><div><dt>Crédits</dt><dd>{me.credits_remaining === -1 ? '∞' : me.credits_remaining}</dd></div><div><dt>Limite journalière</dt><dd>{me.daily_limit === -1 ? '∞' : me.daily_limit}</dd></div><div><dt>Second facteur</dt><dd>{me.totp_enabled ? 'activé' : 'proposé'}</dd></div><div><dt>Session</dt><dd>signée</dd></div></dl><div className="rail-scope"><ShieldEllipsis size={20} /><h2>Périmètre strict</h2><p>Cibles déclarées uniquement. Preuves rédigées. Pas de validation de credentials.</p></div><div className="rail-log"><span>HTTP/2 standard</span><span>Backoff 429/503</span><span>Limite hôte 2</span><span>SQLite chiffré</span></div></aside>
  </div>;
}
