import { useEffect, useState } from 'react';
import { Download, Search, ShieldCheck } from 'lucide-react';
import { api } from './api';
import type { Hit } from './types';
import { DataTable, Empty, Field, PageTitle, date } from './ui';

type Addon = { name: string; category: string; description: string };

export function HitsPage() {
  const [hits, setHits] = useState<Hit[]>([]); const [query, setQuery] = useState(''); const [service, setService] = useState(''); const [status, setStatus] = useState(''); const [error, setError] = useState('');
  const load = async (filters = '') => { try { setHits(await api<Hit[]>(`/api/hits${filters}`)); setError(''); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Chargement impossible'); } };
  useEffect(() => { void load(); }, []);
  const submit = (event: React.FormEvent<HTMLFormElement>) => { event.preventDefault(); const params = new URLSearchParams(); if (query) params.set('q', query); if (service) params.set('service', service); if (status) params.set('status', status); void load(`?${params}`); };
  return <section><PageTitle eyebrow="BIBLIOTHÈQUE" title="Expositions rédigées" description="Déduplication par empreinte HMAC et service. Le score est une priorité de remédiation, pas une valeur financière." action={<a className="secondary button-link" href="/api/hits/export.csv"><Download size={16} />Exporter CSV</a>} />
    <form className="filter-bar" onSubmit={submit}><Field label="Recherche"><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="hôte, chemin, vulnérabilité" /></Field><Field label="Service"><input value={service} onChange={(e) => setService(e.target.value)} placeholder="smtp, aws…" /></Field><Field label="Statut"><select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Tous</option><option value="detected_unvalidated">detected_unvalidated</option></select></Field><button className="primary"><Search size={16} />Filtrer</button></form>
    {error && <div className="feedback error">{error}</div>}{hits.length === 0 ? <Empty>Aucune preuve ne correspond aux filtres.</Empty> : <DataTable label="Bibliothèque de preuves" headers={['Hôte', 'Chemin', 'Vulnérabilité', 'Service', 'Preuve rédigée', 'Statut', 'Points', 'Priorité', 'Dernier passage']}>{hits.map((hit) => <tr key={hit.id}><td className="mono">{hit.host}</td><td className="mono">{hit.path}</td><td>{hit.vuln}</td><td><span className="tag">{hit.service}</span></td><td className="mono redacted">{hit.secret_redacted}</td><td>{hit.status}</td><td>{hit.points}</td><td>{hit.cash_score}/100</td><td>{date(hit.last_seen)}</td></tr>)}</DataTable>}
  </section>;
}

export function AddonsPage() {
  const [addons, setAddons] = useState<Addon[]>([]); const [validation, setValidation] = useState('');
  useEffect(() => { api<{ addons: Addon[]; validation: string }>('/api/addons').then((data) => { setAddons(data.addons); setValidation(data.validation); }).catch(() => setAddons([])); }, []);
  return <section><PageTitle eyebrow="ANALYSE LOCALE" title="Registre des services" description={validation || 'Classification et recommandations de remédiation.'} />
    <div className="scope-note"><ShieldCheck size={20} /><span>Aucun addon n’utilise un secret découvert pour se connecter à un compte tiers. La rotation reste une action manuelle du propriétaire.</span></div>
    <div className="addon-list">{addons.map((addon) => <article key={addon.name}><div><span className="tag">{addon.category}</span><h2>{addon.name}</h2></div><p>{addon.description}</p><span className="state detected">preuve locale</span></article>)}</div>
  </section>;
}
