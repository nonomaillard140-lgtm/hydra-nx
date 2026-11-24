import { useEffect, useState } from 'react';
import { ArrowUpRight, RefreshCw } from 'lucide-react';
import { api } from './api';
import type { Dashboard, Hit } from './types';
import { DataTable, Empty, Feedback, PageTitle, date } from './ui';

export default function DashboardPage({ refreshKey }: { refreshKey: number }) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [hits, setHits] = useState<Hit[]>([]);
  const [error, setError] = useState('');
  const load = async () => {
    setError('');
    try { const [dashboard, library] = await Promise.all([api<Dashboard>('/api/dashboard'), api<Hit[]>('/api/hits')]); setData(dashboard); setHits(library.slice(0, 8)); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Chargement impossible'); }
  };
  useEffect(() => { void load(); }, [refreshKey]);
  const metrics = data?.metrics || {};
  return <section><PageTitle eyebrow="CENTRE DE CONTRÔLE" title="Surface observée" description={data?.scope || 'Chargement du périmètre…'} action={<button className="secondary" onClick={() => void load()}><RefreshCw size={16} />Actualiser</button>} />
    <Feedback message={error} kind="error" />
    <div className="metric-grid">{[['listes', metrics.lists], ['scans', metrics.scans], ['expositions', metrics.hits], ['files actives', metrics.active]].map(([label, value]) => <div className="metric" key={String(label)}><span>{label}</span><strong>{value ?? 0}</strong><small>état courant</small></div>)}</div>
    <div className="split-band"><div><span className="eyebrow">CRÉDITS</span><strong>{data?.credits_remaining === -1 ? 'admin illimité' : `${data?.credits_remaining ?? 0} / ${data?.daily_limit ?? 0}`}</strong></div><div><span className="eyebrow">ORDONNANCEUR</span><strong>{data?.queue_depth ?? 0} en attente</strong></div><a href="#scans">Nouveau scan <ArrowUpRight size={16} /></a></div>
    <div className="section-heading"><h2>Dernières preuves rédigées</h2><a href="#hits">Bibliothèque complète</a></div>
    {hits.length === 0 ? <Empty>Aucune exposition enregistrée. Lancez un scan sur une liste autorisée.</Empty> : <DataTable label="Dernières expositions" headers={['Hôte', 'Exposition', 'Service', 'Preuve', 'Priorité', 'Vu']}>{hits.map((hit) => <tr key={hit.id}><td className="mono">{hit.host}</td><td>{hit.vuln}</td><td><span className="tag">{hit.service}</span></td><td className="mono redacted">{hit.secret_redacted}</td><td>{hit.cash_score}/100</td><td>{date(hit.last_seen)}</td></tr>)}</DataTable>}
  </section>;
}
