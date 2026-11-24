import { useEffect, useState } from 'react';
import { Play, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from './api';
import type { AssetList, Crack, PathItem } from './types';
import { DataTable, Empty, Feedback, Field, PageTitle, date, formData, submitForm } from './ui';

type Notify = (message: string, kind?: 'error' | 'success') => void;

export function ListsPage({ notify, onChanged }: { notify: Notify; onChanged: () => void }) {
  const [items, setItems] = useState<AssetList[]>([]); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const load = async () => { try { setItems(await api<AssetList[]>('/api/lists')); setError(''); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Chargement impossible'); } };
  useEffect(() => { void load(); }, []);
  const create = async (event: React.FormEvent<HTMLFormElement>) => {
    const data = formData(event); const form = event.currentTarget;
    await submitForm(() => api('/api/lists', { method: 'POST', body: JSON.stringify({ name: data.get('name'), kind: data.get('kind'), items: String(data.get('items')).split(/\r?\n/), authorized: data.get('authorized') === 'on' }) }), setBusy, notify, 'Liste autorisée créée');
    form.reset(); await load(); onChanged();
  };
  const remove = async (id: number) => { if (!confirm('Supprimer cette liste et ses éléments ?')) return; await submitForm(() => api(`/api/lists/${id}`, { method: 'DELETE' }), setBusy, notify, 'Liste supprimée'); await load(); onChanged(); };
  return <section><PageTitle eyebrow="INVENTAIRE" title="Listes de cibles" description="Domaines L7 ou adresses L4. Chaque liste emporte une confirmation d’autorisation obligatoire." />
    <Feedback message={error} kind="error" /><form className="work-form" onSubmit={create}><div className="form-grid two"><Field label="Nom"><input name="name" required maxLength={100} placeholder="production-web" /></Field><Field label="Type"><select name="kind" defaultValue="L7"><option value="L7">L7 — domaines</option><option value="L4">L4 — adresses IP</option></select></Field></div><Field label="Cibles, une par ligne" hint="Les schémas URL sont normalisés. Les wildcards et plages sont refusés."><textarea name="items" required rows={6} className="mono" placeholder={'app.example.com\nwww.example.com'} /></Field><label className="check"><input type="checkbox" name="authorized" required /><span>Je confirme posséder ces actifs ou détenir une autorisation écrite de test.</span></label><button className="primary" disabled={busy}><Plus size={16} />Créer la liste</button></form>
    {items.length === 0 ? <Empty>Aucune liste. Importez un périmètre explicitement autorisé.</Empty> : <DataTable label="Listes de cibles" headers={['Nom', 'Type', 'Volume', 'Autorisation', 'Création', 'Action']}>{items.map((item) => <tr key={item.id}><td>{item.name}</td><td><span className="tag">{item.kind}</span></td><td>{item.size}</td><td><span className="status-dot" />confirmée</td><td>{date(item.created_at)}</td><td><button className="icon-button danger" onClick={() => void remove(item.id)} aria-label={`Supprimer ${item.name}`}><Trash2 size={16} /></button></td></tr>)}</DataTable>}
  </section>;
}

export function PathsPage({ notify }: { notify: Notify }) {
  const [items, setItems] = useState<PathItem[]>([]); const [busy, setBusy] = useState(false);
  const load = async () => { try { setItems(await api<PathItem[]>('/api/paths')); } catch (reason) { notify(reason instanceof Error ? reason.message : 'Chargement impossible', 'error'); } };
  useEffect(() => { void load(); }, []);
  const create = async (event: React.FormEvent<HTMLFormElement>) => { const data = formData(event); const form = event.currentTarget; await submitForm(() => api('/api/paths', { method: 'POST', body: JSON.stringify({ raw: data.get('raw'), tags: data.get('tags') }) }), setBusy, notify, 'Chemin ajouté'); form.reset(); await load(); };
  const remove = async (id: number) => { await submitForm(() => api(`/api/paths/${id}`, { method: 'DELETE' }), setBusy, notify, 'Chemin supprimé'); await load(); };
  return <section><PageTitle eyebrow="CORPUS VERSIONNÉ" title="Chemins et variantes" description="Formes canoniques et échappement URL standard. Aucun padding, null byte ou contournement de WAF." />
    <form className="inline-form" onSubmit={create}><Field label="Chemin absolu"><input name="raw" required pattern="/.*" placeholder="/.well-known/config.json" /></Field><Field label="Étiquettes"><input name="tags" placeholder="configuration,revue" /></Field><button className="primary" disabled={busy}><Plus size={16} />Ajouter</button></form>
    {items.length === 0 ? <Empty>Aucun chemin dans le corpus.</Empty> : <DataTable label="Corpus de chemins" headers={['Chemin', 'Variantes', 'Étiquettes', 'Action']}>{items.map((item) => <tr key={item.id}><td className="mono">{item.raw}</td><td>{item.variants?.length || 0}</td><td>{item.tags || '—'}</td><td><button className="icon-button danger" onClick={() => void remove(item.id)} aria-label={`Supprimer ${item.raw}`}><Trash2 size={16} /></button></td></tr>)}</DataTable>}
  </section>;
}

export function ScansPage({ notify }: { notify: Notify }) {
  const [scans, setScans] = useState<Crack[]>([]); const [lists, setLists] = useState<AssetList[]>([]); const [paths, setPaths] = useState<PathItem[]>([]); const [busy, setBusy] = useState(false);
  const load = async () => { try { const [scanData, listData, pathData] = await Promise.all([api<Crack[]>('/api/scans'), api<AssetList[]>('/api/lists'), api<PathItem[]>('/api/paths')]); setScans(scanData); setLists(listData); setPaths(pathData); } catch (reason) { notify(reason instanceof Error ? reason.message : 'Chargement impossible', 'error'); } };
  useEffect(() => { void load(); }, []);
  useEffect(() => { if (!scans.some((scan) => ['queued', 'running'].includes(scan.status))) return; const timer = window.setInterval(() => void load(), 5000); return () => window.clearInterval(timer); }, [scans]);
  const start = async (event: React.FormEvent<HTMLFormElement>) => { const data = formData(event); await submitForm(() => api('/api/scans', { method: 'POST', body: JSON.stringify({ list_id: Number(data.get('list_id')), path_id: Number(data.get('path_id')), authorization_confirmed: data.get('confirmed') === 'on' }) }), setBusy, notify, 'Scan placé dans la file'); await load(); };
  return <section><PageTitle eyebrow="ORDONNANCEUR" title="Scans d’exposition" description="Deux requêtes par hôte au maximum, gigue, backoff 429/503 et référence 403/404 avant détection." action={<button className="secondary" onClick={() => void load()}><RefreshCw size={16} />Actualiser</button>} />
    <form className="work-form" onSubmit={start}><div className="form-grid two"><Field label="Liste autorisée"><select name="list_id" required defaultValue=""><option value="" disabled>Choisir une liste</option>{lists.map((item) => <option key={item.id} value={item.id}>{item.name} — {item.size} cibles</option>)}</select></Field><Field label="Sonde de chemin"><select name="path_id" required defaultValue=""><option value="" disabled>Choisir un chemin</option>{paths.map((item) => <option key={item.id} value={item.id}>{item.raw}</option>)}</select></Field></div><label className="check"><input type="checkbox" name="confirmed" required /><span>Je reconfirme l’autorisation pour ce scan.</span></label><button className="primary" disabled={busy || lists.length === 0}><Play size={16} />Démarrer</button></form>
    {scans.length === 0 ? <Empty>Aucun scan. Les crédits sont débités au volume de cibles, sauf pour l’admin.</Empty> : <DataTable label="Historique des scans" headers={['ID', 'Liste', 'Sonde', 'Statut', 'Statistiques', 'Création']}>{scans.map((scan) => <tr key={scan.id}><td>#{scan.id}</td><td>{scan.list_name}</td><td className="mono">{scan.path_raw}</td><td><span className={`state ${scan.status}`}>{scan.status}</span></td><td className="mono small">{scan.stats_json}</td><td>{date(scan.created_at)}</td></tr>)}</DataTable>}
  </section>;
}
