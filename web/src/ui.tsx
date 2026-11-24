import type { FormEvent, ReactNode } from 'react';
import { AlertCircle, CheckCircle2, Inbox, LoaderCircle } from 'lucide-react';

export function PageTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-title"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

export function Feedback({ message, kind }: { message: string; kind: 'error' | 'success' | 'info' }) {
  if (!message) return null;
  const Icon = kind === 'error' ? AlertCircle : kind === 'success' ? CheckCircle2 : LoaderCircle;
  return <div className={`feedback ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><Icon size={17} aria-hidden="true" /><span>{message}</span></div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty"><Inbox size={20} aria-hidden="true" /><span>{children}</span></div>;
}

export function DataTable({ headers, children, label }: { headers: string[]; children: ReactNode; label: string }) {
  return <div className="table-wrap"><table aria-label={label}><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{children}</tbody></table></div>;
}

export async function submitForm(action: () => Promise<unknown>, setBusy: (busy: boolean) => void, notify: (message: string, kind?: 'error' | 'success') => void, success: string) {
  setBusy(true);
  try { await action(); notify(success, 'success'); } catch (error) { notify(error instanceof Error ? error.message : 'Opération impossible', 'error'); } finally { setBusy(false); }
}

export function formData(event: FormEvent<HTMLFormElement>) {
  event.preventDefault();
  return new FormData(event.currentTarget);
}

export function date(value?: string) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' });
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}
