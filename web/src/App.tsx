import { useEffect, useState } from 'react';
import { Radar } from 'lucide-react';
import { api } from './api';
import type { Me } from './types';
import Login from './Login';
import Console from './Console';

export default function App() {
  const [me, setMe] = useState<Me | null>(null); const [loading, setLoading] = useState(true);
  useEffect(() => { api<{ authenticated: boolean; session?: Me }>('/api/auth/session').then((data) => setMe(data.authenticated && data.session ? data.session : null)).catch(() => setMe(null)).finally(() => setLoading(false)); }, []);
  const logout = () => { setMe(null); window.history.replaceState(null, '', '/login'); };
  if (loading) return <main className="loading-screen"><Radar size={32} /><span>HYDRA initialise la session…</span></main>;
  if (!me) return <Login onLogin={(value) => { setMe(value); window.history.replaceState(null, '', '/app'); }} />;
  return <Console me={me} onLogout={logout} onMe={setMe} />;
}
