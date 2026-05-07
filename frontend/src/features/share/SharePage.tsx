import { useEffect, useState, type FormEvent } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowDownTrayIcon, LockClosedIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';

interface ShareInfo {
  file_name: string;
  expires_at: string;
  password_required: boolean;
}

export default function SharePage() {
  const { token = '' } = useParams();
  const [info, setInfo] = useState<ShareInfo | null>(null);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState('');
  const backendBaseUrl = import.meta.env.VITE_API_URL?.trim() || 'http://127.0.0.1:8000';

  useEffect(() => {
    let mounted = true;
    fetch(`${backendBaseUrl}/share/${token}`, { credentials: 'include' })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok || !payload?.success) {
          throw new Error(payload?.error || 'Share link not found or expired.');
        }
        if (mounted) setInfo(payload.data);
      })
      .catch(() => {
        if (mounted) setError('Share link not found or expired.');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => { mounted = false; };
  }, [token]);

  const handleDownload = async (event: FormEvent) => {
    event.preventDefault();
    setDownloading(true);
    setError('');
    try {
      const form = new URLSearchParams();
      form.append('password', password);
      const response = await fetch(`${backendBaseUrl}/share/${token}/download`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error || payload?.detail || 'Invalid password or failed to download file.');
      }
      const blobUrl = window.URL.createObjectURL(await response.blob());
      const anchor = document.createElement('a');
      anchor.href = blobUrl;
      anchor.download = info?.file_name || 'shared-file';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err: unknown) {
      const detail = typeof err === 'object' && err && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Invalid password or failed to download file.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center gap-2 mb-4">
          <div className="w-10 h-10 rounded-xl bg-blue-600/15 border border-blue-500/30 flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Secure Share</p>
            <h1 className="text-xl font-semibold">{loading ? 'Loading...' : info?.file_name || 'Shared File'}</h1>
          </div>
        </div>

        <div className="mb-4 rounded-xl border border-slate-800 bg-slate-950/70 p-3 text-sm text-slate-300 flex items-start gap-2">
          <LockClosedIcon className="w-4 h-4 text-emerald-400 mt-0.5" />
          <div>
            <p>This link is protected by a password and may expire.</p>
            {!loading && info?.expires_at && <p className="text-xs text-slate-500 mt-1">Expires: {new Date(info.expires_at).toLocaleString()}</p>}
          </div>
        </div>

        {error && <div className="mb-4 rounded-xl border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}

        <form onSubmit={handleDownload} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-300 mb-1.5">Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="Enter share password"
            />
          </div>

          <button
            type="submit"
            disabled={loading || downloading || !password}
            className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {downloading ? 'Downloading...' : <><ArrowDownTrayIcon className="w-4 h-4" /> Download File</>}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-slate-500">
          Need access to the vault? <Link to="/login" className="text-blue-400 hover:text-blue-300">Sign in</Link>
        </p>
      </div>
    </div>
  );
}