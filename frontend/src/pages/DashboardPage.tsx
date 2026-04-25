import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import type { VaultFileSummary, DamEventSummary } from '../types/dashboard';

export default function DashboardPage() {
  const { data: filesData } = useQuery({
    queryKey: ['dashboard-files'],
    queryFn: () => api.get('/files').then(r => r.data.files as VaultFileSummary[]),
    staleTime: 30000,
  });

  const { data: eventsData } = useQuery({
    queryKey: ['dashboard-events'],
    queryFn: () => api.get('/dam/events?limit=200').then(r => r.data.events as DamEventSummary[]),
    staleTime: 30000,
    retry: false, // admin-only, don't retry on 403
  });

  const files = filesData || [];
  const events = eventsData || [];

  const totalFiles = files.length;
  const totalSize = files.reduce((acc: number, f) => acc + (f.size_bytes || 0), 0);
  const threats = events.filter((e) => e.severity === 'high' || e.severity === 'critical').length;
  const cleanFiles = files.filter((f) => f.scan_status !== 'infected').length;

  const formatSize = (b: number) => b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`;

  const stats = [
    { label: 'Encrypted Files', value: totalFiles, sub: `${formatSize(totalSize)} total`, color: 'text-white' },
    { label: 'Threat Events', value: threats, sub: events.length > 0 ? `of ${events.length} events` : 'No event data', color: threats > 0 ? 'text-red-400' : 'text-emerald-400' },
    { label: 'Clean Files', value: cleanFiles, sub: totalFiles > 0 ? `${Math.round((cleanFiles / Math.max(totalFiles, 1)) * 100)}% safe` : '—', color: 'text-emerald-400' },
    { label: 'Security Events', value: events.length, sub: 'audit log entries', color: 'text-blue-400' },
  ];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
        <p className="text-slate-400 text-sm mt-1">Real-time overview of your vault and security posture</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map(s => (
          <div key={s.label} className="bg-slate-800 border border-slate-700 p-5 rounded-xl shadow-lg">
            <h3 className="text-slate-400 text-xs font-semibold uppercase tracking-wide">{s.label}</h3>
            <p className={`text-3xl font-mono font-bold mt-3 ${s.color}`}>
              {filesData === undefined && eventsData === undefined ? '…' : s.value}
            </p>
            <p className="text-slate-500 text-xs mt-1">{s.sub}</p>
          </div>
        ))}
      </div>

      {threats > 0 && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-xl px-5 py-4 flex items-center gap-3 mb-6">
          <span className="text-red-400 text-xl">⚠️</span>
          <div>
            <p className="text-red-300 font-semibold text-sm">{threats} high-severity threat event{threats !== 1 ? 's' : ''} detected</p>
            <p className="text-red-400/70 text-xs">Review the <a href="/alerts" className="underline hover:text-red-300">Threat Alerts</a> page for details.</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h3 className="text-slate-300 font-semibold text-sm mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
            Recent Files
          </h3>
          {files.length === 0 ? (
            <p className="text-slate-500 text-sm">No files uploaded yet.</p>
          ) : (
            <div className="space-y-2">
              {files.slice(0, 5).map((f) => (
                <div key={f.id} className="flex items-center justify-between text-sm">
                  <span className="text-slate-300 truncate max-w-[200px]">{f.original_name}</span>
                  <span className="text-slate-500 text-xs ml-2 shrink-0">
                    {f.size_bytes < 1048576 ? `${(f.size_bytes / 1024).toFixed(1)} KB` : `${(f.size_bytes / 1048576).toFixed(1)} MB`}
                  </span>
                </div>
              ))}
              {files.length > 5 && <p className="text-slate-600 text-xs">+{files.length - 5} more files</p>}
            </div>
          )}
        </div>

        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <h3 className="text-slate-300 font-semibold text-sm mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-red-400 rounded-full animate-pulse" />
            Recent Security Events
          </h3>
          {events.length === 0 ? (
            <p className="text-slate-500 text-sm">No security events logged yet.</p>
          ) : (
            <div className="space-y-2">
              {events.slice(0, 5).map((e) => (
                <div key={e.event_id} className="flex items-center justify-between text-sm">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                    e.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    e.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    e.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                    'bg-blue-500/10 text-blue-400'
                  }`}>{e.severity}</span>
                  <span className="text-slate-400 truncate mx-2 flex-1">{e.action?.replace(/_/g, ' ')}</span>
                  <span className="text-slate-600 text-xs shrink-0">{e.actor_email?.split('@')[0] || '—'}</span>
                </div>
              ))}
              {events.length > 5 && <p className="text-slate-600 text-xs">+{events.length - 5} more events</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
