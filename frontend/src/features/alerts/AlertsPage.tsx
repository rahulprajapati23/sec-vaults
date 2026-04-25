import { useState, useEffect, useRef, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldExclamationIcon, ShieldCheckIcon, MagnifyingGlassIcon,
  FunnelIcon, XMarkIcon, ArrowPathIcon, SignalIcon, SignalSlashIcon,
  ExclamationTriangleIcon, ClockIcon, GlobeAltIcon, UserIcon,
  ComputerDesktopIcon, FireIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';
import { formatDistanceToNow } from 'date-fns';

// --- Types ---
export interface DamEvent {
  event_id: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: string;
  status: string;
  message: string;
  actor_email: string | null;
  actor_user_id: number | null;
  source_ip: string | null;
  geo_country: string | null;
  geo_city: string | null;
  file_id: number | null;
  file_name: string | null;
  created_at: string;
  metadata: Record<string, any>;
  isNew?: boolean; // UI-only flag for animation
}

type WsStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

// --- Severity helpers ---
const SEVERITY_CONFIG = {
  critical: { label: 'CRITICAL', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500 animate-ping', rowHighlight: 'bg-red-500/5 border-l-2 border-red-500' },
  high:     { label: 'HIGH',     bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30', dot: 'bg-orange-500', rowHighlight: 'bg-orange-500/5 border-l-2 border-orange-500' },
  medium:   { label: 'MEDIUM',   bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/30', dot: 'bg-amber-400', rowHighlight: '' },
  low:      { label: 'LOW',      bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', dot: 'bg-blue-400', rowHighlight: '' },
};

const SeverityBadge = ({ severity }: { severity: string }) => {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.low;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-bold border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
};

const safeDate = (val: string) => {
  try {
    if (val.includes('+') || val.endsWith('Z')) return new Date(val);
    return new Date(val + 'Z');
  } catch { return new Date(); }
};

// --- Alert Detail Modal ---
const AlertDetailModal = ({ event, onClose }: { event: DamEvent; onClose: () => void }) => {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl shadow-2xl max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className={`p-5 border-b border-slate-800 flex items-start justify-between rounded-t-2xl ${event.severity === 'critical' ? 'bg-red-500/5' : ''}`}>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <SeverityBadge severity={event.severity} />
              <span className="text-xs text-slate-500 font-mono">{event.event_id.slice(0, 8)}...</span>
            </div>
            <h2 className="text-lg font-bold text-white mt-1">{event.action.replace(/_/g, ' ').toUpperCase()}</h2>
            <p className="text-slate-400 text-sm mt-0.5">{event.message}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white p-1 rounded-lg transition-colors ml-4">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 grid grid-cols-2 gap-4">
          {[
            { icon: UserIcon, label: 'Actor', value: event.actor_email || 'Anonymous' },
            { icon: ComputerDesktopIcon, label: 'IP Address', value: event.source_ip || 'Unknown' },
            { icon: GlobeAltIcon, label: 'Location', value: [event.geo_city, event.geo_country].filter(Boolean).join(', ') || 'Unknown' },
            { icon: ClockIcon, label: 'Time', value: safeDate(event.created_at).toLocaleString() },
            { icon: FireIcon, label: 'Event Type', value: event.event_type },
            { icon: ShieldExclamationIcon, label: 'Status', value: event.status },
          ].map(item => (
            <div key={item.label} className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-3">
              <div className="flex items-center gap-2 mb-1">
                <item.icon className="w-3.5 h-3.5 text-slate-500" />
                <span className="text-xs text-slate-500 font-medium uppercase tracking-wide">{item.label}</span>
              </div>
              <p className="text-sm text-slate-200 font-mono">{item.value || '—'}</p>
            </div>
          ))}
        </div>

        {/* Risk score */}
        {event.metadata?.risk_score !== undefined && (
          <div className="px-5 pb-4">
            <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400 font-medium uppercase tracking-wide">Risk Score</span>
                <span className={`text-lg font-bold font-mono ${event.metadata.risk_score >= 7 ? 'text-red-400' : event.metadata.risk_score >= 4 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {Number(event.metadata.risk_score).toFixed(1)} / 10
                </span>
              </div>
              <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${event.metadata.risk_score >= 7 ? 'bg-red-500' : event.metadata.risk_score >= 4 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                  style={{ width: `${(event.metadata.risk_score / 10) * 100}%` }}
                />
              </div>
              {event.metadata.risk_factors && (
                <div className="flex flex-wrap gap-1.5 mt-3">
                  {(event.metadata.risk_factors as string[]).map(f => (
                    <span key={f} className="text-xs bg-slate-700 border border-slate-600 text-slate-300 px-2 py-0.5 rounded-full">{f}</span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Raw metadata */}
        {Object.keys(event.metadata || {}).length > 0 && (
          <div className="px-5 pb-5">
            <p className="text-xs text-slate-500 font-medium uppercase tracking-wide mb-2">Raw Metadata</p>
            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 font-mono overflow-x-auto whitespace-pre-wrap">
              {JSON.stringify(event.metadata, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

// --- Alert Row ---
const AlertRow = ({ event, onSelect }: { event: DamEvent; onSelect: () => void }) => {
  const cfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.low;
  return (
    <tr
      onClick={onSelect}
      className={`cursor-pointer transition-all border-b border-slate-800/60 hover:bg-slate-800/40 ${event.isNew ? 'animate-pulse bg-blue-500/5' : ''} ${event.severity === 'critical' || event.severity === 'high' ? cfg.rowHighlight : ''}`}
    >
      <td className="px-4 py-3 text-xs text-slate-400 font-mono whitespace-nowrap">
        {formatDistanceToNow(safeDate(event.created_at), { addSuffix: true })}
      </td>
      <td className="px-4 py-3"><SeverityBadge severity={event.severity} /></td>
      <td className="px-4 py-3 text-xs text-slate-300 font-mono">{event.action.replace(/_/g, ' ')}</td>
      <td className="px-4 py-3 text-xs text-slate-400 truncate max-w-[150px]">{event.actor_email || '—'}</td>
      <td className="px-4 py-3 text-xs text-slate-400 font-mono">{event.source_ip || '—'}</td>
      <td className="px-4 py-3 text-xs text-slate-500">{[event.geo_city, event.geo_country].filter(Boolean).join(', ') || '—'}</td>
      <td className="px-4 py-3">
        <span className={`text-xs px-2 py-0.5 rounded-md font-medium ${event.status === 'success' ? 'bg-emerald-500/10 text-emerald-400' : event.status === 'blocked' || event.status === 'failed' ? 'bg-red-500/10 text-red-400' : 'bg-amber-500/10 text-amber-400'}`}>
          {event.status?.toUpperCase()}
        </span>
      </td>
      <td className="px-4 py-3 text-xs text-slate-500 truncate max-w-[140px]">{event.message}</td>
    </tr>
  );
};

// --- Main AlertsPage ---
export const AlertsPage = () => {
  const [alerts, setAlerts] = useState<DamEvent[]>([]);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedAlert, setSelectedAlert] = useState<DamEvent | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [newAlertToast, setNewAlertToast] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  const { data: historical } = useQuery({
    queryKey: ['dam-events'],
    queryFn: async () => {
      const res = await api.get('/dam/events?limit=100');
      return res.data.events as DamEvent[];
    },
    staleTime: Infinity,
  });

  // Sync historical data to state once
  useEffect(() => {
    if (historical && alerts.length === 0) {
      setAlerts(historical);
    }
  }, [historical]);

  const addAlert = useCallback((event: DamEvent) => {
    setAlerts(prev => {
      // Deduplicate by event_id
      if (prev.find(e => e.event_id === event.event_id)) return prev;
      const newAlert = { ...event, isNew: true };
      const next = [newAlert, ...prev].slice(0, 500); // cap at 500
      return next;
    });
    // Remove 'isNew' flag after animation
    setTimeout(() => {
      setAlerts(prev => prev.map(e => e.event_id === event.event_id ? { ...e, isNew: false } : e));
    }, 3000);
    // Toast for high/critical
    if (event.severity === 'critical' || event.severity === 'high') {
      setNewAlertToast(`${event.severity.toUpperCase()}: ${event.action.replace(/_/g, ' ')} from ${event.source_ip || 'unknown IP'}`);
      setTimeout(() => setNewAlertToast(null), 5000);
    }
  }, []);

  // WebSocket connection with auto-reconnect
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setWsStatus('connecting');
    const ws = new WebSocket(`ws://${window.location.host}/ws/alerts`);
    wsRef.current = ws;

    ws.onopen = () => setWsStatus('connected');
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'alert') addAlert(msg as DamEvent);
        // heartbeat / pong — no-op
      } catch { /* ignore malformed */ }
    };
    ws.onclose = () => {
      setWsStatus('disconnected');
      reconnectTimer.current = setTimeout(connect, 3000);
    };
    ws.onerror = () => {
      setWsStatus('error');
      ws.close();
    };

    // Client-side keepalive ping every 20s
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    }, 20000);

    return () => { clearInterval(pingInterval); };
  }, [addAlert]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && tableRef.current) {
      tableRef.current.scrollTop = 0;
    }
  }, [alerts.length, autoScroll]);

  const filtered = alerts.filter(e => {
    const matchSeverity = severityFilter === 'all' || e.severity === severityFilter;
    const matchSearch = !search || [e.actor_email, e.source_ip, e.action, e.message, e.file_name]
      .some(v => v?.toLowerCase().includes(search.toLowerCase()));
    return matchSeverity && matchSearch;
  });

  const criticalCount = alerts.filter(e => e.severity === 'critical').length;
  const highCount = alerts.filter(e => e.severity === 'high').length;

  return (
    <div className="space-y-5 h-full flex flex-col">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldExclamationIcon className="w-6 h-6 text-red-400" /> Threat Alerts
          </h1>
          <p className="text-slate-400 text-sm mt-1">Real-time security event monitoring · SIEM feed</p>
        </div>
        <div className="flex items-center gap-3">
          {/* WS Status */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${
            wsStatus === 'connected' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
            wsStatus === 'connecting' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
            'bg-red-500/10 border-red-500/30 text-red-400'
          }`}>
            {wsStatus === 'connected' ? <SignalIcon className="w-3.5 h-3.5" /> : <SignalSlashIcon className="w-3.5 h-3.5" />}
            {wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'CONNECTING...' : 'DISCONNECTED'}
          </div>

          {/* Auto-scroll toggle */}
          <button
            onClick={() => setAutoScroll(s => !s)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${autoScroll ? 'bg-blue-600/20 border-blue-500/40 text-blue-400' : 'bg-slate-800 border-slate-700 text-slate-400'}`}
          >
            Auto-scroll {autoScroll ? 'ON' : 'OFF'}
          </button>

          <button onClick={connect} className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 rounded-lg transition-all" title="Reconnect">
            <ArrowPathIcon className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Critical alert banner */}
      {criticalCount > 0 && (
        <div className="bg-red-900/20 border border-red-700/50 rounded-xl px-4 py-3 flex items-center gap-3">
          <ExclamationTriangleIcon className="w-5 h-5 text-red-400 shrink-0 animate-pulse" />
          <p className="text-red-300 text-sm font-semibold">
            {criticalCount} CRITICAL {criticalCount === 1 ? 'alert requires' : 'alerts require'} immediate investigation!
          </p>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Events', value: alerts.length, color: 'text-white' },
          { label: 'Critical', value: criticalCount, color: 'text-red-400' },
          { label: 'High', value: highCount, color: 'text-orange-400' },
          { label: 'Showing', value: filtered.length, color: 'text-blue-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/50 border border-slate-800 rounded-xl px-4 py-3">
            <p className="text-xs text-slate-500 uppercase tracking-wide font-medium">{s.label}</p>
            <p className={`text-xl font-bold font-mono mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Search & Filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP, email, action, message..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>
        <div className="flex items-center gap-2">
          <FunnelIcon className="w-4 h-4 text-slate-500" />
          {['all', 'critical', 'high', 'medium', 'low'].map(s => (
            <button key={s}
              onClick={() => setSeverityFilter(s)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all capitalize ${
                severityFilter === s
                  ? s === 'critical' ? 'bg-red-500/20 border-red-500/50 text-red-400' :
                    s === 'high' ? 'bg-orange-500/20 border-orange-500/50 text-orange-400' :
                    s === 'medium' ? 'bg-amber-500/20 border-amber-500/50 text-amber-400' :
                    s === 'low' ? 'bg-blue-500/20 border-blue-500/50 text-blue-400' :
                    'bg-slate-700 border-slate-600 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {s === 'all' ? 'All' : s}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Table */}
      <div ref={tableRef} className="flex-1 overflow-auto bg-slate-900 border border-slate-800 rounded-2xl shadow-xl min-h-0">
        {alerts.length === 0 ? (
          <div className="p-16 text-center">
            <ShieldCheckIcon className="w-12 h-12 text-emerald-700 mx-auto mb-4" />
            <p className="text-slate-300 font-medium mb-1">No alerts detected</p>
            <p className="text-slate-500 text-sm">
              {wsStatus === 'connected' ? 'Monitoring is active. All clear.' : 'Connecting to alert stream...'}
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-800 text-slate-400 text-xs font-semibold uppercase tracking-wide sticky top-0 z-10">
              <tr>
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Action</th>
                <th className="px-4 py-3 text-left">Actor</th>
                <th className="px-4 py-3 text-left">IP</th>
                <th className="px-4 py-3 text-left">Location</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Message</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(event => (
                <AlertRow key={event.event_id} event={event} onSelect={() => setSelectedAlert(event)} />
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-12 text-center text-slate-500">No alerts match your filter.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail Modal */}
      {selectedAlert && <AlertDetailModal event={selectedAlert} onClose={() => setSelectedAlert(null)} />}

      {/* New alert toast */}
      {newAlertToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-red-900/90 border border-red-700 text-red-200 px-4 py-3 rounded-xl shadow-2xl flex items-center gap-3 text-sm font-medium max-w-sm">
          <ExclamationTriangleIcon className="w-4 h-4 shrink-0 animate-pulse" />
          <span className="truncate">{newAlertToast}</span>
          <button onClick={() => setNewAlertToast(null)} className="text-red-400 hover:text-white ml-1">✕</button>
        </div>
      )}
    </div>
  );
};
