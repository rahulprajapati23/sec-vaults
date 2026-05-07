import { useState, useEffect, useCallback } from 'react';
import { api } from '../../services/api';
import { Section, SettingRow, Toggle, NumberInput } from './SettingsComponents';
import { CheckCircleIcon, XCircleIcon } from '@heroicons/react/24/outline';

interface Props {
  config: {
    dailyReportEnabled: boolean;
    weeklyReportEnabled: boolean;
    logRetentionDays: number;
  };
  set: (key: 'dailyReportEnabled' | 'weeklyReportEnabled' | 'logRetentionDays', value: boolean | number) => void;
}

const StatCard = ({ label, value, color }: { label: string; value: string | number | null | undefined; color: string }) => (
  <div className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-4 text-center">
    <p className={`text-2xl font-bold font-mono ${color}`}>{value ?? '…'}</p>
    <p className="text-xs text-slate-500 mt-1 uppercase tracking-wide font-medium">{label}</p>
  </div>
);

export const LogsReportsTab = ({ config, set }: Props) => {
  interface SummaryData {
    total_events: number;
    high_risk_events: number;
    failed_logins: number;
    unauthorized_access: number;
    malware_detected: number;
    unique_actors: number;
    top_attacker_ips?: { source_ip: string; count: number }[];
  }
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [sendResult, setSendResult] = useState<Record<string, { ok: boolean; msg: string } | null>>({});
  const [sending, setSending] = useState<Record<string, boolean>>({});
  const [period, setPeriod] = useState(1);
  const topAttackerIps = summary?.top_attacker_ips ?? [];

  const fetchSummary = useCallback(async (days = period) => {
    setLoading(true);
    try {
      const res = await api.get(`/reports/summary?days=${days}`);
      setSummary(res.data);
    } catch {
      setSummary(null);
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => {
    fetchSummary(period);
  }, [period, fetchSummary]);

  const sendReport = async (type: 'daily' | 'weekly') => {
    setSending(s => ({ ...s, [type]: true }));
    setSendResult(r => ({ ...r, [type]: null }));
    try {
      const res = await api.post(`/reports/send/${type}`);
      setSendResult(r => ({ ...r, [type]: { ok: true, msg: res.data.message } }));
    } catch (err: unknown) {
      const detail = typeof err === 'object' && err && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setSendResult(r => ({ ...r, [type]: { ok: false, msg: detail || 'Failed to send report' } }));
    } finally {
      setSending(s => ({ ...s, [type]: false }));
    }
  };

  const exportEvents = async () => {
    try {
      const res = await api.get('/dam/events?limit=500');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'dam-events.json';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      // no-op, keep UI simple for now
    }
  };

  return (
    <>
      <div>
        <h1 className="text-xl font-bold text-white">Logs & Audit Reports</h1>
        <p className="text-slate-400 text-sm mt-1">Live security stats and scheduled report delivery</p>
      </div>

      {/* Period selector */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500 font-medium">Time range:</span>
        {[1, 7, 30].map(d => (
          <button key={d} onClick={() => setPeriod(d)}
            className={`px-3 py-1 rounded-lg text-xs font-semibold border transition-all ${period === d ? 'bg-blue-600/20 border-blue-500/40 text-blue-400' : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'}`}>
            {d === 1 ? '24h' : d === 7 ? '7 days' : '30 days'}
          </button>
        ))}
        <button onClick={() => fetchSummary(period)} className="px-3 py-1 rounded-lg text-xs text-slate-500 hover:text-white border border-slate-800 hover:border-slate-600 transition-all">↻ Refresh</button>
      </div>

      {/* KPI Grid */}
      {loading ? (
        <div className="grid grid-cols-3 gap-3">
          {Array(6).fill(0).map((_, i) => (
            <div key={i} className="bg-slate-950 border border-slate-800 rounded-xl p-4 animate-pulse h-20" />
          ))}
        </div>
      ) : summary ? (
        <div className="grid grid-cols-3 gap-3">
          <StatCard label="Total Events" value={summary.total_events} color="text-white" />
          <StatCard label="High Risk" value={summary.high_risk_events} color={summary.high_risk_events > 0 ? 'text-red-400' : 'text-emerald-400'} />
          <StatCard label="Failed Logins" value={summary.failed_logins} color={summary.failed_logins > 0 ? 'text-orange-400' : 'text-slate-400'} />
          <StatCard label="Unauth Access" value={summary.unauthorized_access} color={summary.unauthorized_access > 0 ? 'text-red-400' : 'text-slate-400'} />
          <StatCard label="Malware Found" value={summary.malware_detected} color={summary.malware_detected > 0 ? 'text-purple-400' : 'text-emerald-400'} />
          <StatCard label="Unique Actors" value={summary.unique_actors} color="text-blue-400" />
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-center">
          <p className="text-slate-500 text-sm">Unable to load report summary. Admin access required.</p>
        </div>
      )}

      {/* Top Attackers */}
      {topAttackerIps.length > 0 && (
        <Section title="Top Suspicious IPs" icon="⚠️">
          <div className="py-3 space-y-2">
            {topAttackerIps.map((item: any) => (
              <div key={item.source_ip} className="flex items-center justify-between">
                <span className="text-sm font-mono text-slate-300">{item.source_ip}</span>
                <span className="text-xs font-bold text-orange-400 bg-orange-500/10 border border-orange-500/20 px-2 py-0.5 rounded-full">{item.count}× failed</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Send Reports */}
      <Section title="Send Report Now" icon="📤">
        <div className="py-4 space-y-4">
          {(['daily', 'weekly'] as const).map(type => (
            <div key={type} className="space-y-2">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => sendReport(type)}
                  disabled={sending[type]}
                  className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-slate-700 text-slate-300 text-sm rounded-lg transition-colors"
                >
                  {sending[type]
                    ? <><svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg> Sending...</>
                    : `📧 Send ${type === 'daily' ? 'Daily (24h)' : 'Weekly (7d)'} Report`
                  }
                </button>
                <span className="text-xs text-slate-600">Emails admin recipients</span>
              </div>
              {sendResult[type] && (
                <div className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg border ${sendResult[type]!.ok ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400' : 'bg-red-500/5 border-red-500/20 text-red-400'}`}>
                  {sendResult[type]!.ok ? <CheckCircleIcon className="w-3.5 h-3.5" /> : <XCircleIcon className="w-3.5 h-3.5" />}
                  {sendResult[type]!.msg}
                </div>
              )}
            </div>
          ))}
        </div>
      </Section>

      {/* Scheduled delivery toggles */}
      <Section title="Scheduled Reports" icon="📆">
        <SettingRow label="Auto Daily Report" description="Automatically send daily summary at 00:00 UTC">
          <Toggle checked={config.dailyReportEnabled} onChange={v => set('dailyReportEnabled', v)} />
        </SettingRow>
        <SettingRow label="Auto Weekly Report" description="Automatically send weekly report every Monday at 00:00 UTC">
          <Toggle checked={config.weeklyReportEnabled} onChange={v => set('weeklyReportEnabled', v)} />
        </SettingRow>
      </Section>

      {/* Retention + Export */}
      <Section title="Retention & Export" icon="🗂️">
        <SettingRow label="Log Retention Period" description="Audit logs older than this are purged automatically">
          <NumberInput value={config.logRetentionDays} onChange={v => set('logRetentionDays', v)} min={7} max={365} unit="days" />
        </SettingRow>
        <div className="py-4 flex flex-wrap gap-3">
          <button
            onClick={exportEvents}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-sm rounded-lg transition-colors"
          >
            📄 Export JSON (500 events)
          </button>
          <span className="self-center text-xs text-slate-600">Admin access required for full export</span>
        </div>
      </Section>
    </>
  );
};
