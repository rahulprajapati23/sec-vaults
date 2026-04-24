import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../../services/api';
import { ShieldExclamationIcon, PlayIcon, StopIcon } from '@heroicons/react/24/outline';

export const PoliciesPage = () => {
  const queryClient = useQueryClient();
  const [engineActive, setEngineActive] = useState(true);
  const [liveEvents, setLiveEvents] = useState<any[]>([]);

  // Fetch Incidents
  const { data: incidentsData } = useQuery({
    queryKey: ['siem-incidents'],
    queryFn: () => api.get('/siem/incidents').then(r => r.data),
    refetchInterval: 5000,
  });

  const incidents = Array.isArray(incidentsData) ? incidentsData : [];

  // Block IP Mutation
  const blockIpMutation = useMutation({
    mutationFn: (ip: string) => api.post('/siem/response/block-ip', { ip, duration_hours: 24 }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['siem-incidents'] })
  });

  // Resolve Incident Mutation
  const resolveMutation = useMutation({
    mutationFn: (id: string) => api.post(`/siem/incidents/${id}/resolve`, { notes: "Resolved by SOC" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['siem-incidents'] })
  });

  // WebSocket for Live Feed
  useEffect(() => {
    if (!engineActive) return;
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = import.meta.env.VITE_API_URL ? new URL(import.meta.env.VITE_API_URL).host : window.location.host;
    
    const ws = new WebSocket(`${protocol}//${host}/ws/alerts`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'alert' || data.type === 'incident') {
        setLiveEvents(prev => [data, ...prev].slice(0, 50));
      }
    };
    
    return () => ws.close();
  }, [engineActive]);

  const owaspRules = [
    { id: 'A01', name: 'Broken Access Control', triggers: incidents.filter((i: any) => i.owasp_vector.includes('A01')).length },
    { id: 'A02', name: 'Cryptographic Failures', triggers: incidents.filter((i: any) => i.owasp_vector.includes('A02')).length },
    { id: 'A03', name: 'Injection (Malware)', triggers: incidents.filter((i: any) => i.owasp_vector.includes('A03')).length },
    { id: 'A07', name: 'Auth Failures (Brute Force)', triggers: incidents.filter((i: any) => i.owasp_vector.includes('A07')).length },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto h-[calc(100vh-8rem)] flex flex-col">
      {/* SECTION A: TOP CONTROL BAR */}
      <div className="flex items-center justify-between bg-slate-800 border border-slate-700 p-4 rounded-xl shrink-0">
        <div className="flex items-center gap-4">
          <ShieldExclamationIcon className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-xl font-bold text-white tracking-wider">GUARDIUM-LITE SIEM</h1>
            <p className="text-slate-400 text-xs">Enterprise Security Monitoring Console</p>
          </div>
        </div>
        
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-300">Engine Status:</span>
            <button 
              onClick={() => setEngineActive(!engineActive)}
              className={`px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1 transition-colors ${engineActive ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/50' : 'bg-red-500/20 text-red-400 border border-red-500/50'}`}
            >
              {engineActive ? <><PlayIcon className="w-4 h-4"/> LIVE</> : <><StopIcon className="w-4 h-4"/> PAUSED</>}
            </button>
          </div>
          <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            + New Custom Policy
          </button>
        </div>
      </div>

      <div className="flex gap-6 flex-1 min-h-0">
        {/* SECTION B: LEFT PANEL (OWASP ENGINE) */}
        <div className="w-80 bg-slate-800 border border-slate-700 rounded-xl flex flex-col overflow-hidden shrink-0">
          <div className="p-4 border-b border-slate-700 bg-slate-850">
            <h2 className="text-sm font-bold text-slate-200">DETECTION ENGINE</h2>
            <p className="text-xs text-slate-500">Active OWASP Rules</p>
          </div>
          <div className="overflow-y-auto p-4 space-y-3 flex-1">
            {owaspRules.map(rule => (
              <div key={rule.id} className="bg-slate-900 border border-slate-700 rounded-lg p-3">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs font-bold text-blue-400">{rule.id}</span>
                  <span className="text-xs font-medium text-slate-500">{rule.triggers} triggers</span>
                </div>
                <h3 className="text-sm text-slate-300 font-medium">{rule.name}</h3>
                <div className="mt-2 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                  <span className="text-xs text-slate-400">ACTIVE</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* SECTION C: CENTER PANEL (LIVE FEED) */}
        <div className="flex-1 bg-slate-800 border border-slate-700 rounded-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-slate-700 bg-slate-850 flex justify-between items-center">
            <div>
              <h2 className="text-sm font-bold text-slate-200">REAL-TIME THREAT FEED</h2>
              <p className="text-xs text-slate-500">WebSocket Live Stream</p>
            </div>
            {engineActive && <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>}
          </div>
          <div className="overflow-y-auto p-4 space-y-2 flex-1 font-mono text-xs">
            {liveEvents.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500">Listening for events...</div>
            ) : (
              liveEvents.map((evt, i) => (
                <div key={i} className={`p-2 rounded border-l-4 ${evt.severity === 'high' || evt.type === 'incident' ? 'bg-red-950/30 border-red-500 text-red-200' : 'bg-slate-900/50 border-blue-500 text-slate-300'}`}>
                  <span className="text-slate-500 mr-3">[{new Date().toLocaleTimeString()}]</span>
                  <span className="font-bold mr-2">[{evt.type === 'incident' ? 'INCIDENT' : (evt.severity?.toUpperCase() || 'INFO')}]</span>
                  {evt.type === 'incident' ? (
                    <span>{evt.owasp_vector} - {evt.title}</span>
                  ) : (
                    <span>{evt.action}: {evt.message} {evt.source_ip ? `(IP: ${evt.source_ip})` : ''}</span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* SECTION D: BOTTOM PANEL (INCIDENT MANAGEMENT) */}
      <div className="h-64 bg-slate-800 border border-slate-700 rounded-xl flex flex-col shrink-0 overflow-hidden">
        <div className="p-4 border-b border-slate-700 bg-slate-850">
          <h2 className="text-sm font-bold text-slate-200">INCIDENT MANAGEMENT</h2>
          <p className="text-xs text-slate-500">Automated Correlation & Response</p>
        </div>
        <div className="overflow-auto flex-1 p-0">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/50 text-slate-400 text-xs uppercase sticky top-0">
              <tr>
                <th className="px-4 py-3 font-medium">Incident ID</th>
                <th className="px-4 py-3 font-medium">OWASP Vector</th>
                <th className="px-4 py-3 font-medium">Affected Resource</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {incidents.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500 text-sm">No incidents detected. System is secure.</td></tr>
              ) : (
                incidents.map((inc: any) => (
                  <tr key={inc.id} className="hover:bg-slate-750 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-blue-400">{inc.id}</td>
                    <td className="px-4 py-3 text-slate-300 font-medium">{inc.owasp_vector}</td>
                    <td className="px-4 py-3 text-slate-400">{inc.affected_resource}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${inc.risk_score >= 80 ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                        {inc.risk_score}/100
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-bold uppercase ${inc.status === 'open' ? 'text-red-400' : 'text-emerald-400'}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      {inc.status === 'open' && inc.attacker_ip && (
                        <button 
                          onClick={() => blockIpMutation.mutate(inc.attacker_ip)}
                          disabled={blockIpMutation.isPending}
                          className="bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-600/50 px-3 py-1 rounded text-xs font-medium transition-colors"
                        >
                          Block IP
                        </button>
                      )}
                      {inc.status === 'open' && (
                        <button 
                          onClick={() => resolveMutation.mutate(inc.id)}
                          className="bg-slate-700 hover:bg-slate-600 text-slate-300 px-3 py-1 rounded text-xs font-medium transition-colors"
                        >
                          Resolve
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
