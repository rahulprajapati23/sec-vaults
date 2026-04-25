import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  MagnifyingGlassIcon, FunnelIcon, ArrowUpTrayIcon,
  ShieldCheckIcon, ShieldExclamationIcon, LockClosedIcon, ArrowPathIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';
import { UploadModal } from './UploadModal';
import { FileRow } from './FileRow';
import type { VaultFile } from './FileRow';
import { ShareModal } from './ShareModal';

// Toast notification
const Toast = ({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) => (
  <div className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl shadow-2xl border text-sm font-medium transition-all ${
    type === 'error' ? 'bg-red-900/90 border-red-700 text-red-200' : 'bg-emerald-900/90 border-emerald-700 text-emerald-200'
  }`}>
    {type === 'error' ? <ShieldExclamationIcon className="w-4 h-4" /> : <ShieldCheckIcon className="w-4 h-4" />}
    {message}
    <button onClick={onClose} className="ml-2 opacity-60 hover:opacity-100">✕</button>
  </div>
);

export const VaultPage = () => {
  const [showUpload, setShowUpload] = useState(false);
  const [shareTarget, setShareTarget] = useState<{ fileId: number; fileName: string } | null>(null);
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const showToast = (msg: string, type: 'success' | 'error' = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 4000);
  };

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['files'],
    queryFn: async () => {
      const res = await api.get('/files');
      return res.data.files as VaultFile[];
    },
    refetchInterval: 30000,
  });

  const files = (data || []).filter(f =>
    f.original_name.toLowerCase().includes(search.toLowerCase())
  );

  const stats = {
    total: data?.length || 0,
    clean: data?.filter(f => f.scan_status !== 'infected').length || 0,
    threats: data?.filter(f => f.scan_status === 'infected').length || 0,
    totalSize: data?.reduce((acc, f) => acc + f.size_bytes, 0) || 0,
  };

  const formatBytes = (b: number) => b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <LockClosedIcon className="w-6 h-6 text-blue-400" /> Secure Vault
          </h1>
          <p className="text-slate-400 text-sm mt-1">Zero-trust encrypted file storage · AES-GCM · VirusTotal scanning</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 rounded-lg transition-all" title="Refresh">
            <ArrowPathIcon className="w-4 h-4" />
          </button>
          <button onClick={() => setShowUpload(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg transition-all text-sm">
            <ArrowUpTrayIcon className="w-4 h-4" /> Upload File
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Files', value: stats.total, color: 'text-white' },
          { label: 'Storage Used', value: formatBytes(stats.totalSize), color: 'text-blue-400' },
          { label: 'Clean Files', value: stats.clean, color: 'text-emerald-400' },
          { label: 'Threats Blocked', value: stats.threats, color: stats.threats > 0 ? 'text-red-400' : 'text-slate-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800/50 border border-slate-800 rounded-xl px-4 py-3">
            <p className="text-xs text-slate-500 font-medium uppercase tracking-wide">{s.label}</p>
            <p className={`text-xl font-bold font-mono mt-1 ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Search & Filter bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by filename..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 text-slate-300 hover:border-slate-500 rounded-lg text-sm transition-all">
          <FunnelIcon className="w-4 h-4" /> Filter
        </button>
      </div>

      {/* File Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        {isLoading ? (
          <div className="p-16 text-center">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-slate-400 text-sm">Loading encrypted vault...</p>
          </div>
        ) : files.length === 0 ? (
          <div className="p-16 text-center">
            <LockClosedIcon className="w-12 h-12 text-slate-700 mx-auto mb-4" />
            <p className="text-slate-300 font-medium mb-1">{search ? 'No files match your search' : 'Your vault is empty'}</p>
            <p className="text-slate-500 text-sm mb-6">{search ? 'Try a different search term' : 'Upload a file to get started — all files are encrypted at rest.'}</p>
            {!search && (
              <button onClick={() => setShowUpload(true)}
                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-all">
                <ArrowUpTrayIcon className="w-4 h-4" /> Upload First File
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-800 text-slate-400 text-xs font-semibold uppercase tracking-wide">
                <tr>
                  <th className="px-5 py-3">File</th>
                  <th className="px-5 py-3">Size</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Uploaded</th>
                  <th className="px-5 py-3">Downloads</th>
                  <th className="px-5 py-3">Scan</th>
                  <th className="px-5 py-3">Risk</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map(file => (
                  <FileRow
                    key={file.id}
                    file={file}
                    onShare={setShareTarget}
                    onToast={showToast}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Security notice */}
      <div className="flex items-center gap-2 text-xs text-slate-600 px-1">
        <ShieldCheckIcon className="w-3.5 h-3.5 text-emerald-700" />
        All files encrypted with AES-256-GCM. Every action is logged and monitored.
      </div>

      {/* Modals */}
      {showUpload && <UploadModal onClose={() => setShowUpload(false)} />}
      {shareTarget && <ShareModal fileId={shareTarget.fileId} fileName={shareTarget.fileName} onClose={() => setShareTarget(null)} onToast={showToast} />}

      {/* Toast */}
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  );
};
