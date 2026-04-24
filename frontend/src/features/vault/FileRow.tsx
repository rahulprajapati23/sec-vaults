import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  DocumentIcon, LockClosedIcon, ShieldCheckIcon, ShieldExclamationIcon,
  TrashIcon, ArrowDownTrayIcon, LinkIcon, EllipsisVerticalIcon,
  ClockIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';
import { formatDistanceToNow } from 'date-fns';

// Safe date parser — backend may return "2026-04-25T00:00:00+00:00" or "2026-04-25T00:00:00"
const safeDate = (val: string): Date => {
  try {
    // Already has timezone info
    if (val.includes('+') || val.endsWith('Z')) return new Date(val);
    // Naive datetime — treat as UTC
    return new Date(val + 'Z');
  } catch {
    return new Date();
  }
};

export interface VaultFile {
  id: number;
  original_name: string;
  mime_type: string;
  size_bytes: number;
  created_at: string;
  expires_at: string | null;
  download_count: number;
  max_downloads: number | null;
  scan_status?: string;
}

const formatBytes = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`;

const getRiskLevel = (file: VaultFile): 'low' | 'medium' | 'high' => {
  if (file.scan_status === 'infected') return 'high';
  if (file.download_count > 10) return 'medium';
  return 'low';
};

const RiskBadge = ({ level }: { level: 'low' | 'medium' | 'high' }) => {
  const styles = {
    low:    'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    medium: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    high:   'bg-red-500/10 text-red-400 border-red-500/20 animate-pulse',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${styles[level]}`}>
      {level.toUpperCase()}
    </span>
  );
};

interface ShareModalState { fileId: number; fileName: string; }

interface FileRowProps {
  file: VaultFile;
  onShare: (s: ShareModalState) => void;
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

export const FileRow = ({ file, onShare, onToast }: FileRowProps) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const queryClient = useQueryClient();
  const risk = getRiskLevel(file);

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/files/${file.id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['files'] });
      onToast(`"${file.original_name}" deleted successfully.`);
    },
    onError: () => onToast('Failed to delete file.', 'error'),
  });

  const handleDownload = async () => {
    try {
      const response = await api.get(`/files/${file.id}/download`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', file.original_name);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      onToast(`Downloading "${file.original_name}"...`);
    } catch {
      onToast('Download failed or access denied.', 'error');
    }
  };

  const handleDelete = () => {
    if (confirm(`Permanently delete "${file.original_name}"? This cannot be undone.`)) {
      deleteMutation.mutate();
    }
    setMenuOpen(false);
  };

  const isExpired = file.expires_at && new Date(file.expires_at) < new Date();
  const isLimited = file.max_downloads !== null && file.download_count >= file.max_downloads;

  return (
    <tr className="hover:bg-slate-800/40 transition-colors border-b border-slate-800/60 group relative">
      {/* File Name */}
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-3">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
            risk === 'high' ? 'bg-red-500/10' : 'bg-slate-800'
          }`}>
            {risk === 'high'
              ? <ShieldExclamationIcon className="w-4 h-4 text-red-400" />
              : <DocumentIcon className="w-4 h-4 text-slate-400" />
            }
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium text-slate-100 truncate max-w-[200px]">{file.original_name}</p>
            <p className="text-xs text-slate-500">{file.mime_type}</p>
          </div>
        </div>
      </td>

      {/* Size */}
      <td className="px-5 py-3.5 text-sm text-slate-400">{formatBytes(file.size_bytes)}</td>

      {/* Status */}
      <td className="px-5 py-3.5">
        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md bg-slate-800 border border-slate-700 text-slate-300">
          <LockClosedIcon className="w-3 h-3 text-blue-400" />
          {isExpired ? 'EXPIRED' : isLimited ? 'LIMIT REACHED' : 'PRIVATE'}
        </span>
      </td>

      {/* Uploaded */}
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-1 text-xs text-slate-400">
          <ClockIcon className="w-3.5 h-3.5" />
          {formatDistanceToNow(safeDate(file.created_at), { addSuffix: true })}
        </div>
      </td>

      {/* Downloads */}
      <td className="px-5 py-3.5 text-sm text-slate-400">
        <div className="flex items-center gap-1">
          <ArrowDownTrayIcon className="w-3.5 h-3.5" />
          {file.download_count}{file.max_downloads !== null ? ` / ${file.max_downloads}` : ''}
        </div>
      </td>

      {/* Risk */}
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-1.5">
          {file.scan_status === 'infected'
            ? <span className="text-xs text-red-400 flex items-center gap-1"><ShieldExclamationIcon className="w-3.5 h-3.5" /> Infected</span>
            : <span className="text-xs text-emerald-400 flex items-center gap-1"><ShieldCheckIcon className="w-3.5 h-3.5" /> Clean</span>
          }
        </div>
      </td>

      {/* Risk Badge */}
      <td className="px-5 py-3.5"><RiskBadge level={risk} /></td>

      {/* Actions */}
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-1 justify-end">
          <button onClick={handleDownload} disabled={isExpired || isLimited}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-all disabled:opacity-30 disabled:cursor-not-allowed"
            title="Download">
            <ArrowDownTrayIcon className="w-4 h-4" />
          </button>
          <button onClick={() => onShare({ fileId: file.id, fileName: file.original_name })}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-all"
            title="Generate Share Link">
            <LinkIcon className="w-4 h-4" />
          </button>
          <div className="relative">
            <button onClick={() => setMenuOpen(s => !s)}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-all">
              <EllipsisVerticalIcon className="w-4 h-4" />
            </button>
            {menuOpen && (
              <div className="absolute right-0 top-8 z-20 bg-slate-800 border border-slate-700 rounded-xl shadow-2xl py-1 w-40">
                <button onClick={() => { handleDownload(); setMenuOpen(false); }}
                  className="w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 flex items-center gap-2">
                  <ArrowDownTrayIcon className="w-4 h-4" /> Download
                </button>
                <button onClick={() => { onShare({ fileId: file.id, fileName: file.original_name }); setMenuOpen(false); }}
                  className="w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 flex items-center gap-2">
                  <LinkIcon className="w-4 h-4" /> Share Link
                </button>
                <div className="border-t border-slate-700 my-1" />
                <button onClick={handleDelete}
                  className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/10 flex items-center gap-2">
                  <TrashIcon className="w-4 h-4" /> Delete
                </button>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
};
