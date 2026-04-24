import React, { useState, useRef } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { CloudArrowUpIcon, XMarkIcon, ShieldCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { api } from '../../services/api';

type ScanStatus = 'idle' | 'uploading' | 'scanning' | 'clean' | 'infected' | 'error';

interface UploadModalProps {
  onClose: () => void;
}

export const UploadModal = ({ onClose }: UploadModalProps) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [expiryHours, setExpiryHours] = useState(24);
  const [maxDownloads, setMaxDownloads] = useState<number | ''>('');
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const handleFile = (f: File) => { setSelectedFile(f); setScanStatus('idle'); setErrorMsg(''); };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const formatBytes = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(1)} MB`;

  const handleUpload = async () => {
    if (!selectedFile) return;
    setScanStatus('uploading');
    setProgress(10);
    setErrorMsg('');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('expiry_hours', String(expiryHours));
    if (maxDownloads) formData.append('max_downloads', String(maxDownloads));

    try {
      setProgress(40);
      setScanStatus('scanning');
      const res = await api.post('/files/api-upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => {
          if (e.total) setProgress(Math.round((e.loaded / e.total) * 50) + 10);
        },
      });
      setProgress(100);
      setScanStatus(res.data.scan_status === 'infected' ? 'infected' : 'clean');
      queryClient.invalidateQueries({ queryKey: ['files'] });
      if (res.data.scan_status !== 'infected') {
        setTimeout(onClose, 1500);
      }
    } catch (err: any) {
      setScanStatus('error');
      setProgress(0);
      if (err.response?.status === 406) {
        setScanStatus('infected');
        setErrorMsg('Malware detected! File has been blocked and quarantined.');
      } else if (err.response?.status === 413) {
        setErrorMsg('File too large. Maximum allowed size exceeded.');
      } else {
        setErrorMsg(err.response?.data?.detail || 'Upload failed. Please try again.');
      }
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-white">Upload Encrypted File</h2>
            <p className="text-xs text-slate-400 mt-0.5">AES-GCM encrypted · VirusTotal scanned</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white p-1 rounded-lg transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Drop Zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => inputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
              isDragging ? 'border-blue-500 bg-blue-500/10' :
              selectedFile ? 'border-emerald-600 bg-emerald-500/5' :
              'border-slate-700 hover:border-slate-500 bg-slate-800/30'
            }`}
          >
            <input ref={inputRef} type="file" className="hidden" onChange={(e) => { if (e.target.files?.[0]) handleFile(e.target.files[0]); }} />
            <CloudArrowUpIcon className="w-10 h-10 text-slate-400 mx-auto mb-3" />
            {selectedFile ? (
              <div>
                <p className="text-white font-medium text-sm">{selectedFile.name}</p>
                <p className="text-slate-400 text-xs mt-1">{formatBytes(selectedFile.size)}</p>
              </div>
            ) : (
              <div>
                <p className="text-slate-300 text-sm font-medium">Drop file here or click to browse</p>
                <p className="text-slate-500 text-xs mt-1">Max 10 MB · All types supported</p>
              </div>
            )}
          </div>

          {/* Options */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Expiry (hours)</label>
              <input type="number" min={1} max={720} value={expiryHours}
                onChange={(e) => setExpiryHours(parseInt(e.target.value) || 24)}
                className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500" />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Max Downloads (optional)</label>
              <input type="number" min={1} value={maxDownloads}
                onChange={(e) => setMaxDownloads(e.target.value ? parseInt(e.target.value) : '')}
                placeholder="Unlimited"
                className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 placeholder-slate-600" />
            </div>
          </div>

          {/* Progress & Scan Status */}
          {scanStatus !== 'idle' && (
            <div className="space-y-2">
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all duration-500 ${
                  scanStatus === 'infected' || scanStatus === 'error' ? 'bg-red-500' :
                  scanStatus === 'clean' ? 'bg-emerald-500' : 'bg-blue-500'
                }`} style={{ width: `${progress}%` }} />
              </div>
              <div className="flex items-center gap-2">
                {scanStatus === 'uploading' && <><div className="w-2 h-2 bg-blue-400 rounded-full animate-ping" /><span className="text-xs text-blue-400">Encrypting and uploading...</span></>}
                {scanStatus === 'scanning' && <><div className="w-2 h-2 bg-amber-400 rounded-full animate-ping" /><span className="text-xs text-amber-400">VirusTotal scan in progress...</span></>}
                {scanStatus === 'clean' && <><ShieldCheckIcon className="w-4 h-4 text-emerald-400" /><span className="text-xs text-emerald-400">Clean — File stored securely!</span></>}
                {scanStatus === 'infected' && <><ExclamationTriangleIcon className="w-4 h-4 text-red-400" /><span className="text-xs text-red-400">Malware detected — Upload blocked!</span></>}
                {scanStatus === 'error' && <><ExclamationTriangleIcon className="w-4 h-4 text-red-400" /><span className="text-xs text-red-400">{errorMsg}</span></>}
              </div>
            </div>
          )}

          {/* Upload Button */}
          <button
            onClick={handleUpload}
            disabled={!selectedFile || ['uploading', 'scanning', 'clean'].includes(scanStatus)}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all text-sm flex items-center justify-center gap-2"
          >
            {['uploading', 'scanning'].includes(scanStatus) ? (
              <><svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Processing...</>
            ) : 'Upload & Encrypt →'}
          </button>
        </div>
      </div>
    </div>
  );
};
