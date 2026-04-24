import { useState } from 'react';
import {
  XMarkIcon, LinkIcon, ClipboardDocumentIcon, CheckIcon,
  ArrowDownTrayIcon, QrCodeIcon, ShieldCheckIcon,
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';

interface ShareModalProps {
  fileId: number;
  fileName: string;
  onClose: () => void;
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

interface ShareResult {
  share_url: string;
  full_url: string;
  share_id: number;
  expires_at: string;
  qr_code: string | null;
  file_name: string;
}

export const ShareModal = ({ fileId, fileName, onClose, onToast }: ShareModalProps) => {
  const [password, setPassword] = useState('');
  const [expiryHours, setExpiryHours] = useState(24);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<ShareResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const handleGenerate = async () => {
    if (password.length < 8) { setError('Password must be at least 8 characters.'); return; }
    setIsLoading(true); setError('');
    try {
      const form = new URLSearchParams();
      form.append('password', password);
      form.append('expires_hours', String(expiryHours));
      const res = await api.post(`/files/${fileId}/share`, form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      setResult(res.data);
      onToast('Secure share link generated!');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to generate share link.');
      onToast('Failed to generate share link.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result) return;
    const urlToCopy = result.full_url || `${window.location.origin}${result.share_url}`;
    navigator.clipboard.writeText(urlToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadQR = () => {
    if (!result?.qr_code) return;
    const link = document.createElement('a');
    link.href = result.qr_code;
    link.download = `qr-${result.file_name || 'share'}.png`;
    link.click();
  };

  const displayUrl = result
    ? (result.full_url || `${window.location.origin}${result.share_url}`)
    : '';

  const expiresLabel = result
    ? new Date(result.expires_at).toLocaleString()
    : '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <LinkIcon className="w-5 h-5 text-blue-400" /> Generate Secure Link
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 truncate max-w-xs">{fileName}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white p-1 rounded-lg transition-colors">
            <XMarkIcon className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {!result ? (
            <>
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Link Password (min 8 chars) *</label>
                <input
                  type="password" value={password}
                  onChange={e => { setPassword(e.target.value); setError(''); }}
                  placeholder="••••••••"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Expires In</label>
                <select value={expiryHours} onChange={e => setExpiryHours(parseInt(e.target.value))}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500">
                  <option value={1}>1 hour</option>
                  <option value={6}>6 hours</option>
                  <option value={24}>24 hours</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                </select>
              </div>

              <div className="bg-slate-800 border border-slate-700 rounded-xl p-3">
                <p className="text-xs text-slate-400 font-medium mb-1.5 flex items-center gap-1.5">
                  <ShieldCheckIcon className="w-3.5 h-3.5 text-emerald-400" /> Security Info
                </p>
                <ul className="space-y-1 text-xs text-slate-500">
                  <li>• Recipient must know the password to access</li>
                  <li>• Link expires automatically after {expiryHours}h</li>
                  <li>• Max 5 wrong password attempts before lock</li>
                  <li>• Every access attempt is logged with IP + timestamp</li>
                </ul>
              </div>

              {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</p>}

              <button onClick={handleGenerate} disabled={isLoading || !password}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-lg text-sm flex items-center justify-center gap-2 transition-all">
                {isLoading
                  ? <><svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Generating...</>
                  : <><LinkIcon className="w-4 h-4" /> Generate Secure Link + QR Code</>
                }
              </button>
            </>
          ) : (
            <div className="space-y-4">
              {/* Success banner */}
              <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3 text-center">
                <p className="text-emerald-400 font-semibold text-sm">🔐 Secure Link Generated!</p>
                <p className="text-slate-400 text-xs mt-0.5">Expires: {expiresLabel}</p>
              </div>

              {/* Two-column: URL + QR */}
              <div className={`grid gap-4 ${result.qr_code ? 'grid-cols-[1fr_auto]' : 'grid-cols-1'}`}>
                {/* URL box */}
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Secure Share URL</label>
                  <div className="flex items-center gap-2">
                    <input readOnly value={displayUrl}
                      className="flex-1 px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-300 text-xs font-mono focus:outline-none" />
                    <button onClick={handleCopy}
                      className="p-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-all shrink-0"
                      title="Copy link">
                      {copied ? <CheckIcon className="w-4 h-4 text-emerald-400" /> : <ClipboardDocumentIcon className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* QR Code */}
                {result.qr_code && (
                  <div className="flex flex-col items-center gap-2">
                    <label className="text-xs font-medium text-slate-400 self-start">QR Code</label>
                    <div className="bg-slate-100 rounded-xl p-1.5 shadow-lg">
                      <img src={result.qr_code} alt="Share QR Code" className="w-28 h-28 rounded-lg" />
                    </div>
                    <button onClick={handleDownloadQR}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-lg transition-all">
                      <ArrowDownTrayIcon className="w-3.5 h-3.5" /> Download QR
                    </button>
                  </div>
                )}
              </div>

              {/* No QR fallback message */}
              {!result.qr_code && (
                <div className="flex items-center gap-2 text-xs text-amber-400/70 bg-amber-500/5 border border-amber-500/10 rounded-lg px-3 py-2">
                  <QrCodeIcon className="w-4 h-4 shrink-0" />
                  <span>QR code unavailable — install <code className="font-mono">qrcode[pil]</code> on the server to enable</span>
                </div>
              )}

              <div className="bg-slate-800 border border-slate-700 rounded-xl p-3 text-xs text-slate-500 space-y-1">
                <p className="text-slate-400 font-medium mb-1">📋 Sharing Instructions</p>
                <p>1. Send this URL to the recipient</p>
                <p>2. Share the password you set <strong className="text-slate-400">separately</strong> (not in same message)</p>
                <p>3. Or print the QR code — recipient scans to open in browser, then enters password</p>
              </div>

              <div className="flex gap-2">
                <button onClick={handleCopy}
                  className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg text-sm flex items-center justify-center gap-2 transition-all">
                  {copied ? <><CheckIcon className="w-4 h-4" /> Copied!</> : <><ClipboardDocumentIcon className="w-4 h-4" /> Copy Link</>}
                </button>
                <button onClick={onClose} className="flex-1 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-lg text-sm transition-colors">
                  Done
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
