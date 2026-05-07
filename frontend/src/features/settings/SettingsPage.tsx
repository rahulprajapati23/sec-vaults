import { useState, useCallback, useEffect } from 'react';
import { useAuth } from '../auth/AuthContext';
import { api } from '../../services/api';
import {
  UserIcon, ShieldCheckIcon, LockClosedIcon,
  BellIcon, DocumentTextIcon, CpuChipIcon,
  CheckCircleIcon, EnvelopeIcon, XCircleIcon
} from '@heroicons/react/24/outline';
import { Toggle, SettingRow, Section, NumberInput, TagInput, SaveBar } from './SettingsComponents';
import { LogsReportsTab } from './LogsReportsTab';
import { logEvent } from '../../services/logger';


type Tab = 'profile' | 'security' | 'access' | 'notifications' | 'smtp' | 'logs' | 'advanced';

const NAV: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'profile',       label: 'Profile',              icon: <UserIcon className="w-4 h-4" /> },
  { id: 'security',      label: 'Security',             icon: <ShieldCheckIcon className="w-4 h-4" /> },
  { id: 'access',        label: 'Access Control',       icon: <LockClosedIcon className="w-4 h-4" /> },
  { id: 'notifications', label: 'Alerts & Notifs',      icon: <BellIcon className="w-4 h-4" /> },
  { id: 'smtp',          label: 'Email / SMTP',         icon: <EnvelopeIcon className="w-4 h-4" /> },
  { id: 'logs',          label: 'Logs & Reports',       icon: <DocumentTextIcon className="w-4 h-4" /> },
  { id: 'advanced',      label: 'Advanced Security',    icon: <CpuChipIcon className="w-4 h-4" /> },
];

interface Config {
  // Security
  bruteForceThreshold: number;
  loginFailureWindowMins: number;
  sessionTimeoutHours: number;
  mfaEnabled: boolean;
  geoTrackingEnabled: boolean;
  // Access control
  defaultFilePrivate: boolean;
  requireApprovalForDownload: boolean;
  blockedEmails: string[];
  blockedIPs: string[];
  allowedDomains: string[];
  secureLinkExpiryHours: number;
  secureLinkMaxDownloads: number;
  // Notifications
  emailOnFailedLogin: boolean;
  emailOnSuspiciousActivity: boolean;
  emailOnFileAccess: boolean;
  alertThreshold: number;
  // Logs
  dailyReportEnabled: boolean;
  weeklyReportEnabled: boolean;
  logRetentionDays: number;
  // Advanced
  honeypotEnabled: boolean;
  anomalyDetectionEnabled: boolean;
  riskScoringEnabled: boolean;
}

const DEFAULT_CONFIG: Config = {
  bruteForceThreshold: 5,
  loginFailureWindowMins: 10,
  sessionTimeoutHours: 24,
  mfaEnabled: false,
  geoTrackingEnabled: true,
  defaultFilePrivate: true,
  requireApprovalForDownload: false,
  blockedEmails: [],
  blockedIPs: [],
  allowedDomains: [],
  secureLinkExpiryHours: 24,
  secureLinkMaxDownloads: 5,
  emailOnFailedLogin: true,
  emailOnSuspiciousActivity: true,
  emailOnFileAccess: false,
  alertThreshold: 3,
  dailyReportEnabled: false,
  weeklyReportEnabled: true,
  logRetentionDays: 90,
  honeypotEnabled: true,
  anomalyDetectionEnabled: true,
  riskScoringEnabled: true,
};

const isEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) || v.startsWith('@');
const isIP = (v: string) => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v);

export const SettingsPage = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>('security');
  const [config, setConfig] = useState<Config>(DEFAULT_CONFIG);
  const [saved, setSaved] = useState<Config>(DEFAULT_CONFIG);
  const [isSaving, setIsSaving] = useState(false);
  const [toast, setToast] = useState('');

  // SMTP state
  const [smtpStatus, setSmtpStatus] = useState<{
    smtp_enabled: boolean;
    smtp_host: string | null;
    smtp_port?: number;
    smtp_user?: string | null;
    smtp_sender?: string | null;
    smtp_starttls?: boolean;
    admin_alert_emails?: string[];
  } | null>(null);
  const [smtpTesting, setSmtpTesting] = useState(false);
  const [smtpResult, setSmtpResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const smtpEnabled = Boolean(smtpStatus?.smtp_enabled);
  const smtpAdminEmails = smtpStatus?.admin_alert_emails ?? [];

  useEffect(() => {
    // 1. Fetch SMTP status
    api.get('/system/smtp-status')
      .then(r => setSmtpStatus(r.data))
      .catch(() => setSmtpStatus({ smtp_enabled: false, smtp_host: null }));

    // 2. Fetch System Settings
    api.get('/system/settings')
      .then(r => {
        if (Object.keys(r.data).length > 0) {
          const merged = { ...DEFAULT_CONFIG, ...r.data };
          setConfig(merged);
          setSaved(merged);
        }
      })
      .catch(err => {
        console.error('Failed to load settings:', err);
      });
  }, []);

  const handleSmtpTest = async () => {
    setSmtpTesting(true);
    setSmtpResult(null);
    try {
      const res = await api.post('/system/smtp-test');
      setSmtpResult({ ok: true, msg: res.data.message });
    } catch (err: unknown) {
      const message = typeof err === 'object' && err && 'response' in err
        ? (err as { response?: { data?: { error?: string } } }).response?.data?.error
        : undefined;
      setSmtpResult({ ok: false, msg: message || 'SMTP test failed' });
    } finally {
      setSmtpTesting(false);
    }
  };

  const isDirty = JSON.stringify(config) !== JSON.stringify(saved);
  const set = useCallback(<K extends keyof Config>(key: K, value: Config[K]) => {
    setConfig(prev => ({ ...prev, [key]: value }));
    logEvent('setting_changed_draft', `User modified draft setting: ${key}`, { key, value });
  }, []);


  const handleSave = async () => {
    setIsSaving(true);
    try {
      // 1. Save to backend
      await api.post('/system/settings', config);
      
      // 2. Update local state
      setSaved(config);
      setToast('Settings saved successfully');
      logEvent('settings_saved', 'User saved system settings to backend', { config });
      setTimeout(() => setToast(''), 3000);
    } catch (err: any) {
      console.error('Failed to save settings:', err);
      const msg = err.response?.data?.detail || 'Failed to save settings';
      alert(msg);
    } finally {
      setIsSaving(false);
    }
  };

  const handleDiscard = () => { setConfig(saved); };

  const isAdmin = user?.role === 'admin' || user?.role === 'owner';

  return (
    <div className="flex gap-6 h-full min-h-0 pb-16">
      {/* Sidebar Nav */}
      <div className="w-52 shrink-0">
        <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest mb-3 px-2">Settings</p>
        <nav className="space-y-0.5">
          {NAV.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                activeTab === item.id
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 space-y-5 overflow-y-auto min-h-0">
        {/* ─── PROFILE ──────────────────────────────────── */}
        {activeTab === 'profile' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Profile</h1>
              <p className="text-slate-400 text-sm mt-1">Your account information and session status</p>
            </div>
            <Section title="Account Information" icon="👤">
              <SettingRow label="Email Address" description="Your registered email address">
                <span className="text-sm text-slate-300 font-mono">{user?.email || '—'}</span>
              </SettingRow>
              <SettingRow label="Role" description="Your access level in this system">
                <span className={`text-xs px-2 py-1 rounded-full font-bold border ${
                  user?.role === 'admin' ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' :
                  'bg-blue-500/20 text-blue-400 border-blue-500/30'
                }`}>{(user?.role || 'user').toUpperCase()}</span>
              </SettingRow>
              <SettingRow label="User ID" description="Your system identifier">
                <span className="text-xs text-slate-500 font-mono">#{user?.id}</span>
              </SettingRow>
            </Section>

            <Section title="Session & Security" icon="🛡️">
              <SettingRow label="Active Session Timeout" description="Auto-logout after this period of inactivity">
                <NumberInput value={config.sessionTimeoutHours} onChange={v => set('sessionTimeoutHours', v)} min={1} max={168} unit="hours" />
              </SettingRow>
              <SettingRow label="Multi-Factor Authentication" description="Require extra verification on every login" badge="2FA">
                <Toggle checked={config.mfaEnabled} onChange={v => set('mfaEnabled', v)} />
              </SettingRow>
            </Section>
          </>
        )}

        {/* ─── SECURITY ─────────────────────────────────── */}
        {activeTab === 'security' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Security Policies</h1>
              <p className="text-slate-400 text-sm mt-1">Define brute-force protection, lockout thresholds, and identity tracking</p>
            </div>
            <Section title="Brute Force & Lockout" icon="🔒">
              <SettingRow label="Login Failure Threshold" description="Number of failures before account/IP is temporarily blocked">
                <NumberInput value={config.bruteForceThreshold} onChange={v => set('bruteForceThreshold', v)} min={2} max={20} unit="attempts" />
              </SettingRow>
              <SettingRow label="Failure Window" description="Reset failure count after this period">
                <NumberInput value={config.loginFailureWindowMins} onChange={v => set('loginFailureWindowMins', v)} min={1} max={1440} unit="min" />
              </SettingRow>
              <SettingRow label="Session Timeout" description="Force logout after this period of inactivity">
                <NumberInput value={config.sessionTimeoutHours} onChange={v => set('sessionTimeoutHours', v)} min={1} max={168} unit="hrs" />
              </SettingRow>
            </Section>

            <Section title="Identity & Authentication" icon="🔑">
              <SettingRow label="Multi-Factor Authentication" description="Require extra verification on every login attempt" badge="RECOMMENDED">
                <Toggle checked={config.mfaEnabled} onChange={v => set('mfaEnabled', v)} />
              </SettingRow>
              <SettingRow label="Geolocation Tracking" description="Track country/city per login event for anomaly detection">
                <Toggle checked={config.geoTrackingEnabled} onChange={v => set('geoTrackingEnabled', v)} />
              </SettingRow>
            </Section>
          </>
        )}

        {/* ─── ACCESS CONTROL ───────────────────────────── */}
        {activeTab === 'access' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Access Control Policies</h1>
              <p className="text-slate-400 text-sm mt-1">Zero-trust rules for who can see and download your files</p>
            </div>

            <Section title="File Access Policy" icon="📁">
              <SettingRow label="Default File Visibility" description="All new uploads start as PRIVATE and inaccessible by default">
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-semibold ${config.defaultFilePrivate ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {config.defaultFilePrivate ? 'PRIVATE' : 'SHARED'}
                  </span>
                  <Toggle checked={config.defaultFilePrivate} onChange={v => set('defaultFilePrivate', v)} />
                </div>
              </SettingRow>
              <SettingRow label="Require Approval for Download" description="Recipients must request access; owner must manually approve before any download">
                <Toggle checked={config.requireApprovalForDownload} onChange={v => set('requireApprovalForDownload', v)} />
              </SettingRow>
            </Section>

            <Section title="Secure Link Settings" icon="🔗">
              <SettingRow label="Default Link Expiry" description="Share links expire automatically after this period">
                <NumberInput value={config.secureLinkExpiryHours} onChange={v => set('secureLinkExpiryHours', v)} min={1} max={720} unit="hours" />
              </SettingRow>
              <SettingRow label="Max Downloads per Link" description="Link becomes invalid after this many downloads (0 = unlimited)">
                <NumberInput value={config.secureLinkMaxDownloads} onChange={v => set('secureLinkMaxDownloads', v)} min={0} max={1000} unit="times" />
              </SettingRow>
            </Section>

            <Section title="Blocklist" icon="🚫">
              <div className="py-4">
                <p className="text-sm font-medium text-slate-200 mb-1">Blocked Email Addresses / Domains</p>
                <p className="text-xs text-slate-500 mb-3">These identities are permanently denied all access. Use @domain.com to block an entire domain.</p>
                <TagInput tags={config.blockedEmails} onChange={v => set('blockedEmails', v)} placeholder="user@example.com or @domain.com" validate={isEmail} />
              </div>
              <div className="py-4">
                <p className="text-sm font-medium text-slate-200 mb-1">Blocked IP Addresses / CIDR Ranges</p>
                <p className="text-xs text-slate-500 mb-3">Block specific IPs or ranges from accessing any endpoint. e.g. 192.168.1.1 or 10.0.0.0/8</p>
                <TagInput tags={config.blockedIPs} onChange={v => set('blockedIPs', v)} placeholder="192.168.1.1 or 10.0.0.0/8" validate={isIP} />
              </div>
            </Section>

            <Section title="Allowlist" icon="✅">
              <div className="py-4">
                <p className="text-sm font-medium text-slate-200 mb-1">Trusted Email Domains</p>
                <p className="text-xs text-slate-500 mb-3">Only users from these domains can request file access. Leave empty to allow all.</p>
                <TagInput tags={config.allowedDomains} onChange={v => set('allowedDomains', v)} placeholder="@company.com" validate={(v) => v.startsWith('@')} />
              </div>
            </Section>
          </>
        )}

        {/* ─── NOTIFICATIONS ────────────────────────────── */}
        {activeTab === 'notifications' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Alerts & Notifications</h1>
              <p className="text-slate-400 text-sm mt-1">Configure when and how you receive security alerts</p>
            </div>
            <Section title="Email Alert Triggers" icon="📧">
              <SettingRow label="Failed Login Attempts" description="Send alert when someone fails to log in">
                <Toggle checked={config.emailOnFailedLogin} onChange={v => set('emailOnFailedLogin', v)} />
              </SettingRow>
              <SettingRow label="Suspicious Activity" description="Alert on anomalous access patterns, new geolocation, or unusual hours">
                <Toggle checked={config.emailOnSuspiciousActivity} onChange={v => set('emailOnSuspiciousActivity', v)} />
              </SettingRow>
              <SettingRow label="File Access Requests" description="Notify when someone requests access to your files">
                <Toggle checked={config.emailOnFileAccess} onChange={v => set('emailOnFileAccess', v)} />
              </SettingRow>
            </Section>

            <Section title="Alert Thresholds" icon="⚡">
              <SettingRow label="Failure Count Before Alert" description="Send alert only after this many failed attempts (prevents noise)">
                <NumberInput value={config.alertThreshold} onChange={v => set('alertThreshold', v)} min={1} max={20} unit="attempts" />
              </SettingRow>
            </Section>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
              <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${smtpStatus?.smtp_enabled ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
              <p className="text-sm text-slate-300">
                SMTP is <strong className={smtpStatus?.smtp_enabled ? 'text-emerald-400' : 'text-red-400'}>
                  {smtpStatus === null ? 'checking...' : smtpStatus.smtp_enabled ? 'configured and active' : 'not configured'}
                </strong>
                {smtpStatus?.smtp_host && <span className="text-slate-500 text-xs ml-2">via {smtpStatus.smtp_host}</span>}
              </p>
            </div>
          </>
        )}

        {/* ─── SMTP ─────────────────────────────────────── */}
        {activeTab === 'smtp' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Email / SMTP Configuration</h1>
              <p className="text-slate-400 text-sm mt-1">Live status of your mail delivery system</p>
            </div>

            {/* Status card */}
            <div className={`rounded-xl border p-5 flex items-start gap-4 ${
              smtpStatus?.smtp_enabled
                ? 'bg-emerald-500/5 border-emerald-500/20'
                : 'bg-red-500/5 border-red-500/20'
            }`}>
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-xl shrink-0 ${
                smtpEnabled ? 'bg-emerald-500/15' : 'bg-red-500/15'
              }`}>
                {smtpStatus === null ? '⏳' : smtpEnabled ? '✅' : '❌'}
              </div>
              <div>
                <p className={`font-bold text-sm ${smtpEnabled ? 'text-emerald-400' : 'text-red-400'}`}>
                  {smtpStatus === null ? 'Checking SMTP status...' : smtpEnabled ? 'SMTP is Active' : 'SMTP is Disabled'}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">
                  {smtpEnabled
                    ? 'Email alerts and notifications are fully operational.'
                    : 'Set SMTP_ENABLED=true in your .env file to enable email delivery.'}
                </p>
              </div>
            </div>

            {/* Config details */}
            {smtpStatus && (
              <Section title="Current Configuration" icon="⚙️">
                {[
                  { label: 'SMTP Host', value: smtpStatus.smtp_host || '—' },
                  { label: 'Port', value: smtpStatus.smtp_port || '—' },
                  { label: 'Auth User', value: smtpStatus.smtp_user || '—' },
                  { label: 'Sender Address', value: smtpStatus.smtp_sender || '—' },
                  { label: 'STARTTLS', value: smtpStatus.smtp_starttls ? 'Enabled' : 'Disabled' },
                ].map(item => (
                  <SettingRow key={item.label} label={item.label} description="">
                    <span className="text-sm font-mono text-slate-300">{String(item.value)}</span>
                  </SettingRow>
                ))}
              </Section>
            )}

            {/* Admin recipients */}
            {smtpAdminEmails.length > 0 && (
              <Section title="Alert Recipients" icon="📬">
                <div className="py-4">
                  <p className="text-xs text-slate-500 mb-3">Security alerts and reports are sent to these addresses:</p>
                  <div className="flex flex-wrap gap-2">
                    {smtpAdminEmails.map((email: string) => (
                      <span key={email} className="inline-flex items-center gap-1.5 bg-slate-800 border border-slate-700 text-slate-300 text-xs px-3 py-1.5 rounded-full">
                        <EnvelopeIcon className="w-3 h-3 text-blue-400" /> {email}
                      </span>
                    ))}
                  </div>
                </div>
              </Section>
            )}

            {/* Test Email */}
            <Section title="Test Email Delivery" icon="📤">
              <div className="py-4 space-y-4">
                <p className="text-xs text-slate-400">
                  Send a test email to your account address (<strong className="text-slate-300">{user?.email}</strong>) to verify end-to-end delivery.
                </p>

                <button
                  onClick={handleSmtpTest}
                  disabled={smtpTesting || !smtpEnabled}
                  className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all"
                >
                  {smtpTesting
                    ? <><svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg> Sending...</>
                    : <><EnvelopeIcon className="w-4 h-4" /> Send Test Email</>
                  }
                </button>

                {smtpResult && (
                  <div className={`flex items-start gap-3 rounded-xl border p-4 ${
                    smtpResult.ok
                      ? 'bg-emerald-500/5 border-emerald-500/20'
                      : 'bg-red-500/5 border-red-500/20'
                  }`}>
                    {smtpResult.ok
                      ? <CheckCircleIcon className="w-5 h-5 text-emerald-400 shrink-0" />
                      : <XCircleIcon className="w-5 h-5 text-red-400 shrink-0" />
                    }
                    <div>
                      <p className={`text-sm font-semibold ${smtpResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                        {smtpResult.ok ? 'Test email sent!' : 'Test failed'}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">{smtpResult.msg}</p>
                    </div>
                  </div>
                )}

                {!smtpEnabled && (
                  <div className="bg-amber-900/20 border border-amber-700/30 rounded-xl p-4">
                    <p className="text-amber-300 text-xs font-semibold mb-2">To enable email:</p>
                    <pre className="text-amber-400/80 text-xs font-mono leading-relaxed whitespace-pre-wrap">{`SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_SENDER=you@gmail.com
SMTP_STARTTLS=true
ADMIN_ALERT_EMAILS=admin@yourcompany.com`}</pre>
                  </div>
                )}
              </div>
            </Section>
          </>
        )}

        {/* ─── LOGS & REPORTS ───────────────────────────── */}
        {activeTab === 'logs' && (
          <LogsReportsTab
            config={config}
            set={(key, value) => {
              set(key, value as Config[typeof key]);
            }}
          />
        )}

        {/* ─── ADVANCED SECURITY ────────────────────────── */}
        {activeTab === 'advanced' && (
          <>
            <div>
              <h1 className="text-xl font-bold text-white">Advanced Security</h1>
              <p className="text-slate-400 text-sm mt-1">Enterprise threat detection, honeypot traps, and risk engine configuration</p>
            </div>

            {!isAdmin && (
              <div className="bg-amber-900/20 border border-amber-700/30 rounded-xl px-4 py-3">
                <p className="text-amber-300 text-sm font-semibold">Admin access required to modify these settings</p>
              </div>
            )}

            <Section title="Threat Detection Engine" icon="🔍">
              <SettingRow label="Anomaly Detection" description="Flag logins from new countries, unusual hours, or abnormal download volume" badge="AI">
                <Toggle checked={config.anomalyDetectionEnabled} onChange={v => set('anomalyDetectionEnabled', v)} disabled={!isAdmin} />
              </SettingRow>
              <SettingRow label="Risk Scoring" description="Assign a 0–10 risk score to every security event based on severity, action, and context">
                <Toggle checked={config.riskScoringEnabled} onChange={v => set('riskScoringEnabled', v)} disabled={!isAdmin} />
              </SettingRow>
            </Section>

            <Section title="Honeypot System" icon="🍯">
              <SettingRow label="Enable Honeypot Files" description="Plant decoy /system/admin-keys.pem endpoint — any access triggers a CRITICAL security event" badge="TRAP">
                <Toggle checked={config.honeypotEnabled} onChange={v => set('honeypotEnabled', v)} disabled={!isAdmin} />
              </SettingRow>
            </Section>

            <Section title="Automation Rules" icon="⚙️">
              <div className="py-4 space-y-3">
                {[
                  { condition: `Failed logins > ${config.bruteForceThreshold}`, action: 'Block IP + send email alert', active: true },
                  { condition: 'Login from new country', action: 'Flag as suspicious + log anomaly event', active: config.anomalyDetectionEnabled },
                  { condition: 'Honeypot URL accessed', action: 'Log CRITICAL event + optional IP block', active: config.honeypotEnabled },
                  { condition: 'File download > 10×', action: 'Upgrade file risk to MEDIUM', active: config.riskScoringEnabled },
                ].map((rule, i) => (
                  <div key={i} className={`flex items-start gap-3 p-3 rounded-lg border ${rule.active ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-800/50 border-slate-700 opacity-50'}`}>
                    <span className={`text-xs font-bold mt-0.5 ${rule.active ? 'text-emerald-400' : 'text-slate-600'}`}>
                      {rule.active ? '▶ ACTIVE' : '○ OFF'}
                    </span>
                    <div>
                      <p className="text-xs text-slate-300 font-mono"><span className="text-amber-400">IF</span> {rule.condition}</p>
                      <p className="text-xs text-slate-400 font-mono"><span className="text-blue-400">THEN</span> {rule.action}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          </>
        )}
      </div>

      {/* Save Bar */}
      <SaveBar isDirty={isDirty} isSaving={isSaving} onSave={handleSave} onDiscard={handleDiscard} />

      {/* Success Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 bg-emerald-900/90 border border-emerald-700 text-emerald-200 px-4 py-3 rounded-xl shadow-2xl flex items-center gap-2 text-sm font-medium">
          <CheckCircleIcon className="w-4 h-4" /> {toast}
        </div>
      )}
    </div>
  );
};
