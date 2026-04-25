import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from './AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { EyeIcon, EyeSlashIcon, ShieldCheckIcon, ExclamationTriangleIcon, LockClosedIcon } from '@heroicons/react/24/outline';

const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [lockCountdown, setLockCountdown] = useState(0);
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const emailRef = useRef<HTMLInputElement>(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    emailRef.current?.focus();
  }, []);

  useEffect(() => {
    if (lockCountdown > 0) {
      const timer = setTimeout(() => setLockCountdown(c => c - 1), 1000);
      return () => clearTimeout(timer);
    } else if (lockCountdown === 0 && isLocked) {
      setIsLocked(false);
      setFailedAttempts(0);
    }
  }, [lockCountdown, isLocked]);

  const validateEmail = (v: string) => {
    if (!v) return 'Email is required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Enter a valid email address';
    return '';
  };

  const validatePassword = (v: string) => {
    if (!v) return 'Password is required';
    return '';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const eErr = validateEmail(email);
    const pErr = validatePassword(password);
    setEmailError(eErr);
    setPasswordError(pErr);
    if (eErr || pErr) return;
    if (isLocked) return;

    setIsLoading(true);
    setError('');
    try {
      await login(email, password);
      navigate('/');
    } catch (err: unknown) {
      const status = typeof err === 'object' && err && 'response' in err
        ? (err as { response?: { status?: number } }).response?.status
        : undefined;
      const newAttempts = failedAttempts + 1;
      setFailedAttempts(newAttempts);

      if (status === 423 || newAttempts >= 5) {
        setIsLocked(true);
        setLockCountdown(300);
        setError('');
      } else if (status === 429) {
        setError('Too many requests. Please slow down.');
      } else if (status === 401) {
        setError('Invalid email or password.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex">
      {/* Left decorative panel */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-slate-900 via-blue-950 to-slate-900 flex-col justify-between p-12 border-r border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-white" />
          </div>
          <span className="text-white font-bold text-lg tracking-tight">SecureVault</span>
        </div>

        <div>
          <div className="mb-8 p-4 bg-slate-800/50 border border-slate-700 rounded-xl">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></div>
              <span className="text-xs text-emerald-400 font-semibold uppercase tracking-widest">All Systems Operational</span>
            </div>
            <p className="text-slate-400 text-sm">Threat monitoring, file encryption, and IAM services are running normally.</p>
          </div>

          <blockquote className="border-l-2 border-blue-500 pl-6 mb-6">
            <p className="text-slate-300 text-lg font-light leading-relaxed">
              "Enterprise-grade security doesn't have to compromise usability."
            </p>
          </blockquote>

          <div className="grid grid-cols-1 gap-3">
            {[
              { icon: '🔒', label: 'AES-256-GCM encryption at rest' },
              { icon: '🛡️', label: 'VirusTotal malware scanning on upload' },
              { icon: '📋', label: 'Tamper-proof audit log (hash chain)' },
              { icon: '🔑', label: 'Zero-knowledge architecture' },
            ].map(item => (
              <div key={item.label} className="bg-slate-800/30 border border-slate-700/50 rounded-lg px-4 py-2.5 flex items-center gap-3">
                <span className="text-base">{item.icon}</span>
                <span className="text-slate-300 text-sm">{item.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 text-slate-600 text-xs">
          <LockClosedIcon className="w-3 h-3" />
          <span>256-bit AES-GCM encryption · SOC 2 compliant · Zero-knowledge architecture</span>
        </div>
      </div>

      {/* Right: Login Form */}
      <div className="flex-1 flex items-center justify-center px-4 py-12">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="flex lg:hidden items-center gap-2 mb-8 justify-center">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <ShieldCheckIcon className="w-5 h-5 text-white" />
            </div>
            <span className="text-white font-bold text-lg">SecureVault</span>
          </div>

          <div className="mb-8">
            <h1 className="text-2xl font-bold text-white">Welcome back</h1>
            <p className="text-slate-400 mt-1">Sign in to access your encrypted vault</p>
          </div>

          {/* Locked out banner */}
          {isLocked && (
            <div className="mb-5 bg-red-900/30 border border-red-700/50 rounded-xl p-4 flex items-start gap-3">
              <LockClosedIcon className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-red-300 font-semibold text-sm">Account Temporarily Locked</p>
                <p className="text-red-400/80 text-xs mt-0.5">
                  Too many failed attempts. Try again in {Math.floor(lockCountdown / 60)}m {lockCountdown % 60}s.
                </p>
              </div>
            </div>
          )}

          {/* Suspicious activity warning */}
          {failedAttempts >= 3 && !isLocked && (
            <div className="mb-5 bg-amber-900/20 border border-amber-700/40 rounded-xl p-4 flex items-start gap-3">
              <ExclamationTriangleIcon className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-amber-300 font-semibold text-sm">Suspicious Activity Detected</p>
                <p className="text-amber-400/80 text-xs mt-0.5">
                  {failedAttempts} failed attempt{failedAttempts > 1 ? 's' : ''}. Account locks after 5 failures.
                </p>
              </div>
            </div>
          )}

          {/* General error */}
          {error && !isLocked && (
            <div className="mb-5 bg-red-900/20 border border-red-700/30 rounded-xl p-3">
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5" noValidate>
            {/* Email Field */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Email address</label>
              <input
                ref={emailRef}
                type="email"
                value={email}
                onChange={(e) => { setEmail(e.target.value); if (emailError) setEmailError(''); }}
                onBlur={() => setEmailError(validateEmail(email))}
                disabled={isLocked}
                placeholder="you@company.com"
                className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all ${emailError ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
              />
              {emailError && <p className="mt-1.5 text-xs text-red-400">{emailError}</p>}
            </div>

            {/* Password Field */}
            <div>
              <div className="flex justify-between items-center mb-1.5">
                <label className="block text-sm font-medium text-slate-300">Password</label>
                <Link to="/forgot-password" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">Forgot password?</Link>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); if (passwordError) setPasswordError(''); }}
                  onBlur={() => setPasswordError(validatePassword(password))}
                  disabled={isLocked}
                  placeholder="••••••••••"
                  className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all pr-10 ${passwordError ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
                />
                <button type="button" onClick={() => setShowPassword(s => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                  {showPassword ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
                </button>
              </div>
              {passwordError && <p className="mt-1.5 text-xs text-red-400">{passwordError}</p>}
            </div>

            {/* Remember me */}
            <div className="flex items-center gap-2">
              <input type="checkbox" id="remember" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} className="w-4 h-4 accent-blue-600 bg-slate-900 border-slate-600 rounded" />
              <label htmlFor="remember" className="text-sm text-slate-400 cursor-pointer">Remember me for 30 days</label>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={isLoading || isLocked}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all text-sm flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Authenticating...
                </>
              ) : 'Sign In'}
            </button>
          </form>

          <p className="text-center text-slate-500 text-sm mt-6">
            Don't have an account?{' '}
            <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">Create account</Link>
          </p>

          <div className="mt-8 pt-6 border-t border-slate-800 flex items-center justify-center gap-1.5 text-slate-600 text-xs">
            <LockClosedIcon className="w-3 h-3" />
            <span>Protected by end-to-end encryption</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
