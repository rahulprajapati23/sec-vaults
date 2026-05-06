import React, { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  EyeIcon, EyeSlashIcon, ShieldCheckIcon,
  CheckCircleIcon, XCircleIcon
} from '@heroicons/react/24/outline';
import { api } from '../../services/api';

interface PasswordRule { label: string; test: (p: string) => boolean; }
const PASSWORD_RULES: PasswordRule[] = [
  { label: 'At least 8 characters', test: (p) => p.length >= 8 },
  { label: 'One uppercase letter',  test: (p) => /[A-Z]/.test(p) },
  { label: 'One number',            test: (p) => /[0-9]/.test(p) },
  { label: 'One special character', test: (p) => /[^a-zA-Z0-9]/.test(p) },
];

const getStrength = (password: string) => {
  const score = PASSWORD_RULES.filter(r => r.test(password)).length;
  if (score <= 1) return { label: 'Weak',   color: 'bg-red-500',     width: 'w-1/4',  textColor: 'text-red-400' };
  if (score === 2) return { label: 'Fair',   color: 'bg-amber-500',   width: 'w-2/4',  textColor: 'text-amber-400' };
  if (score === 3) return { label: 'Good',   color: 'bg-blue-500',    width: 'w-3/4',  textColor: 'text-blue-400' };
  return              { label: 'Strong', color: 'bg-emerald-500', width: 'w-full', textColor: 'text-emerald-400' };
};

type Step = 'details' | 'success';

const RegisterPage = () => {
  // Step 1 — details
  const [email, setEmail]               = useState('');
  const [fullName, setFullName]         = useState('');
  const [password, setPassword]         = useState('');
  const [confirmPw, setConfirmPw]       = useState('');
  const [showPw, setShowPw]             = useState(false);
  const [showCPw, setShowCPw]           = useState(false);
  const [agreed, setAgreed]             = useState(false);
  const [errors, setErrors]             = useState<Record<string, string>>({});

  const [step, setStep]                 = useState<Step>('details');
  const [isLoading, setIsLoading]       = useState(false);
  const [serverError, setServerError]   = useState('');
  const nameRef = useRef<HTMLInputElement>(null);

  const strength      = password ? getStrength(password) : null;
  const allRulesPassed = password ? PASSWORD_RULES.every(r => r.test(password)) : false;

  useEffect(() => { nameRef.current?.focus(); }, []);
  

  const validateDetails = () => {
    const errs: Record<string, string> = {};
    if (!fullName.trim()) errs.fullName = 'Full name is required';
    if (!email)           errs.email    = 'Email is required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errs.email = 'Enter a valid email address';
    if (!password)        errs.password = 'Password is required';
    else if (!allRulesPassed) errs.password = 'Password does not meet requirements';
    if (password !== confirmPw) errs.confirmPw = 'Passwords do not match';
    if (!agreed)          errs.agreed   = 'You must accept the terms';
    return errs;
  };

  // Step 1 → create account
  const handleCreateAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError('');
    const errs = validateDetails();
    setErrors(errs);
    if (Object.keys(errs).length > 0) return;

    setIsLoading(true);
    try {
      const form = new URLSearchParams();
      form.append('email', email.trim().toLowerCase());
      form.append('password', password);
      form.append('full_name', fullName.trim());
      // Backend endpoint: POST /auth/register
      await api.post('/auth/register', form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      setStep('success');
    } catch (err: unknown) {
      const status = typeof err === 'object' && err && 'response' in err
        ? (err as { response?: { status?: number } }).response?.status
        : undefined;
      if (status === 400) {
        setServerError('This email is already registered. Please sign in.');
      } else {
        setServerError('Failed to create account. Try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  

  /* ─── SUCCESS ─────────────────────────────────────────────── */
  if (step === 'success') {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
        <div className="max-w-md w-full text-center">
          <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
            <CheckCircleIcon className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-3">Account Created!</h1>
          <p className="text-slate-400 mb-6 text-sm">Your email has been verified and your account is active. You can now sign in.</p>
          <Link to="/login" className="inline-flex items-center justify-center w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg transition-all text-sm">
            Sign in to your account →
          </Link>
        </div>
      </div>
    );
  }

  /* Registration is a single-step flow now */

  /* ─── STEP 1: DETAILS ─────────────────────────────────────── */
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-lg">
        <div className="flex items-center gap-2 mb-8 justify-center">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-white" />
          </div>
          <span className="text-white font-bold text-lg">SecureVault</span>
        </div>

        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold text-white">Create your account</h1>
          <p className="text-slate-400 mt-1 text-sm">Your email will be verified before the account is created</p>
        </div>

        {/* Steps indicator */}
        <div className="flex items-center gap-2 mb-8">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full bg-blue-600 flex items-center justify-center text-xs text-white font-bold">1</div>
            <span className="text-sm text-white font-medium">Your details</span>
          </div>
          <div className="flex-1 h-px bg-slate-700 mx-2"></div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center text-xs text-slate-400 font-bold">2</div>
            <span className="text-sm text-slate-500">Create account</span>
          </div>
        </div>

        {serverError && (
          <div className="mb-5 bg-red-900/20 border border-red-700/30 rounded-xl p-3">
            <p className="text-red-400 text-sm">{serverError}</p>
          </div>
        )}

        <form onSubmit={handleCreateAccount} className="space-y-4" noValidate>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Full Name *</label>
            <input
              ref={nameRef}
              type="text"
              value={fullName}
              onChange={e => { setFullName(e.target.value); setErrors(p => ({...p, fullName: ''})); }}
              placeholder="Jane Smith"
              className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all ${errors.fullName ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
            />
            {errors.fullName && <p className="mt-1 text-xs text-red-400">{errors.fullName}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Work Email *</label>
            <input
              type="email"
              value={email}
              onChange={e => { setEmail(e.target.value); setErrors(p => ({...p, email: ''})); }}
              placeholder="you@company.com"
              className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all ${errors.email ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
            />
            {errors.email && <p className="mt-1 text-xs text-red-400">{errors.email}</p>}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Password *</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                value={password}
                onChange={e => { setPassword(e.target.value); setErrors(p => ({...p, password: ''})); }}
                placeholder="••••••••••"
                className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all pr-10 ${errors.password ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
              />
              <button type="button" onClick={() => setShowPw(s => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                {showPw ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
              </button>
            </div>
            {errors.password && <p className="mt-1 text-xs text-red-400">{errors.password}</p>}
            {password && strength && (
              <div className="mt-2">
                <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div className={`h-full ${strength.color} ${strength.width} transition-all duration-500 rounded-full`} />
                </div>
                <p className={`text-xs mt-1 font-medium ${strength.textColor}`}>{strength.label} password</p>
              </div>
            )}
            {password && (
              <div className="mt-3 grid grid-cols-2 gap-1.5">
                {PASSWORD_RULES.map(rule => {
                  const passed = rule.test(password);
                  return (
                    <div key={rule.label} className="flex items-center gap-1.5">
                      {passed ? <CheckCircleIcon className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> : <XCircleIcon className="w-3.5 h-3.5 text-slate-600 shrink-0" />}
                      <span className={`text-xs ${passed ? 'text-emerald-400' : 'text-slate-500'}`}>{rule.label}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">Confirm Password *</label>
            <div className="relative">
              <input
                type={showCPw ? 'text' : 'password'}
                value={confirmPw}
                onChange={e => { setConfirmPw(e.target.value); setErrors(p => ({...p, confirmPw: ''})); }}
                placeholder="••••••••••"
                className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all pr-10 ${errors.confirmPw ? 'border-red-500 focus:ring-red-500/30' : confirmPw && confirmPw === password ? 'border-emerald-600' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
              />
              <button type="button" onClick={() => setShowCPw(s => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                {showCPw ? <EyeSlashIcon className="w-4 h-4" /> : <EyeIcon className="w-4 h-4" />}
              </button>
            </div>
            {errors.confirmPw && <p className="mt-1 text-xs text-red-400">{errors.confirmPw}</p>}
            {confirmPw && confirmPw === password && !errors.confirmPw && (
              <p className="mt-1 text-xs text-emerald-400 flex items-center gap-1"><CheckCircleIcon className="w-3.5 h-3.5" /> Passwords match</p>
            )}
          </div>

          <div>
            <div className="flex items-start gap-2">
              <input type="checkbox" id="terms" checked={agreed} onChange={e => { setAgreed(e.target.checked); setErrors(p => ({...p, agreed: ''})); }} className="mt-1 w-4 h-4 accent-blue-600 rounded" />
              <label htmlFor="terms" className="text-sm text-slate-400 cursor-pointer">
                I agree to the <a href="#" className="text-blue-400 hover:text-blue-300">Terms of Service</a> and <a href="#" className="text-blue-400 hover:text-blue-300">Privacy Policy</a>
              </label>
            </div>
            {errors.agreed && <p className="mt-1 text-xs text-red-400 ml-6">{errors.agreed}</p>}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all text-sm flex items-center justify-center gap-2 mt-2"
          >
            {isLoading ? (
              <><svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Creating account...</>
            ) : 'Create account →'}
          </button>
        </form>

        <p className="text-center text-slate-500 text-sm mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">Sign in</Link>
        </p>
      </div>
    </div>
  );
};

export default RegisterPage;
