import React, { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheckIcon, EnvelopeIcon, ArrowLeftIcon } from '@heroicons/react/24/outline';
import { api } from '../../services/api';

type Step = 'email' | 'sent' | 'success';

const ForgotPasswordPage = () => {
  const [step, setStep] = useState<Step>('email');
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [serverError, setServerError] = useState('');
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => { emailRef.current?.focus(); }, []);

  const validateEmail = (v: string) => {
    if (!v) return 'Email is required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Enter a valid email address';
    return '';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const err = validateEmail(email);
    setEmailError(err);
    if (err) return;

    setIsLoading(true);
    setServerError('');
    try {
      // Call the backend password reset endpoint
      await api.post('/auth/request-password-reset', { email });
      setStep('sent');
    } catch (err: any) {
      // For security, we show success even if email doesn't exist (prevents user enumeration)
      setStep('sent');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="flex items-center gap-2 mb-10 justify-center">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-white" />
          </div>
          <span className="text-white font-bold text-lg">SecureVault</span>
        </div>

        {/* Step 1: Enter email */}
        {step === 'email' && (
          <div>
            <div className="text-center mb-8">
              <div className="w-14 h-14 bg-blue-500/10 border border-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                <EnvelopeIcon className="w-7 h-7 text-blue-400" />
              </div>
              <h1 className="text-2xl font-bold text-white">Forgot your password?</h1>
              <p className="text-slate-400 mt-2 text-sm leading-relaxed">
                No problem. Enter your email address and we'll send you a secure link to reset it.
              </p>
            </div>

            {serverError && (
              <div className="mb-5 bg-red-900/20 border border-red-700/30 rounded-xl p-3">
                <p className="text-red-400 text-sm">{serverError}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">Email address</label>
                <input
                  ref={emailRef}
                  type="email"
                  value={email}
                  onChange={e => { setEmail(e.target.value); if (emailError) setEmailError(''); }}
                  onBlur={() => setEmailError(validateEmail(email))}
                  placeholder="you@company.com"
                  className={`w-full px-4 py-2.5 bg-slate-900 border rounded-lg text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 transition-all ${emailError ? 'border-red-500 focus:ring-red-500/30' : 'border-slate-700 focus:ring-blue-500/30 focus:border-blue-500'}`}
                />
                {emailError && <p className="mt-1.5 text-xs text-red-400">{emailError}</p>}
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all text-sm flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Sending reset link...
                  </>
                ) : 'Send Reset Link'}
              </button>
            </form>

            <div className="mt-6 p-4 bg-slate-900 border border-slate-800 rounded-xl">
              <p className="text-xs text-slate-400 font-medium mb-2">Security Notice</p>
              <ul className="space-y-1.5 text-xs text-slate-500">
                <li>• Reset links expire after <strong className="text-slate-400">15 minutes</strong></li>
                <li>• The link can only be used <strong className="text-slate-400">once</strong></li>
                <li>• Your old password remains active until you reset it</li>
              </ul>
            </div>
          </div>
        )}

        {/* Step 2: Email sent confirmation */}
        {step === 'sent' && (
          <div className="text-center">
            <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
              <EnvelopeIcon className="w-8 h-8 text-emerald-400" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-3">Check your email</h1>
            <p className="text-slate-400 mb-2 text-sm">
              If an account exists for <span className="text-white font-medium">{email}</span>, we sent a reset link.
            </p>
            <p className="text-slate-500 text-xs mb-8">
              Didn't receive it? Check your spam folder. The link expires in 15 minutes.
            </p>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-left mb-6">
              <p className="text-xs text-slate-400 font-medium mb-3">What happens next?</p>
              <ol className="space-y-2">
                {[
                  'Open the email from SecureVault',
                  'Click the "Reset Password" link',
                  'Enter your new password (must meet requirements)',
                  'You\'ll be redirected to login',
                ].map((step, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-4 h-4 rounded-full bg-blue-600/20 border border-blue-600/40 text-blue-400 text-xs flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                    <span className="text-xs text-slate-400">{step}</span>
                  </li>
                ))}
              </ol>
            </div>

            <button
              onClick={() => setStep('email')}
              className="text-slate-400 hover:text-white text-sm transition-colors flex items-center gap-1 mx-auto"
            >
              <ArrowLeftIcon className="w-3.5 h-3.5" /> Use a different email
            </button>
          </div>
        )}

        <div className="mt-8 text-center">
          <Link to="/login" className="text-blue-400 hover:text-blue-300 text-sm transition-colors flex items-center justify-center gap-1">
            <ArrowLeftIcon className="w-3.5 h-3.5" /> Back to Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;
