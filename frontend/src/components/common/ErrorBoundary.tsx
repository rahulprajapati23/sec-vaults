import React, { Component } from 'react';
import { ShieldExclamationIcon, ArrowPathIcon } from '@heroicons/react/24/outline';

interface State { hasError: boolean; error: string; }

export class ErrorBoundary extends Component<{ children: React.ReactNode }, State> {
  state = { hasError: false, error: '' };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error: error.message };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('ErrorBoundary caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[400px] text-center px-4">
          <div className="w-14 h-14 bg-red-500/10 border border-red-500/20 rounded-full flex items-center justify-center mb-4">
            <ShieldExclamationIcon className="w-7 h-7 text-red-400" />
          </div>
          <h2 className="text-lg font-bold text-white mb-2">Something went wrong</h2>
          <p className="text-slate-400 text-sm mb-1">{this.state.error}</p>
          <p className="text-slate-600 text-xs mb-6">Check the browser console for details.</p>
          <button
            onClick={() => { this.setState({ hasError: false, error: '' }); window.location.reload(); }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-all"
          >
            <ArrowPathIcon className="w-4 h-4" /> Reload Page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
