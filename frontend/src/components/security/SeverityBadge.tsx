import React from 'react';
import { cn } from '../common/Button';

export const SeverityBadge = ({ severity }: { severity: 'low' | 'medium' | 'high' | 'critical' }) => {
  const colors = {
    low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    high: "bg-red-500/10 text-red-400 border-red-500/20",
    critical: "bg-red-600 text-white border-red-700 animate-pulse"
  };

  return (
    <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-semibold border", colors[severity])}>
      {severity.toUpperCase()}
    </span>
  );
};
