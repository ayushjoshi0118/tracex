import React from 'react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md' | 'lg';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'sm' }) => {
  const norm = (status || '').toLowerCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (norm.includes('critical') || norm.includes('malicious') || norm.includes('fail') || norm.includes('compromised')) {
    colorClasses = 'bg-rose-950/40 text-rose-400 border-rose-800/60';
    dotColor = 'bg-rose-400';
  } else if (norm.includes('high') || norm.includes('suspicious') || norm.includes('softfail')) {
    colorClasses = 'bg-amber-950/40 text-amber-300 border-amber-800/60';
    dotColor = 'bg-amber-400';
  } else if (norm.includes('verified') || norm.includes('pass') || norm.includes('clean') || norm.includes('active')) {
    colorClasses = 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60';
    dotColor = 'bg-emerald-400';
  } else if (norm.includes('missing') || norm.includes('unverified')) {
    colorClasses = 'bg-slate-800/80 text-slate-400 border-slate-700';
    dotColor = 'bg-slate-500';
  } else if (norm.includes('info') || norm.includes('neutral') || norm.includes('medium')) {
    colorClasses = 'bg-cyan-950/40 text-cyan-400 border-cyan-800/60';
    dotColor = 'bg-cyan-400';
  }

  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-xs' : size === 'md' ? 'px-2.5 py-0.5 text-[11px]' : 'px-2 py-0.5 text-[10px]';

  return (
    <span className={`inline-flex items-center space-x-1.5 font-mono font-medium rounded-full border ${sizeClasses} ${colorClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      <span className="uppercase tracking-wider">{status}</span>
    </span>
  );
};
