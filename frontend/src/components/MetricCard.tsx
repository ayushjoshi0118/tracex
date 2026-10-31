import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'emerald' | 'rose' | 'amber' | 'slate';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subValue,
  icon: Icon,
  variant = 'cyan'
}) => {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      bg: 'bg-gradient-to-br from-[#0c1626] to-[#0a101b]',
      iconBg: 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/40',
      text: 'text-cyan-400'
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      bg: 'bg-gradient-to-br from-[#0b1c18] to-[#0a101b]',
      iconBg: 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40',
      text: 'text-emerald-400'
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/40',
      bg: 'bg-gradient-to-br from-[#1c0c14] to-[#0a101b]',
      iconBg: 'bg-rose-950/60 text-rose-400 border border-rose-800/40',
      text: 'text-rose-400'
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      bg: 'bg-gradient-to-br from-[#1c160c] to-[#0a101b]',
      iconBg: 'bg-amber-950/60 text-amber-400 border border-amber-800/40',
      text: 'text-amber-400'
    },
    slate: {
      border: 'border-slate-800 hover:border-slate-700',
      bg: 'bg-[#0d1424]',
      iconBg: 'bg-slate-800 text-slate-300 border border-slate-700',
      text: 'text-slate-200'
    }
  };

  const scheme = colorMap[variant];

  return (
    <div className={`p-4 rounded-xl border ${scheme.border} ${scheme.bg} transition-all duration-200 shadow-sm flex items-start justify-between`}>
      <div>
        <p className="text-[11px] font-mono uppercase tracking-wider text-slate-400">{label}</p>
        <p className="text-2xl font-black font-mono mt-1 text-slate-100">{value}</p>
        {subValue && (
          <p className="text-[11px] text-slate-500 mt-1 font-mono">{subValue}</p>
        )}
      </div>
      <div className={`p-2.5 rounded-lg ${scheme.iconBg}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
};
