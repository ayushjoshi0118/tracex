import React, { useEffect, useState } from 'react';
import { 
  FolderGit2, 
  Archive, 
  ShieldAlert, 
  CheckCircle2, 
  FileSearch, 
  Globe, 
  Mail, 
  Network,
  ArrowRight,
  ShieldCheck,
  Cpu,
  Lock
} from 'lucide-react';
import { MetricCard } from '../components/MetricCard';
import { StatusBadge } from '../components/StatusBadge';
import { investigationsApi, evidenceApi } from '../services/api';
import { InvestigationSummary, EvidenceItem } from '../types';

interface DashboardProps {
  onNavigate: (tab: string, contextId?: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [invs, evs] = await Promise.all([
        investigationsApi.list(),
        evidenceApi.list()
      ]);
      setInvestigations(invs);
      setEvidenceList(evs);
    } catch (err) {
      console.error('Failed to load dashboard telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  const activeCasesCount = investigations.filter(i => i.status === 'active').length;
  const verifiedEvidenceCount = evidenceList.filter(e => e.integrity_status === 'verified').length;

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Top Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0d1728] via-[#09121f] to-[#0a1820] border border-cyan-900/40 p-6 md:p-8">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center space-x-2 px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-800/60 text-cyan-400 text-xs font-mono">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>DEFENSIVE FORENSIC COMMAND CENTER</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-black font-mono text-slate-100 tracking-tight">
              TRACEX FORENSICS PLATFORM
            </h1>
            <p className="text-sm text-slate-400 max-w-2xl">
              Strictly non-destructive digital investigation ecosystem. Extract cryptographic baselines, inspect unexecuted artifacts, trace attack relays, and maintain an immutable Chain of Custody ledger.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => onNavigate('files')}
              className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-2 transition-all shadow-[0_0_20px_rgba(6,182,212,0.3)]"
            >
              <FileSearch className="w-4 h-4" />
              <span>Analyze Artifact</span>
            </button>
            <button
              onClick={() => onNavigate('intel')}
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs font-mono flex items-center space-x-2 border border-slate-700 transition-all"
            >
              <Globe className="w-4 h-4" />
              <span>IOC Lookup</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Active Investigations"
          value={activeCasesCount}
          subValue={`${investigations.length} Total Dossiers Registered`}
          icon={FolderGit2}
          variant="cyan"
        />
        <MetricCard
          label="Seized Evidence Items"
          value={evidenceList.length}
          subValue="Isolated in Quarantine Vault"
          icon={Archive}
          variant="slate"
        />
        <MetricCard
          label="Cryptographic Verification"
          value={`${verifiedEvidenceCount}/${evidenceList.length || 0}`}
          subValue="100% SHA-256 Baseline Match"
          icon={CheckCircle2}
          variant="emerald"
        />
        <MetricCard
          label="Threat Intelligence Feeds"
          value="4 Connected"
          subValue="VT, AbuseIPDB, OTX, Curated DB"
          icon={ShieldAlert}
          variant="amber"
        />
      </div>

      {/* Quick Launch Triage Bar */}
      <div className="bg-[#0b121e] border border-slate-800/80 rounded-xl p-4">
        <p className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-2">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Forensic Analysis Modules</span>
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <button
            onClick={() => onNavigate('files')}
            className="flex items-center space-x-3 p-3 rounded-lg bg-[#0e1626] hover:bg-[#142036] border border-slate-800 hover:border-cyan-500/40 text-left transition-all group"
          >
            <div className="p-2 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 group-hover:scale-105 transition-transform">
              <FileSearch className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-mono font-bold text-slate-200">File Forensics</p>
              <p className="text-[10px] text-slate-400">Entropy, Mismatch, YARA</p>
            </div>
          </button>

          <button
            onClick={() => onNavigate('email')}
            className="flex items-center space-x-3 p-3 rounded-lg bg-[#0e1626] hover:bg-[#142036] border border-slate-800 hover:border-emerald-500/40 text-left transition-all group"
          >
            <div className="p-2 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 group-hover:scale-105 transition-transform">
              <Mail className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-mono font-bold text-slate-200">Email Forensics</p>
              <p className="text-[10px] text-slate-400">SPF/DKIM/DMARC & Hops</p>
            </div>
          </button>

          <button
            onClick={() => onNavigate('network')}
            className="flex items-center space-x-3 p-3 rounded-lg bg-[#0e1626] hover:bg-[#142036] border border-slate-800 hover:border-blue-500/40 text-left transition-all group"
          >
            <div className="p-2 rounded bg-blue-950/60 border border-blue-800/40 text-blue-400 group-hover:scale-105 transition-transform">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-mono font-bold text-slate-200">PCAP Inspector</p>
              <p className="text-[10px] text-slate-400">DNS & HTTP Conversations</p>
            </div>
          </button>

          <button
            onClick={() => onNavigate('evidence')}
            className="flex items-center space-x-3 p-3 rounded-lg bg-[#0e1626] hover:bg-[#142036] border border-slate-800 hover:border-amber-500/40 text-left transition-all group"
          >
            <div className="p-2 rounded bg-amber-950/60 border border-amber-800/40 text-amber-400 group-hover:scale-105 transition-transform">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <p className="text-xs font-mono font-bold text-slate-200">Chain of Custody</p>
              <p className="text-[10px] text-slate-400">Auditable Ledger Audit</p>
            </div>
          </button>
        </div>
      </div>

      {/* Main Grid: Active Cases & Evidence Vault */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Active Investigations (2 Cols) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-mono uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <FolderGit2 className="w-4 h-4 text-cyan-400" />
              <span>Active Investigation Dossiers</span>
            </h2>
            <button
              onClick={() => onNavigate('investigations')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
            >
              <span>View All</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {investigations.map((inv) => (
              <div
                key={inv.id}
                onClick={() => onNavigate('investigations', inv.id)}
                className="p-4 rounded-xl bg-[#0c1322] border border-slate-800/90 hover:border-cyan-500/40 transition-all cursor-pointer group space-y-3"
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">{inv.id}</span>
                      <StatusBadge status={inv.priority} size="sm" />
                      <StatusBadge status={inv.status} size="sm" />
                    </div>
                    <h3 className="text-sm font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors mt-1">
                      {inv.title}
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">
                    Lead: {inv.lead_analyst}
                  </span>
                </div>

                {inv.description && (
                  <p className="text-xs text-slate-400 line-clamp-2">
                    {inv.description}
                  </p>
                )}

                <div className="flex items-center space-x-6 text-[11px] font-mono text-slate-500 border-t border-slate-800/60 pt-2.5">
                  <span>Artifacts: <strong className="text-slate-300">{inv.evidence_count}</strong></span>
                  <span>IOCs: <strong className="text-slate-300">{inv.ioc_count}</strong></span>
                  <span>Timeline Milestones: <strong className="text-slate-300">{inv.timeline_event_count}</strong></span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Evidence Vault Highlights (1 Col) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-mono uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <Archive className="w-4 h-4 text-emerald-400" />
              <span>Evidence Vault Status</span>
            </h2>
            <button
              onClick={() => onNavigate('evidence')}
              className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center space-x-1"
            >
              <span>Locker</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="bg-[#0c1322] border border-slate-800/90 rounded-xl p-4 space-y-3">
            <p className="text-xs text-slate-400">
              Recent seized artifacts placed in isolated quarantine. Each entry features an initial SHA-256 fingerprint.
            </p>

            <div className="space-y-2.5">
              {evidenceList.slice(0, 3).map((item) => (
                <div key={item.id} className="p-3 rounded-lg bg-[#090e18] border border-slate-800 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-slate-200 truncate max-w-[170px]">
                      {item.name}
                    </span>
                    <StatusBadge status={item.integrity_status} size="sm" />
                  </div>
                  <p className="text-[10px] font-mono text-slate-500 truncate">
                    ID: {item.id} | Size: {item.file_size_bytes} B
                  </p>
                  <p className="text-[10px] font-mono text-cyan-400/80 truncate">
                    SHA-256: {item.sha256.slice(0, 24)}...
                  </p>
                </div>
              ))}
            </div>

            <div className="pt-2 border-t border-slate-800">
              <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-800/40 text-[11px] text-emerald-300 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Auditable bit-rot and tamper detection active across physical storage.</span>
              </div>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
};
