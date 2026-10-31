import React, { useState } from 'react';
import { 
  Globe, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  MapPin, 
  Server, 
  Clock, 
  Layers, 
  AlertOctagon,
  Copy,
  Check,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { threatIntelApi } from '../services/api';
import { ThreatIntelReport } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const ThreatIntelligence: React.FC = () => {
  const [iocInput, setIocInput] = useState<string>('185.220.101.5');
  const [loading, setLoading] = useState<boolean>(false);
  const [report, setReport] = useState<ThreatIntelReport | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const sampleIOCs = [
    { label: 'Tor Exit / Scanner IP', value: '185.220.101.5' },
    { label: 'C2 Team Server IP', value: '198.51.100.44' },
    { label: 'Phishing Harvester Domain', value: 'secure-login-update-account.com' },
    { label: 'Public DNS Resolver', value: '8.8.8.8' },
    { label: 'WannaCry SHA-256 Hash', value: 'ed01ebf83334a19373070b818de2e95a415239b6d3663a58d4e9d98717f782de' }
  ];

  const handleLookup = async (queryValue?: string) => {
    const target = queryValue || iocInput;
    if (!target.trim()) return;

    try {
      setLoading(true);
      setErrorMsg(null);
      const data = await threatIntelApi.lookup(target);
      setReport(data);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Threat intelligence query failed');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <Globe className="w-4 h-4" />
            <span>MODULE 02 // THREAT INTELLIGENCE & REPUTATION</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            IOC Investigation & Provenance
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlate IP addresses, domains, URLs, and file hashes against threat feeds with full provenance timestamps.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/50 text-cyan-300 text-xs font-mono">
          <Clock className="w-4 h-4" />
          <span>Real-time Intelligence Attribution</span>
        </div>
      </div>

      {/* Search Input Box */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-500" />
            <input
              type="text"
              value={iocInput}
              onChange={(e) => setIocInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
              placeholder="Enter IP (e.g. 185.220.101.5), Domain, URL, or SHA-256 Hash..."
              className="w-full bg-[#080d17] border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <button
            onClick={() => handleLookup()}
            disabled={loading}
            className="w-full sm:w-auto px-6 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center justify-center space-x-2 transition-all shrink-0 shadow-sm"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            <span>Investigate IOC</span>
          </button>
        </div>

        {/* Quick Sample Selector Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-slate-500">Fast Triage Vectors:</span>
          {sampleIOCs.map((sample) => (
            <button
              key={sample.value}
              onClick={() => {
                setIocInput(sample.value);
                handleLookup(sample.value);
              }}
              className="px-2.5 py-1 rounded-md bg-[#080d17] hover:bg-slate-800 border border-slate-800 text-[10px] font-mono text-slate-300 transition-colors flex items-center space-x-1"
            >
              <span>{sample.label}</span>
            </button>
          ))}
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Intelligence Report Display */}
      {report && (
        <div className="space-y-6">
          
          {/* Main Dossier Banner */}
          <div className="p-5 rounded-2xl bg-[#0c1424] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                  {report.ioc_type}
                </span>
                <StatusBadge status={report.score.risk_level} size="md" />
              </div>
              <div className="flex items-center space-x-3 mt-1">
                <h2 className="text-lg md:text-xl font-bold font-mono text-slate-100 select-all break-all">
                  {report.ioc_value}
                </h2>
                <button
                  onClick={() => copyToClipboard(report.ioc_value)}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-400 transition-colors"
                  title="Copy Indicator"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Classification: <strong className="text-slate-200">{report.score.classification}</strong>
              </p>
            </div>

            {/* Threat Dial / Score Box */}
            <div className="flex items-center space-x-4 bg-[#080d17] p-3 rounded-xl border border-slate-800">
              <div className="text-right">
                <p className="text-[10px] uppercase font-mono text-slate-400">Reputation Risk Score</p>
                <p className={`text-2xl font-black font-mono ${
                  report.score.reputation_score > 70 ? 'text-rose-400' :
                  report.score.reputation_score > 30 ? 'text-amber-400' : 'text-emerald-400'
                }`}>
                  {report.score.reputation_score} / 100
                </p>
              </div>
              <div className={`p-2.5 rounded-lg ${
                report.score.reputation_score > 70 ? 'bg-rose-950/60 text-rose-400 border border-rose-800/60' :
                report.score.reputation_score > 30 ? 'bg-amber-950/60 text-amber-400 border border-amber-800/60' :
                'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
              }`}>
                {report.score.reputation_score > 30 ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
              </div>
            </div>
          </div>

          {/* Grid: Context & Provenance */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* Geolocation & Network Infrastructure */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <MapPin className="w-4 h-4" />
                <span>Geographic & Autonomous System (ASN) Routing</span>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Country / Jurisdiction:</span>
                  <span className="text-slate-200 font-bold">
                    {report.geolocation?.country || 'Local / Non-Routable or Unmapped'} ({report.geolocation?.country_code || 'N/A'})
                  </span>
                </div>

                {report.geolocation?.city && (
                  <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">City Location:</span>
                    <span className="text-slate-200 font-bold">{report.geolocation.city}</span>
                  </div>
                )}

                <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Autonomous System:</span>
                  <span className="text-slate-200 font-bold">
                    {report.autonomous_system?.asn || 'Internal Network'}
                  </span>
                </div>

                {report.autonomous_system?.org && (
                  <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400">Hosting Provider / ISP:</span>
                    <span className="text-slate-200 font-bold truncate max-w-[200px]">
                      {report.autonomous_system.org}
                    </span>
                  </div>
                )}
              </div>

              {/* Threat Tags */}
              <div className="pt-2 border-t border-slate-800">
                <p className="text-[10px] font-mono uppercase text-slate-500 mb-2">Threat Categories & Campaign Tags:</p>
                <div className="flex flex-wrap gap-1.5">
                  {report.categories.map((c) => (
                    <span key={c} className="px-2 py-0.5 rounded bg-slate-800 text-[11px] font-mono text-cyan-300 border border-slate-700">
                      #{c}
                    </span>
                  ))}
                  {report.threat_actors_or_campaigns.map((a) => (
                    <span key={a} className="px-2 py-0.5 rounded bg-rose-950/50 text-[11px] font-mono text-rose-300 border border-rose-800/40">
                      [APT] {a}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* External Intelligence Provenance Log */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Layers className="w-4 h-4" />
                <span>External Source Provenance & Audit Trail</span>
              </div>

              <div className="space-y-3">
                {report.external_sources.map((src, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-[#080d17] border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-slate-200">{src.provider}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                        src.is_live_api ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'bg-slate-800 text-slate-400'
                      }`}>
                        {src.is_live_api ? 'LIVE API' : 'CURATED FEED'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 font-mono">{src.status}</p>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1">
                      <span>Retrieved: {new Date(src.retrieval_timestamp).toUTCString()}</span>
                      {src.source_url && (
                        <a
                          href={src.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                        >
                          <span>Evidence Ref</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
                <strong className="text-slate-300 block mb-1">Evidentiary Guarantee:</strong>
                All external results document their raw query timestamp and provider origin. TRACEX never fabricates threat reputation scores.
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
};
