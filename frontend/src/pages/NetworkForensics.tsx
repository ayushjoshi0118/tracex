import React, { useState } from 'react';
import { 
  Network, 
  Upload, 
  AlertTriangle, 
  ShieldCheck, 
  Activity, 
  Server, 
  Globe, 
  Terminal, 
  Layers,
  ArrowRightLeft,
  FileCode,
  ShieldAlert
} from 'lucide-react';
import { networkForensicsApi } from '../services/api';
import { NetworkForensicsResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const NetworkForensics: React.FC = () => {
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<NetworkForensicsResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'protocols' | 'dns' | 'http' | 'talkers'>('protocols');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleFileUpload = async (file: File) => {
    try {
      setAnalyzing(true);
      setErrorMsg(null);
      const res = await networkForensicsApi.analyzePcap(file);
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Network packet forensic analysis failed.');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <Network className="w-4 h-4" />
            <span>MODULE 04 // OFFLINE PCAP PACKET INSPECTOR</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            Network Forensics & Conversation Matrix
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Offline traffic dissection, protocol breakdowns, DNS tunneling detection, and cleartext credential extraction.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/50 text-emerald-400 text-xs font-mono">
          <ShieldCheck className="w-4 h-4" />
          <span>Passive Offline Analysis (No Active Scans)</span>
        </div>
      </div>

      {/* Upload Box */}
      <div className="border-2 border-dashed border-slate-800 hover:border-slate-700 bg-[#0a101b] rounded-2xl p-8 text-center transition-colors">
        <input
          type="file"
          id="pcapUpload"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />
        <label htmlFor="pcapUpload" className="cursor-pointer flex flex-col items-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-cyan-950/60 border border-cyan-800/40 flex items-center justify-center text-cyan-400">
            <Upload className="w-6 h-6 animate-pulse" />
          </div>
          <p className="text-sm font-semibold text-slate-200">
            Upload offline capture trace (.pcap, .pcapng, .cap)
          </p>
          <p className="text-xs text-slate-500 font-mono">
            Analyzes headers, sessions, DNS queries, and cleartext streams safely
          </p>
        </label>

        {analyzing && (
          <div className="mt-4 p-3 rounded-lg bg-cyan-950/40 text-cyan-400 text-xs font-mono flex items-center justify-center space-x-2">
            <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <span>Decoding packet headers, tracking talker IP matrices, and analyzing Shannon entropy...</span>
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          
          {/* Overview Metric Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
              <p className="text-[10px] font-mono uppercase text-slate-400">Total Packets Parsed</p>
              <p className="text-2xl font-black font-mono text-cyan-400 mt-1">
                {result.total_packets.toLocaleString()}
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Capture Size: {(result.file_size_bytes / 1024).toFixed(1)} KB</p>
            </div>

            <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
              <p className="text-[10px] font-mono uppercase text-slate-400">Duration Elapsed</p>
              <p className="text-2xl font-black font-mono text-emerald-400 mt-1">
                {result.capture_duration_seconds}s
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Stream Timeframe</p>
            </div>

            <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
              <p className="text-[10px] font-mono uppercase text-slate-400">DNS Inquiries</p>
              <p className="text-2xl font-black font-mono text-slate-200 mt-1">
                {result.dns_queries.length}
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Lookups Logged</p>
            </div>

            <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
              <p className="text-[10px] font-mono uppercase text-slate-400">Security Anomalies</p>
              <p className={`text-2xl font-black font-mono mt-1 ${
                result.anomalies.length > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {result.anomalies.length}
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Flagged Irregularities</p>
            </div>
          </div>

          {/* Anomalies Banner */}
          {result.anomalies.length > 0 && (
            <div className="bg-[#0c1322] border border-rose-900/50 rounded-xl p-5 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono text-rose-400 uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                <span>Detected Network Traffic Anomalies ({result.anomalies.length})</span>
              </div>

              <div className="space-y-2">
                {result.anomalies.map((anom, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-rose-950/20 border border-rose-800/40 flex items-start space-x-3 text-xs font-mono">
                    <StatusBadge status={anom.severity} size="sm" />
                    <div>
                      <p className="text-slate-100 font-bold">{anom.title}</p>
                      <p className="text-slate-300 mt-0.5">{anom.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Subtabs: Protocols, DNS, HTTP, Top Talkers */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              {[
                { id: 'protocols', label: 'Protocol Breakdown' },
                { id: 'talkers', label: 'Top Talkers' },
                { id: 'dns', label: `DNS Queries (${result.dns_queries.length})` },
                { id: 'http', label: `HTTP Streams (${result.http_requests.length})` },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                    activeTab === tab.id ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/60' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Protocols Tab */}
            {activeTab === 'protocols' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">
                  Distribution of packet frames by layer 3/4/7 protocol headers:
                </p>
                <div className="space-y-2.5">
                  {result.protocol_distribution.map((proto) => (
                    <div key={proto.protocol} className="p-3 rounded-lg bg-[#080d17] border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="font-bold text-slate-200">{proto.protocol}</span>
                        <span className="text-cyan-400 font-bold">{proto.percentage}% ({proto.packet_count} packets / {proto.byte_count} B)</span>
                      </div>
                      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-500 rounded-full"
                          style={{ width: `${proto.percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top Talkers Tab */}
            {activeTab === 'talkers' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">
                  Top IP endpoints generating or receiving byte volume in the capture:
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                        <th className="py-2.5 px-3">IP Address</th>
                        <th className="py-2.5 px-3">Packets Sent</th>
                        <th className="py-2.5 px-3">Packets Received</th>
                        <th className="py-2.5 px-3">Total Volume</th>
                        <th className="py-2.5 px-3">Associated Domains</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {result.top_talkers.map((talker) => (
                        <tr key={talker.ip} className="hover:bg-slate-900/50">
                          <td className="py-2 px-3 text-cyan-400 font-bold">{talker.ip}</td>
                          <td className="py-2 px-3">{talker.packets_sent}</td>
                          <td className="py-2 px-3">{talker.packets_received}</td>
                          <td className="py-2 px-3">{(talker.bytes_total / 1024).toFixed(1)} KB</td>
                          <td className="py-2 px-3 text-[11px] text-slate-400">
                            {talker.associated_domains.join(', ') || 'N/A'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* DNS Queries Tab */}
            {activeTab === 'dns' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">
                  DNS lookup timeline with Shannon entropy profiling for domain generation algorithms (DGA) and tunneling detection:
                </p>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {result.dns_queries.map((q, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-[#080d17] border border-slate-800 text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold">
                            {q.query_type}
                          </span>
                          <span className="font-bold text-slate-100">{q.query_name}</span>
                        </div>
                        <span className="text-[11px] text-slate-500">{q.timestamp}</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                        <span>Client: {q.client_ip} &rarr; Server: {q.server_ip}</span>
                        <span>Entropy: <strong className={q.entropy > 4.2 ? 'text-rose-400' : 'text-slate-300'}>{q.entropy}</strong></span>
                      </div>
                      {q.response_ips.length > 0 && (
                        <p className="text-[10px] text-emerald-400 truncate">
                          Resolved IPs: {q.response_ips.join(', ')}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* HTTP Inspector Tab */}
            {activeTab === 'http' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-400">
                  Decoded cleartext HTTP request lines, user-agents, and authorization headers:
                </p>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {result.http_requests.length > 0 ? (
                    result.http_requests.map((req, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-[#080d17] border border-slate-800 text-xs font-mono space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-cyan-300 font-bold">{req.request_line}</span>
                          {req.has_auth && (
                            <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800 text-[10px]">
                              CLEARTEXT AUTH PRESENT
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-slate-400">Host: {req.host} | Client: {req.client_ip}:{req.server_port}</p>
                        <p className="text-[10px] text-slate-500 truncate">UA: {req.user_agent}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-slate-500 italic p-4 text-center">No unencrypted HTTP frames found in capture trace</p>
                  )}
                </div>
              </div>
            )}

          </div>

        </div>
      )}

    </div>
  );
};
