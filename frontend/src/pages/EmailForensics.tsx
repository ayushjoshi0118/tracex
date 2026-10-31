import React, { useState } from 'react';
import { 
  Mail, 
  Upload, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  ArrowRight, 
  FileCode, 
  ExternalLink,
  Lock,
  Layers,
  Send,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { emailForensicsApi } from '../services/api';
import { EmailForensicsResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const EmailForensics: React.FC = () => {
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<EmailForensicsResponse | null>(null);
  const [rawText, setRawText] = useState<string>('');
  const [activeInputTab, setActiveInputTab] = useState<'upload' | 'paste'>('upload');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const samplePhishEml = `Received: from mail-relay-ext.suspicious-net.ru (mail-relay-ext.suspicious-net.ru [185.220.101.5])
    by mx.corporate-defense.com with ESMTP id 8F92AB12
    for <cfo@corporate-defense.com>; Fri, 30 Oct 2026 14:22:10 +0000
From: "Corporate Security Office" <security-alerts@corporate-defense.com>
Reply-To: "External Audit Team" <verify@secure-login-update-account.com>
To: <cfo@corporate-defense.com>
Subject: URGENT: Mandatory Executive Credential Verification Required Immediately
Date: Fri, 30 Oct 2026 14:21:40 +0000
Message-ID: <20261030142140.8A9F1B2C@corporate-defense.com>
Received-SPF: softfail (corporate-defense.com does not designate 185.220.101.5 as permitted sender)
Authentication-Results: mx.corporate-defense.com;
    spf=softfail;
    dkim=fail;
    dmarc=fail

ATTENTION CFO:

Our security platform detected an unauthorized login attempt against your executive workstation.
Please verify your corporate credentials immediately at:
http://185.220.101.5/auth/login.php?user=cfo@corporate-defense.com

Alternative verification mirror:
https://secure-login-update-account.com/sso/session-reset
`;

  const handleAnalyze = async (file?: File, text?: string) => {
    try {
      setAnalyzing(true);
      setErrorMsg(null);
      const res = await emailForensicsApi.analyzeEmail(file, text);
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Email forensic analysis failed.');
    } finally {
      setAnalyzing(false);
    }
  };

  const loadSample = () => {
    setActiveInputTab('paste');
    setRawText(samplePhishEml);
    handleAnalyze(undefined, samplePhishEml);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <Mail className="w-4 h-4" />
            <span>MODULE 03 // EMAIL FORENSICS & HEADER PARSER</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            Email Header & Authentication Analyzer
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deep RFC 822 parsing, SPF/DKIM/DMARC status evaluation, hop relay tracing, and URL defanging.
          </p>
        </div>

        <button
          onClick={loadSample}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-200 transition-colors flex items-center space-x-1.5"
        >
          <Send className="w-3.5 h-3.5 text-cyan-400" />
          <span>Load Sample Phishing EML</span>
        </button>
      </div>

      {/* Input Selection Tabs */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveInputTab('upload')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
              activeInputTab === 'upload' ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/60' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Upload .EML File
          </button>
          <button
            onClick={() => setActiveInputTab('paste')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
              activeInputTab === 'paste' ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/60' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Paste Raw Email Content
          </button>
        </div>

        {activeInputTab === 'upload' ? (
          <div className="border-2 border-dashed border-slate-800 rounded-xl p-8 text-center hover:border-slate-700 transition-colors">
            <input
              type="file"
              id="emlUpload"
              accept=".eml,.msg,.txt"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleAnalyze(e.target.files[0]);
                }
              }}
            />
            <label htmlFor="emlUpload" className="cursor-pointer flex flex-col items-center space-y-2">
              <Upload className="w-8 h-8 text-cyan-400" />
              <p className="text-xs font-mono text-slate-200">Click to upload raw .EML forensic message</p>
              <p className="text-[11px] text-slate-500 font-mono">RFC 822 standard email format</p>
            </label>
          </div>
        ) : (
          <div className="space-y-3">
            <textarea
              rows={8}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw email message headers and body here..."
              className="w-full bg-[#080d17] border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => handleAnalyze(undefined, rawText)}
              disabled={analyzing || !rawText.trim()}
              className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-2 transition-all"
            >
              <Mail className="w-4 h-4" />
              <span>Parse & Trace Headers</span>
            </button>
          </div>
        )}

        {analyzing && (
          <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/40 text-cyan-400 text-xs font-mono flex items-center space-x-2">
            <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <span>Analyzing hop latency, cryptographic auth headers, and link anchors...</span>
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="space-y-6">
          
          {/* Top Verdict Banner */}
          <div className="p-5 rounded-2xl bg-[#0c1424] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                  Subject
                </span>
                <StatusBadge status={result.verdict} size="md" />
              </div>
              <h2 className="text-lg font-bold font-mono text-slate-100 mt-1">
                {result.subject}
              </h2>
              <div className="flex flex-wrap gap-4 text-xs font-mono text-slate-400 pt-1">
                <span>From: <strong className="text-slate-200">{result.sender}</strong></span>
                {result.reply_to && (
                  <span>Reply-To: <strong className="text-slate-200">{result.reply_to}</strong></span>
                )}
                <span>Date: <strong className="text-slate-200">{result.date_sent || 'N/A'}</strong></span>
              </div>
            </div>

            {/* Phishing Risk Meter */}
            <div className="bg-[#080d17] p-3 rounded-xl border border-slate-800 text-right shrink-0">
              <p className="text-[10px] uppercase font-mono text-slate-400">Phishing Risk Score</p>
              <p className={`text-2xl font-black font-mono ${
                result.risk_score > 60 ? 'text-rose-400' :
                result.risk_score > 30 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {result.risk_score} / 100
              </p>
              <p className="text-[10px] font-mono text-slate-500">Heuristic Risk Index</p>
            </div>
          </div>

          {/* Authentication Results (SPF, DKIM, DMARC) */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
              <ShieldCheck className="w-4 h-4" />
              <span>Email Authentication Protocols (SPF / DKIM / DMARC)</span>
            </div>

            <p className="text-xs text-slate-400">
              TRACEX distinguishes strictly between <strong className="text-slate-200">Missing Configuration</strong> and <strong className="text-rose-400">Explicit Authentication Failure</strong>.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {result.auth_results.map((auth) => (
                <div
                  key={auth.protocol}
                  className={`p-4 rounded-xl border space-y-2 ${
                    auth.status_category === 'verified'
                      ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                      : auth.status_category === 'failed'
                      ? 'bg-rose-950/20 border-rose-800/40 text-rose-300'
                      : 'bg-slate-900 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold">{auth.protocol}</span>
                    <StatusBadge status={auth.status} size="sm" />
                  </div>
                  <p className="text-xs leading-relaxed">{auth.details}</p>
                  {auth.raw_header_value && (
                    <p className="text-[10px] font-mono opacity-60 truncate">
                      Raw: {auth.raw_header_value}
                    </p>
                  )}
                </div>
              ))}
            </div>

            {/* Sender / Reply-To Mismatch Alert */}
            {result.sender_reply_to_mismatch && (
              <div className="p-3.5 rounded-lg bg-rose-950/30 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-start space-x-3">
                <AlertCircle className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                <div>
                  <strong className="block text-rose-200 uppercase">BEC / Spoofing Alert: Domain Mismatch</strong>
                  The domain transmitting the message does not match the Reply-To target address. Replies will be routed to an external third-party inbox!
                </div>
              </div>
            )}
          </div>

          {/* Hop-by-Hop Relay Timeline */}
          {result.hops.length > 0 && (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Layers className="w-4 h-4" />
                <span>Hop-by-Hop Relay Transit Path ({result.hops.length} Relay Nodes)</span>
              </div>

              <div className="relative pl-6 border-l border-cyan-900/60 space-y-4 my-2">
                {result.hops.map((hop) => (
                  <div key={hop.hop_number} className="relative space-y-1">
                    <div className="absolute -left-[31px] top-1 w-3 h-3 rounded-full bg-cyan-500 border-2 border-[#0c1322]" />
                    <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-cyan-300">
                          Hop #{hop.hop_number}: {hop.from_server}
                        </span>
                        {hop.ip && (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            IP: {hop.ip}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400 font-mono">
                        Handled By Gateway: <span className="text-slate-300">{hop.by_server}</span>
                      </p>
                      {hop.timestamp_str && (
                        <p className="text-[10px] text-slate-500 font-mono">
                          Relay Time: {hop.timestamp_str}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Suspicious & Defanged URLs */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
              <ExternalLink className="w-4 h-4" />
              <span>Extracted & Defanged Links ({result.extracted_urls.length})</span>
            </div>

            <p className="text-xs text-slate-400">
              All hyperlinked destinations found in the message body are safely defanged (<code className="text-cyan-400">hxxp[://]</code>) to prevent accidental execution.
            </p>

            <div className="space-y-2">
              {result.extracted_urls.length > 0 ? (
                result.extracted_urls.map((link, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-[#080d17] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                    <div className="space-y-1 overflow-hidden">
                      <p className="text-cyan-300 select-all font-bold truncate">{link.defanged_url}</p>
                      <p className="text-slate-500 text-[11px]">Domain: {link.domain}</p>
                    </div>
                    <StatusBadge status={link.potential_risk} size="sm" />
                  </div>
                ))
              ) : (
                <p className="text-xs text-slate-500 italic p-3 text-center">No hyperlinks found in message body</p>
              )}
            </div>
          </div>

          {/* Phishing Indicators & Observations */}
          {result.phishing_indicators.length > 0 && (
            <div className="bg-[#0c1322] border border-amber-900/40 rounded-xl p-5 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono text-amber-400 uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                <span>Phishing Indicators & Heuristic Observations ({result.phishing_indicators.length})</span>
              </div>

              <div className="space-y-2">
                {result.phishing_indicators.map((ind, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 flex items-start space-x-3 text-xs font-mono">
                    <StatusBadge status={ind.severity} size="sm" />
                    <div className="space-y-0.5">
                      <p className="text-slate-200 font-bold">{ind.category}</p>
                      <p className="text-slate-400">{ind.indicator}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
