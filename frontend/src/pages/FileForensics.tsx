import React, { useState } from 'react';
import { 
  FileSearch, 
  Upload, 
  Copy, 
  Check, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Lock, 
  Hash, 
  FileCode,
  FileText,
  Search,
  CheckCircle2
} from 'lucide-react';
import { fileForensicsApi, evidenceApi } from '../services/api';
import { FileForensicsResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const FileForensics: React.FC = () => {
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<FileForensicsResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [stringFilter, setStringFilter] = useState<string>('');
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [registeredSuccess, setRegisteredSuccess] = useState<boolean>(false);

  const handleFileUpload = async (file: File) => {
    try {
      setAnalyzing(true);
      setErrorMsg(null);
      setRegisteredSuccess(false);
      const res = await fileForensicsApi.analyzeFile(file);
      setResult(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'File analysis failed. Ensure backend service is reachable.');
    } finally {
      setAnalyzing(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const registerCurrentAsEvidence = async () => {
    if (!result) return;
    try {
      // Create a blob from empty/stored for form data registration
      const dummyBlob = new Blob([result.file_id], { type: result.mime_type });
      const dummyFile = new File([dummyBlob], result.filename);
      const formData = new FormData();
      formData.append('file', dummyFile);
      formData.append('name', `Forensic Seizure: ${result.filename}`);
      formData.append('acquired_by', 'Investigator Specialist');
      formData.append('badge_number', 'DFIR-772');
      formData.append('source_description', `Seized via File Forensics Module (${result.detected_type})`);
      formData.append('notes', result.analysis_notes.join('; '));

      await evidenceApi.register(formData);
      setRegisteredSuccess(true);
      setTimeout(() => setRegisteredSuccess(false), 4000);
    } catch (err) {
      console.error('Failed to register evidence:', err);
    }
  };

  const filteredStrings = result?.strings_sample.filter(s => 
    s.toLowerCase().includes(stringFilter.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Module Title Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <FileSearch className="w-4 h-4" />
            <span>MODULE 01 // STATIC ARTIFACT TRIAGE</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            File Forensics & Hash Integrity
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Non-destructive header extraction, Shannon entropy profiling, file signature mismatch analysis, and YARA inspection.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-emerald-950/40 border border-emerald-800/50 text-emerald-400 text-xs font-mono">
          <ShieldCheck className="w-4 h-4" />
          <span>Quarantine Storage: No-Execute Sandbox</span>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/20'
            : 'border-slate-800 hover:border-slate-700 bg-[#0a101b]'
        }`}
      >
        <input
          type="file"
          id="fileInput"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />
        <label htmlFor="fileInput" className="cursor-pointer flex flex-col items-center space-y-3">
          <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-800/40 flex items-center justify-center text-cyan-400 shadow-inner">
            <Upload className="w-6 h-6 animate-bounce" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-200">
              Drag & drop artifact here, or <span className="text-cyan-400 underline underline-offset-4">browse files</span>
            </p>
            <p className="text-xs text-slate-500 font-mono mt-1">
              Supports PE, ELF, Mach-O, PDF, Office, ZIP, EML, PCAP, Scripts (Max 50 MB)
            </p>
          </div>
        </label>

        {analyzing && (
          <div className="absolute inset-0 bg-[#090e18]/90 backdrop-blur-sm rounded-2xl flex flex-col items-center justify-center space-y-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs font-mono text-cyan-400">
              Generating SHA-512 fingerprints & inspecting binary headers...
            </p>
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Analysis Results View */}
      {result && (
        <div className="space-y-6">
          
          {/* Top Verdict Bar */}
          <div className="p-4 rounded-xl bg-[#0d1424] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <div className={`p-2.5 rounded-lg ${
                result.security_verdict === 'malicious' ? 'bg-rose-950/70 text-rose-400 border border-rose-800' :
                result.security_verdict === 'suspicious' ? 'bg-amber-950/70 text-amber-400 border border-amber-800' :
                'bg-emerald-950/70 text-emerald-400 border border-emerald-800'
              }`}>
                {result.security_verdict === 'clean' ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-bold text-slate-100 font-mono">{result.filename}</span>
                  <StatusBadge status={result.security_verdict} size="sm" />
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  ID: {result.file_id} | Size: {result.file_size_human} ({result.file_size_bytes.toLocaleString()} bytes)
                </p>
              </div>
            </div>

            <button
              onClick={registerCurrentAsEvidence}
              disabled={registeredSuccess}
              className={`px-3.5 py-2 rounded-lg text-xs font-mono font-semibold flex items-center space-x-2 transition-all ${
                registeredSuccess
                  ? 'bg-emerald-600 text-slate-950 cursor-default'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-slate-950 shadow-sm'
              }`}
            >
              {registeredSuccess ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Enrolled In Custody Ledger</span>
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  <span>Lock in Evidence Locker</span>
                </>
              )}
            </button>
          </div>

          {/* Grid: Hashes, Signature, Entropy */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Cryptographic Hashes (2 Cols) */}
            <div className="lg:col-span-2 bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Hash className="w-4 h-4" />
                <span>Cryptographic Integrity Fingerprints</span>
              </div>

              <div className="space-y-3">
                {[
                  { label: 'SHA-256 (Forensic Baseline)', value: result.hashes.sha256 },
                  { label: 'SHA-512 (High Collision Resistance)', value: result.hashes.sha512 },
                  { label: 'MD5 (Legacy Fast Hash)', value: result.hashes.md5 },
                  { label: 'SHA-1', value: result.hashes.sha1 },
                ].map((hashItem) => (
                  <div key={hashItem.label} className="bg-[#080d17] p-2.5 rounded-lg border border-slate-800/80 flex items-center justify-between gap-3 group">
                    <div className="overflow-hidden">
                      <p className="text-[10px] font-mono uppercase text-slate-400">{hashItem.label}</p>
                      <p className="text-xs font-mono text-slate-200 truncate select-all">{hashItem.value}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(hashItem.value, hashItem.label)}
                      className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-400 transition-colors shrink-0"
                      title="Copy Hash"
                    >
                      {copiedKey === hashItem.label ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Entropy & Packing Gauge (1 Col) */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <FileCode className="w-4 h-4" />
                <span>Shannon Entropy Analysis</span>
              </div>

              <div className="space-y-2">
                <div className="flex items-baseline justify-between">
                  <span className="text-3xl font-black font-mono text-slate-100">{result.entropy}</span>
                  <span className="text-xs font-mono text-slate-500">/ 8.0 Max</span>
                </div>

                <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden p-0.5">
                  <div
                    className={`h-full rounded-full transition-all ${
                      result.entropy > 7.2 ? 'bg-rose-500' :
                      result.entropy > 5.0 ? 'bg-cyan-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${(result.entropy / 8.0) * 100}%` }}
                  />
                </div>

                <p className="text-xs font-mono text-slate-400 pt-1">
                  Profile: <strong className="text-slate-200">{result.entropy_level}</strong>
                </p>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  High entropy (&gt;7.2) indicates packed code (e.g. UPX), encrypted payloads, or randomized droppers used to defeat static signature scanners.
                </p>
              </div>
            </div>

          </div>

          {/* Magic Signature & Mismatch Alert */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <FileText className="w-4 h-4" />
                <span>Binary Signature Identification & Header Mismatch</span>
              </div>
              <StatusBadge status={result.signature.is_mismatch ? 'CRITICAL MISMATCH' : 'MATCH VERIFIED'} size="sm" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">Detected Magic Bytes</p>
                <p className="text-slate-200 font-bold mt-1 select-all">{result.signature.detected_magic}</p>
              </div>

              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">Identified Format</p>
                <p className="text-cyan-400 font-bold mt-1">{result.signature.description}</p>
              </div>

              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">Claimed Extension</p>
                <p className="text-slate-300 font-bold mt-1">.{result.signature.claimed_extension}</p>
              </div>

              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800">
                <p className="text-slate-500 text-[10px] uppercase">Verified Extension</p>
                <p className="text-emerald-400 font-bold mt-1">.{result.signature.matched_extension}</p>
              </div>
            </div>

            {/* Forensic Notes */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <p className="text-[11px] font-mono uppercase text-slate-400">Forensic Examiner Observations:</p>
              {result.analysis_notes.map((note, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-300 flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                  <span>{note}</span>
                </div>
              ))}
            </div>
          </div>

          {/* YARA Rule Detections */}
          {result.yara_matches.length > 0 && (
            <div className="bg-[#0c1322] border border-rose-900/40 rounded-xl p-5 space-y-3">
              <div className="flex items-center space-x-2 text-xs font-mono text-rose-400 uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4" />
                <span>YARA Threat Signature Matches ({result.yara_matches.length})</span>
              </div>

              <div className="space-y-2.5">
                {result.yara_matches.map((rule, idx) => (
                  <div key={idx} className="p-3 rounded-lg bg-rose-950/20 border border-rose-800/40 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-rose-300">{rule.rule}</span>
                      <StatusBadge status={rule.severity} size="sm" />
                    </div>
                    <p className="text-xs text-slate-300">{rule.description}</p>
                    <div className="flex items-center space-x-1 pt-1">
                      {rule.tags.map(t => (
                        <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                          #{t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Printable Strings Inspector */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4" />
                <span>Extracted ASCII/Unicode Strings ({filteredStrings.length})</span>
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter strings (e.g. http, api, cmd)..."
                  value={stringFilter}
                  onChange={(e) => setStringFilter(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="h-64 overflow-y-auto bg-[#070b14] border border-slate-900 rounded-lg p-3 font-mono text-xs text-slate-300 space-y-1 select-all">
              {filteredStrings.length > 0 ? (
                filteredStrings.map((str, idx) => (
                  <div key={idx} className="hover:bg-slate-800/50 px-1 py-0.5 rounded transition-colors break-all">
                    <span className="text-slate-600 select-none mr-3">{String(idx + 1).padStart(3, '0')}</span>
                    <span>{str}</span>
                  </div>
                ))
              ) : (
                <p className="text-slate-500 italic p-4 text-center">No strings matched query</p>
              )}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
