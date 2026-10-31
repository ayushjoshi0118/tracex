import React, { useEffect, useState } from 'react';
import { 
  GitCompare, 
  Archive, 
  Hash, 
  FileCode, 
  Terminal, 
  AlertTriangle, 
  CheckCircle2, 
  ShieldAlert, 
  Search, 
  ArrowRightLeft,
  Copy,
  Check,
  FileText
} from 'lucide-react';
import { evidenceApi } from '../services/api';
import { EvidenceItem, EvidenceComparisonResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const MetadataComparison: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [selectedIdA, setSelectedIdA] = useState<string>('');
  const [selectedIdB, setSelectedIdB] = useState<string>('');
  const [comparing, setComparing] = useState<boolean>(false);
  const [comparison, setComparison] = useState<EvidenceComparisonResponse | null>(null);
  const [stringFilter, setStringFilter] = useState<string>('');
  const [stringTab, setStringTab] = useState<'shared' | 'unique_a' | 'unique_b'>('shared');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    loadEvidenceList();
  }, []);

  const loadEvidenceList = async () => {
    try {
      const items = await evidenceApi.list();
      setEvidenceList(items);
      if (items.length >= 2) {
        setSelectedIdA(items[0].id);
        setSelectedIdB(items[1].id);
      } else if (items.length === 1) {
        setSelectedIdA(items[0].id);
        setSelectedIdB(items[0].id);
      }
    } catch (err) {
      console.error('Failed to load evidence items for comparison:', err);
    }
  };

  const handleRunComparison = async () => {
    if (!selectedIdA || !selectedIdB) return;
    try {
      setComparing(true);
      setErrorMsg(null);
      const res = await evidenceApi.compare(selectedIdA, selectedIdB);
      setComparison(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Forensic comparison failed.');
    } finally {
      setComparing(false);
    }
  };

  const itemA = evidenceList.find(e => e.id === selectedIdA);
  const itemB = evidenceList.find(e => e.id === selectedIdB);

  // String lists
  const currentStringList = comparison ? (
    stringTab === 'shared' ? comparison.shared_strings_sample :
    stringTab === 'unique_a' ? comparison.unique_to_a_sample :
    comparison.unique_to_b_sample
  ) : [];

  const filteredStrings = currentStringList.filter(s =>
    s.toLowerCase().includes(stringFilter.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <GitCompare className="w-4 h-4" />
            <span>FORENSIC DIFFERENTIAL ANALYSIS // METADATA & ARTIFACT COMPARISON</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            File Metadata & Binary Difference Analyzer
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Compare cryptographic hashes, entropy profiles, string overlaps, and binary header alignments side-by-side.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/50 text-cyan-300 text-xs font-mono">
          <ArrowRightLeft className="w-4 h-4" />
          <span>Non-Destructive Dual Triage</span>
        </div>
      </div>

      {/* Artifact Selection Bar */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-6 space-y-4">
        <p className="text-xs font-mono uppercase text-slate-400 tracking-wider">
          Select Two Quarantined Evidence Artifacts from Locker:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* Artifact A Selector */}
          <div className="p-4 rounded-xl bg-[#080d17] border border-slate-800 space-y-2">
            <label className="text-[10px] font-mono uppercase text-cyan-400 block font-bold">
              Artifact Alpha (Reference Baseline)
            </label>
            <select
              value={selectedIdA}
              onChange={(e) => setSelectedIdA(e.target.value)}
              className="w-full bg-[#0d1424] border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {evidenceList.map(e => (
                <option key={e.id} value={e.id}>{e.id}: {e.name} ({e.original_filename})</option>
              ))}
            </select>
            {itemA && (
              <p className="text-[11px] font-mono text-slate-500 truncate">
                SHA-256: {itemA.sha256.slice(0, 28)}... | Size: {itemA.file_size_bytes} B
              </p>
            )}
          </div>

          {/* Artifact B Selector */}
          <div className="p-4 rounded-xl bg-[#080d17] border border-slate-800 space-y-2">
            <label className="text-[10px] font-mono uppercase text-emerald-400 block font-bold">
              Artifact Beta (Target for Comparison)
            </label>
            <select
              value={selectedIdB}
              onChange={(e) => setSelectedIdB(e.target.value)}
              className="w-full bg-[#0d1424] border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {evidenceList.map(e => (
                <option key={e.id} value={e.id}>{e.id}: {e.name} ({e.original_filename})</option>
              ))}
            </select>
            {itemB && (
              <p className="text-[11px] font-mono text-slate-500 truncate">
                SHA-256: {itemB.sha256.slice(0, 28)}... | Size: {itemB.file_size_bytes} B
              </p>
            )}
          </div>

        </div>

        <button
          onClick={handleRunComparison}
          disabled={comparing || !selectedIdA || !selectedIdB}
          className="w-full py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center justify-center space-x-2 transition-all shadow-sm"
        >
          {comparing ? (
            <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
          ) : (
            <GitCompare className="w-4 h-4" />
          )}
          <span>Execute Forensic Differential Analysis</span>
        </button>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6">
          
          {/* Top Forensic Conclusion Banner */}
          <div className={`p-5 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 ${
            comparison.exact_hash_match
              ? 'bg-emerald-950/20 border-emerald-800/60 text-emerald-300'
              : 'bg-cyan-950/20 border-cyan-800/60 text-cyan-300'
          }`}>
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <StatusBadge status={comparison.exact_hash_match ? 'IDENTICAL CRYPTO FINGERPRINT' : 'DIVERGENT ARTIFACTS'} size="md" />
                <span className="text-xs font-mono text-slate-400">
                  {comparison.item_a_id} &harr; {comparison.item_b_id}
                </span>
              </div>
              <h3 className="text-base font-bold font-mono text-slate-100 mt-1">
                {comparison.item_a_name} vs. {comparison.item_b_name}
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
                {comparison.forensic_conclusions[0]}
              </p>
            </div>

            <div className="bg-[#080d17] p-3 rounded-xl border border-slate-800 text-right shrink-0">
              <p className="text-[10px] uppercase font-mono text-slate-400">Entropy Delta</p>
              <p className="text-xl font-black font-mono text-slate-100">{comparison.entropy_delta}</p>
              <p className="text-[10px] font-mono text-slate-500">Size Delta: {comparison.size_delta_bytes} B</p>
            </div>
          </div>

          {/* Cryptographic Hash Comparison Matrix */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
              <Hash className="w-4 h-4" />
              <span>Multi-Algorithm Cryptographic Checkpoint Matrix</span>
            </div>

            <div className="space-y-3">
              {comparison.hashes.map((h) => (
                <div key={h.algorithm} className="p-3.5 rounded-lg bg-[#080d17] border border-slate-800 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{h.algorithm}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      h.is_match ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {h.is_match ? 'MATCH CONFIRMED' : 'DIVERGENCE CONFIRMED'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                    <div className="bg-[#0c1424] p-2 rounded border border-slate-800">
                      <span className="text-cyan-400 block text-[10px] uppercase font-bold">Artifact Alpha:</span>
                      <span className="text-slate-300 truncate block select-all">{h.hash_a}</span>
                    </div>
                    <div className="bg-[#0c1424] p-2 rounded border border-slate-800">
                      <span className="text-emerald-400 block text-[10px] uppercase font-bold">Artifact Beta:</span>
                      <span className="text-slate-300 truncate block select-all">{h.hash_b}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Size, Entropy & File Signatures Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Size Differential */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
              <span className="text-xs font-mono uppercase text-cyan-400 font-bold block">
                Physical Byte Size Differential
              </span>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Alpha:</span>
                  <span className="text-slate-200 font-bold">{comparison.size_a_human} ({comparison.size_a_bytes} B)</span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Beta:</span>
                  <span className="text-slate-200 font-bold">{comparison.size_b_human} ({comparison.size_b_bytes} B)</span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Delta Variance:</span>
                  <span className="text-cyan-400 font-bold">{comparison.size_delta_bytes} Bytes</span>
                </div>
              </div>
            </div>

            {/* Entropy Divergence */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
              <span className="text-xs font-mono uppercase text-cyan-400 font-bold block">
                Shannon Entropy Comparison
              </span>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Alpha Profile:</span>
                  <span className="text-slate-200 font-bold">{comparison.entropy_a} ({comparison.entropy_a_level})</span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Beta Profile:</span>
                  <span className="text-slate-200 font-bold">{comparison.entropy_b} ({comparison.entropy_b_level})</span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Entropy Delta:</span>
                  <span className="text-emerald-400 font-bold">{comparison.entropy_delta}</span>
                </div>
              </div>
            </div>

            {/* Signature Format Alignment */}
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
              <span className="text-xs font-mono uppercase text-cyan-400 font-bold block">
                Signature & MIME Alignment
              </span>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Alpha Signature</span>
                  <span className="text-slate-200 font-bold truncate block">{comparison.signature_a}</span>
                </div>
                <div className="p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Beta Signature</span>
                  <span className="text-slate-200 font-bold truncate block">{comparison.signature_b}</span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[#080d17] border border-slate-800">
                  <span className="text-slate-400">Same Format:</span>
                  <span className={comparison.is_same_file_type ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                    {comparison.is_same_file_type ? 'YES' : 'NO'}
                  </span>
                </div>
              </div>
            </div>

          </div>

          {/* Hex Header Alignment (First 32 Bytes) */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase text-cyan-400 font-bold flex items-center space-x-1.5">
                <FileCode className="w-4 h-4" />
                <span>Binary Header Alignment (Offset 0x00 - 0x1F)</span>
              </span>
              <StatusBadge status={comparison.header_bytes_match ? 'HEADER BYTES IDENTICAL' : 'HEADER BYTES DIFFER'} size="sm" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 space-y-1">
                <span className="text-[10px] text-cyan-400 uppercase font-bold block">Artifact Alpha Header Hex</span>
                <p className="text-slate-200 select-all break-all">{comparison.header_a_hex}</p>
              </div>
              <div className="p-3 rounded-lg bg-[#080d17] border border-slate-800 space-y-1">
                <span className="text-[10px] text-emerald-400 uppercase font-bold block">Artifact Beta Header Hex</span>
                <p className="text-slate-200 select-all break-all">{comparison.header_b_hex}</p>
              </div>
            </div>
          </div>

          {/* String Overlap & Difference Analyzer */}
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                <Terminal className="w-4 h-4" />
                <span>Extracted String Intersection & Diffs</span>
              </div>

              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter string list..."
                  value={stringFilter}
                  onChange={(e) => setStringFilter(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* String Category Pills */}
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
              <button
                onClick={() => setStringTab('shared')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  stringTab === 'shared' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Shared Strings ({comparison.shared_strings_count})
              </button>
              <button
                onClick={() => setStringTab('unique_a')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  stringTab === 'unique_a' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Unique to Alpha ({comparison.unique_to_a_count})
              </button>
              <button
                onClick={() => setStringTab('unique_b')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  stringTab === 'unique_b' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Unique to Beta ({comparison.unique_to_b_count})
              </button>
            </div>

            <div className="h-48 overflow-y-auto bg-[#070b14] border border-slate-900 rounded-lg p-3 font-mono text-xs text-slate-300 space-y-1 select-all">
              {filteredStrings.length > 0 ? (
                filteredStrings.map((str, idx) => (
                  <div key={idx} className="hover:bg-slate-800/50 px-1 py-0.5 rounded transition-colors break-all flex items-center space-x-2">
                    <span className="text-slate-600 select-none">{String(idx + 1).padStart(3, '0')}</span>
                    <span>{str}</span>
                  </div>
                ))
              ) : (
                <p className="text-slate-500 italic p-4 text-center">No strings found in this category</p>
              )}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
