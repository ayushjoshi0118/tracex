import React, { useEffect, useState } from 'react';
import { 
  Archive, 
  Plus, 
  Search, 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  Clock, 
  CheckCircle2, 
  Copy, 
  Check, 
  FileText, 
  UserCheck, 
  History,
  AlertTriangle,
  RefreshCw,
  X
} from 'lucide-react';
import { evidenceApi, investigationsApi } from '../services/api';
import { EvidenceItem, CustodyLog, InvestigationSummary } from '../types';
import { StatusBadge } from '../components/StatusBadge';

export const EvidenceLocker: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  
  // Registration Modal State
  const [showRegisterModal, setShowRegisterModal] = useState<boolean>(false);
  const [regFile, setRegFile] = useState<File | null>(null);
  const [regName, setRegName] = useState<string>('');
  const [regInvId, setRegInvId] = useState<string>('');
  const [regExaminer, setRegExaminer] = useState<string>('Specialist Vance');
  const [regBadge, setRegBadge] = useState<string>('DFIR-8820');
  const [regSource, setRegSource] = useState<string>('Physical Evidence Seizure');
  const [regNotes, setRegNotes] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  // Audit state
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [evList, invList] = await Promise.all([
        evidenceApi.list(),
        investigationsApi.list()
      ]);
      setEvidenceList(evList);
      setInvestigations(invList);
    } catch (err) {
      console.error('Failed to load evidence locker data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!regFile || !regName.trim()) return;

    try {
      setSubmitting(true);
      const formData = new FormData();
      formData.append('file', regFile);
      formData.append('name', regName);
      if (regInvId) formData.append('investigation_id', regInvId);
      formData.append('acquired_by', regExaminer);
      formData.append('badge_number', regBadge);
      formData.append('source_description', regSource);
      if (regNotes) formData.append('notes', regNotes);

      const newEv = await evidenceApi.register(formData);
      setEvidenceList([newEv, ...evidenceList]);
      setShowRegisterModal(false);
      // Reset form
      setRegFile(null);
      setRegName('');
      setRegNotes('');
    } catch (err) {
      console.error('Evidence registration error:', err);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRunAudit = async (evId: string) => {
    try {
      setVerifyingId(evId);
      const log = await evidenceApi.verifyIntegrity(
        evId,
        'Lead Auditor Beta',
        'AUD-991',
        'Routine Cryptographic Bit-Rot and Tamper Audit'
      );
      // Reload evidence details to update UI
      const updated = await evidenceApi.get(evId);
      setEvidenceList(evidenceList.map(item => item.id === evId ? updated : item));
      if (selectedEvidence?.id === evId) {
        setSelectedEvidence(updated);
      }
    } catch (err) {
      console.error('Audit verification error:', err);
    } finally {
      setVerifyingId(null);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredEvidence = evidenceList.filter(ev =>
    ev.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    ev.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    ev.sha256.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <Archive className="w-4 h-4" />
            <span>MODULE 05 // SECURE EVIDENCE MANAGEMENT</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            Evidence Locker & Chain of Custody
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable Chain of Custody ledger with on-disk SHA-256 integrity audits and tamper alerts.
          </p>
        </div>

        <button
          onClick={() => setShowRegisterModal(true)}
          className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-2 transition-all shadow-sm"
        >
          <Plus className="w-4 h-4" />
          <span>Register Evidence</span>
        </button>
      </div>

      {/* Search & Stats Bar */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by Evidence ID, file name, or SHA-256 hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#080d17] border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-4 text-xs font-mono text-slate-400">
          <span>Total Items: <strong className="text-slate-100">{evidenceList.length}</strong></span>
          <span>Verified: <strong className="text-emerald-400">{evidenceList.filter(e => e.integrity_status === 'verified').length}</strong></span>
        </div>
      </div>

      {/* Evidence Cards List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredEvidence.map((item) => (
          <div
            key={item.id}
            className="p-5 rounded-xl bg-[#0c1322] border border-slate-800 hover:border-cyan-500/40 transition-all space-y-4"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">{item.id}</span>
                  <StatusBadge status={item.integrity_status} size="sm" />
                </div>
                <h3 className="text-sm font-bold text-slate-100 mt-1">{item.name}</h3>
                <p className="text-[11px] font-mono text-slate-400">Original: {item.original_filename}</p>
              </div>

              <button
                onClick={() => handleRunAudit(item.id)}
                disabled={verifyingId === item.id}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 flex items-center space-x-1.5 border border-slate-700 transition-colors"
                title="Perform live on-disk hash check"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${verifyingId === item.id ? 'animate-spin text-cyan-400' : ''}`} />
                <span>Verify</span>
              </button>
            </div>

            {/* Cryptographic Hash Baseline */}
            <div className="p-2.5 rounded-lg bg-[#080d17] border border-slate-800 space-y-1">
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                <span>AUTHORITATIVE SHA-256 FINGERPRINT</span>
                <button
                  onClick={() => copyHash(item.sha256)}
                  className="hover:text-cyan-400 transition-colors"
                >
                  {copiedHash === item.sha256 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <p className="text-xs font-mono text-slate-200 truncate select-all">{item.sha256}</p>
            </div>

            {/* Metadata Footer */}
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800">
              <div>
                <span className="text-slate-600 block text-[10px]">ACQUIRED BY:</span>
                <span className="text-slate-300">{item.acquired_by} ({item.badge_number})</span>
              </div>
              <div>
                <span className="text-slate-600 block text-[10px]">CASE ASSIGNMENT:</span>
                <span className="text-cyan-400">{item.investigation_id || 'Standalone Locker'}</span>
              </div>
            </div>

            <button
              onClick={() => setSelectedEvidence(item)}
              className="w-full py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-cyan-400 border border-slate-800 flex items-center justify-center space-x-1.5 transition-colors"
            >
              <History className="w-3.5 h-3.5" />
              <span>Inspect Chain of Custody ({item.custody_logs?.length || 1} Logs)</span>
            </button>
          </div>
        ))}
      </div>

      {/* Custody Drawer / Modal */}
      {selectedEvidence && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b121e] border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl">
            
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">{selectedEvidence.id}</span>
                  <StatusBadge status={selectedEvidence.integrity_status} size="sm" />
                </div>
                <h3 className="text-base font-bold text-slate-100 mt-1">Chain of Custody Ledger</h3>
              </div>
              <button
                onClick={() => setSelectedEvidence(null)}
                className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-4">
              <p className="text-xs text-slate-400">
                Auditable legal ledger. Every acquisition, integrity verification checkpoint, and physical transfer is recorded with cryptographic validation.
              </p>

              <div className="space-y-3">
                {selectedEvidence.custody_logs && selectedEvidence.custody_logs.length > 0 ? (
                  selectedEvidence.custody_logs.map((log) => (
                    <div key={log.id} className="p-3.5 rounded-xl bg-[#070d18] border border-slate-800 space-y-2 text-xs font-mono">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{log.action}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] ${
                          log.is_hash_match ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                        }`}>
                          {log.is_hash_match ? 'HASH MATCH' : 'TAMPER DETECTED'}
                        </span>
                      </div>
                      <p className="text-slate-400">
                        Performed By: <strong className="text-slate-200">{log.performed_by}</strong> (Badge: {log.badge_number})
                      </p>
                      <p className="text-slate-500 text-[11px]">
                        Timestamp: {new Date(log.timestamp).toUTCString()}
                      </p>
                      <p className="text-slate-400">
                        Location: <span className="text-slate-300">{log.custody_location}</span>
                      </p>
                      {log.notes && (
                        <p className="text-slate-300 bg-slate-900/80 p-2 rounded border border-slate-800/80">
                          {log.notes}
                        </p>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 italic">No custody entries found</p>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-[#090e18] flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-500">
                Stored in isolated forensic quarantine vault
              </span>
              <button
                onClick={() => setSelectedEvidence(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200"
              >
                Close Ledger
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Registration Modal */}
      {showRegisterModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b121e] border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl">
            
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-base font-bold font-mono text-slate-100 flex items-center space-x-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Register Forensic Evidence</span>
              </h3>
              <button
                onClick={() => setShowRegisterModal(false)}
                className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleRegisterEvidence} className="p-5 space-y-4 text-xs font-mono">
              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Select Artifact File</label>
                <input
                  type="file"
                  required
                  onChange={(e) => setRegFile(e.target.files ? e.target.files[0] : null)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Evidence Description / Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Seized Memory Dump or Gateway Log"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Investigation Dossier</label>
                  <select
                    value={regInvId}
                    onChange={(e) => setRegInvId(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  >
                    <option value="">None (Standalone)</option>
                    {investigations.map(inv => (
                      <option key={inv.id} value={inv.id}>{inv.id}: {inv.title}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Examiner Name</label>
                  <input
                    type="text"
                    required
                    value={regExaminer}
                    onChange={(e) => setRegExaminer(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Examiner Badge #</label>
                  <input
                    type="text"
                    required
                    value={regBadge}
                    onChange={(e) => setRegBadge(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Source Description</label>
                  <input
                    type="text"
                    value={regSource}
                    onChange={(e) => setRegSource(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Forensic Notes</label>
                <textarea
                  rows={3}
                  value={regNotes}
                  onChange={(e) => setRegNotes(e.target.value)}
                  placeholder="Seizure circumstances, chain of custody observations..."
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  {submitting ? 'Hashing & Locking...' : 'Enforce & Register'}
                </button>
              </div>
            </form>

          </div>
        </div>
      )}

    </div>
  );
};
