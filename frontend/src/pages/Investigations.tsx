import React, { useEffect, useState } from 'react';
import { 
  FolderGit2, 
  Plus, 
  FileText, 
  Download, 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Archive, 
  Globe, 
  CheckCircle2, 
  Calendar,
  User,
  Hash,
  AlertTriangle,
  ArrowRight,
  Layers,
  FileDown,
  X,
  Search,
  Filter,
  RefreshCw,
  Share2,
  Lock,
  GitCommit,
  ExternalLink,
  ChevronRight,
  Eye,
  Check,
  Copy
} from 'lucide-react';
import { investigationsApi, reportsApi, evidenceApi } from '../services/api';
import { InvestigationDetail, InvestigationSummary, InvestigationGraphResponse, EvidenceItem, CustodyLog } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EvidenceGraph } from '../components/EvidenceGraph';

interface InvestigationsProps {
  initialCaseId?: string;
  onNavigateToComparison?: () => void;
}

export const Investigations: React.FC<InvestigationsProps> = ({ initialCaseId, onNavigateToComparison }) => {
  const [cases, setCases] = useState<InvestigationSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(initialCaseId || 'INV-2026-001');
  const [caseDetail, setCaseDetail] = useState<InvestigationDetail | null>(null);
  const [graphData, setGraphData] = useState<InvestigationGraphResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'evidence' | 'timeline' | 'iocs' | 'export'>('overview');

  // Timeline interactive filters
  const [timelineCategoryFilter, setTimelineCategoryFilter] = useState<string>('all');
  const [timelineSeverityFilter, setTimelineSeverityFilter] = useState<string>('all');
  const [timelineSearch, setTimelineSearch] = useState<string>('');

  // Modals state
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [showTransferModal, setShowTransferModal] = useState<boolean>(false);
  const [showAddIocModal, setShowAddIocModal] = useState<boolean>(false);
  const [selectedEvidenceForTransfer, setSelectedEvidenceForTransfer] = useState<EvidenceItem | null>(null);

  // New Case form
  const [newTitle, setNewTitle] = useState<string>('');
  const [newDesc, setNewDesc] = useState<string>('');
  const [newPriority, setNewPriority] = useState<string>('high');
  const [newAnalyst, setNewAnalyst] = useState<string>('Specialist Vance');

  // Note form state
  const [noteContent, setNoteContent] = useState<string>('');
  const [noteType, setNoteType] = useState<string>('verified_fact');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);

  // Timeline form state
  const [timelineTitle, setTimelineTitle] = useState<string>('');
  const [timelineDesc, setTimelineDesc] = useState<string>('');
  const [timelineCat, setTimelineCat] = useState<string>('artifact');
  const [timelineSev, setTimelineSev] = useState<string>('high');
  const [timelineRef, setTimelineRef] = useState<string>('');

  // Add IOC form state
  const [iocType, setIocType] = useState<string>('ip');
  const [iocValue, setIocValue] = useState<string>('');
  const [iocCategory, setIocCategory] = useState<string>('c2');
  const [iocScore, setIocScore] = useState<number>(85.0);
  const [iocClassification, setIocClassification] = useState<string>('malicious');
  const [iocNotes, setIocNotes] = useState<string>('');

  // Custody transfer form state
  const [txRecipient, setTxRecipient] = useState<string>('Examiner Delta');
  const [txBadge, setTxBadge] = useState<string>('DFIR-9002');
  const [txLocation, setTxLocation] = useState<string>('Secure Digital Vault Room 4B');
  const [txReason, setTxReason] = useState<string>('Secondary Deep Binary Inspection');
  const [txNotes, setTxNotes] = useState<string>('Transferred under official forensic chain of custody protocol.');

  // Audit verifying state
  const [verifyingEvidenceId, setVerifyingEvidenceId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Export state
  const [exportingPdf, setExportingPdf] = useState<boolean>(false);
  const [exportingJson, setExportingJson] = useState<boolean>(false);
  const [examinerSig, setExaminerSig] = useState<string>('Lead Forensic Examiner Vance');
  const [badgeNum, setBadgeNum] = useState<string>('DFIR-8820');

  useEffect(() => {
    loadCases();
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetail(selectedCaseId);
      loadGraphData(selectedCaseId);
    }
  }, [selectedCaseId]);

  const loadCases = async () => {
    try {
      setLoading(true);
      const list = await investigationsApi.list();
      setCases(list);
      if (list.length > 0 && !selectedCaseId) {
        setSelectedCaseId(list[0].id);
      }
    } catch (err) {
      console.error('Failed to load cases:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadCaseDetail = async (id: string) => {
    try {
      const data = await investigationsApi.get(id);
      setCaseDetail(data);
    } catch (err) {
      console.error('Failed to load case detail:', err);
    }
  };

  const loadGraphData = async (id: string) => {
    try {
      const graph = await investigationsApi.getGraph(id);
      setGraphData(graph);
    } catch (err) {
      console.error('Failed to load graph data:', err);
    }
  };

  const handleUpdateStatus = async (newStatus: string) => {
    if (!caseDetail) return;
    try {
      const updated = await investigationsApi.update(caseDetail.id, { status: newStatus });
      setCaseDetail(updated);
      setCases(cases.map(c => c.id === caseDetail.id ? { ...c, status: updated.status } : c));
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const handleUpdatePriority = async (newPri: string) => {
    if (!caseDetail) return;
    try {
      const updated = await investigationsApi.update(caseDetail.id, { priority: newPri });
      setCaseDetail(updated);
      setCases(cases.map(c => c.id === caseDetail.id ? { ...c, priority: updated.priority } : c));
    } catch (err) {
      console.error('Failed to update priority:', err);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    try {
      const created = await investigationsApi.create({
        title: newTitle,
        description: newDesc,
        priority: newPriority,
        lead_analyst: newAnalyst
      });
      setCases([created, ...cases]);
      setSelectedCaseId(created.id);
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
    } catch (err) {
      console.error('Failed to create case:', err);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseDetail || !noteContent.trim()) return;

    try {
      setSubmittingNote(true);
      await investigationsApi.addNote(caseDetail.id, {
        author: examinerSig,
        badge_number: badgeNum,
        content: noteContent,
        is_finding: noteType
      });
      setNoteContent('');
      loadCaseDetail(caseDetail.id);
    } catch (err) {
      console.error('Failed to add note:', err);
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleAddTimeline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseDetail || !timelineTitle.trim()) return;

    try {
      await investigationsApi.addTimelineEvent(caseDetail.id, {
        title: timelineTitle,
        description: timelineDesc,
        category: timelineCat,
        severity: timelineSev,
        source: 'Analyst Milestone',
        raw_reference: timelineRef || undefined
      });
      setTimelineTitle('');
      setTimelineDesc('');
      setTimelineRef('');
      loadCaseDetail(caseDetail.id);
      loadGraphData(caseDetail.id);
    } catch (err) {
      console.error('Failed to add timeline event:', err);
    }
  };

  const handleAddIOC = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseDetail || !iocValue.trim()) return;

    try {
      await investigationsApi.addIOC(caseDetail.id, {
        ioc_type: iocType,
        value: iocValue.trim(),
        category: iocCategory,
        threat_score: iocScore,
        classification: iocClassification,
        attribution_source: 'Case Investigator Correlation',
        notes: iocNotes
      });
      setShowAddIocModal(false);
      setIocValue('');
      setIocNotes('');
      loadCaseDetail(caseDetail.id);
      loadGraphData(caseDetail.id);
    } catch (err) {
      console.error('Failed to add IOC:', err);
    }
  };

  const handleRunAudit = async (evId: string) => {
    try {
      setVerifyingEvidenceId(evId);
      await evidenceApi.verifyIntegrity(
        evId,
        examinerSig,
        badgeNum,
        'Active Investigation Verification Audit'
      );
      if (caseDetail) {
        loadCaseDetail(caseDetail.id);
      }
    } catch (err) {
      console.error('Integrity audit error:', err);
    } finally {
      setVerifyingEvidenceId(null);
    }
  };

  const handleExecuteTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvidenceForTransfer) return;

    try {
      await evidenceApi.transferCustody(selectedEvidenceForTransfer.id, {
        transferred_to: txRecipient,
        recipient_badge: txBadge,
        transferred_by: examinerSig,
        releasing_badge: badgeNum,
        new_location: txLocation,
        reason: txReason,
        notes: txNotes
      });
      setShowTransferModal(false);
      if (caseDetail) {
        loadCaseDetail(caseDetail.id);
      }
    } catch (err) {
      console.error('Custody transfer error:', err);
    }
  };

  const handleDownloadPdf = async () => {
    if (!caseDetail) return;
    try {
      setExportingPdf(true);
      const blob = await reportsApi.downloadPdf(caseDetail.id, examinerSig, badgeNum);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TRACEX_Forensic_Report_${caseDetail.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      console.error('PDF export error:', err);
    } finally {
      setExportingPdf(false);
    }
  };

  const handleExportJson = async () => {
    if (!caseDetail) return;
    try {
      setExportingJson(true);
      const data = await reportsApi.exportJson(caseDetail.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `TRACEX_Dossier_${caseDetail.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (err) {
      console.error('JSON export error:', err);
    } finally {
      setExportingJson(false);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Filtered timeline
  const filteredTimeline = (caseDetail?.timeline_events || []).filter(evt => {
    const matchesCat = timelineCategoryFilter === 'all' || evt.category === timelineCategoryFilter;
    const matchesSev = timelineSeverityFilter === 'all' || evt.severity === timelineSeverityFilter;
    const matchesSearch = !timelineSearch || 
      evt.title.toLowerCase().includes(timelineSearch.toLowerCase()) ||
      (evt.description || '').toLowerCase().includes(timelineSearch.toLowerCase()) ||
      (evt.raw_reference || '').toLowerCase().includes(timelineSearch.toLowerCase());
    return matchesCat && matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Platform Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <FolderGit2 className="w-4 h-4" />
            <span>INVESTIGATION WORKSPACE // DOSSIERS & CORRELATIONS</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            Forensic Case Investigation Environment
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Interactive correlation graph, advanced chronological timeline, evidence workspace, and chain of custody management.
          </p>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-2 transition-all shadow-sm"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Case Selector Strip */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2 scrollbar-none">
        {cases.map((c) => (
          <button
            key={c.id}
            onClick={() => setSelectedCaseId(c.id)}
            className={`px-4 py-2.5 rounded-xl text-xs font-mono flex items-center space-x-2 shrink-0 border transition-all ${
              selectedCaseId === c.id
                ? 'bg-[#101b30] border-cyan-500/60 text-cyan-300 shadow-sm'
                : 'bg-[#0c1322] border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <span className="font-bold">{c.id}</span>
            <span className="text-slate-500">|</span>
            <span className="truncate max-w-[150px]">{c.title}</span>
            <StatusBadge status={c.priority} size="sm" />
          </button>
        ))}
      </div>

      {/* Main Workspace for Selected Case */}
      {caseDetail && (
        <div className="space-y-6">
          
          {/* Executive Dossier Header */}
          <div className="p-6 rounded-2xl bg-[#0c1424] border border-slate-800 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">{caseDetail.id}</span>
                  <StatusBadge status={caseDetail.status} size="sm" />
                  <StatusBadge status={caseDetail.priority} size="sm" />
                </div>
                <h2 className="text-xl font-bold font-mono text-slate-100 mt-1">
                  {caseDetail.title}
                </h2>
              </div>

              {/* Status and Priority Quick-Switch Controls */}
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                <div className="p-2 rounded-lg bg-[#080d17] border border-slate-800 flex items-center space-x-2">
                  <span className="text-slate-500 text-[10px]">STATUS:</span>
                  <select
                    value={caseDetail.status}
                    onChange={(e) => handleUpdateStatus(e.target.value)}
                    className="bg-transparent text-slate-200 focus:outline-none cursor-pointer font-bold"
                  >
                    <option value="active">Active Triage</option>
                    <option value="in_review">In Review</option>
                    <option value="closed">Closed</option>
                    <option value="archived">Archived</option>
                  </select>
                </div>

                <div className="p-2 rounded-lg bg-[#080d17] border border-slate-800 flex items-center space-x-2">
                  <span className="text-slate-500 text-[10px]">PRIORITY:</span>
                  <select
                    value={caseDetail.priority}
                    onChange={(e) => handleUpdatePriority(e.target.value)}
                    className="bg-transparent text-slate-200 focus:outline-none cursor-pointer font-bold"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div className="p-2 rounded-lg bg-[#080d17] border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">LEAD ANALYST</span>
                  <span className="text-cyan-400 font-bold">{caseDetail.lead_analyst}</span>
                </div>
              </div>
            </div>

            {caseDetail.description && (
              <p className="text-xs text-slate-300 leading-relaxed bg-[#080d17] p-3 rounded-xl border border-slate-800/80">
                {caseDetail.description}
              </p>
            )}

            {/* Sub-Navigation Navigation Tabs */}
            <div className="flex items-center space-x-2 border-t border-slate-800 pt-3 overflow-x-auto scrollbar-none">
              {[
                { id: 'overview', label: `Investigation Overview (${caseDetail.notes.length})` },
                { id: 'graph', label: 'Relationship Visualization' },
                { id: 'evidence', label: `Evidence Workspace (${caseDetail.evidence_items.length})` },
                { id: 'timeline', label: `Investigation Timeline (${caseDetail.timeline_events.length})` },
                { id: 'iocs', label: `Correlated IOCs (${caseDetail.iocs.length})` },
                { id: 'export', label: 'Export Certified Dossier' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors shrink-0 ${
                    activeTab === tab.id
                      ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/60'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* TAB 1: Investigation Overview & Findings */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              
              {/* Executive Overview Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">EVIDENCE ARTIFACTS</span>
                  <p className="text-2xl font-black font-mono text-emerald-400 mt-1">{caseDetail.evidence_items.length}</p>
                  <span className="text-[10px] font-mono text-slate-400">All Quarantined</span>
                </div>
                <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">TRACKED IOCS</span>
                  <p className="text-2xl font-black font-mono text-rose-400 mt-1">{caseDetail.iocs.length}</p>
                  <span className="text-[10px] font-mono text-slate-400">Threat Indicators</span>
                </div>
                <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">TIMELINE MILESTONES</span>
                  <p className="text-2xl font-black font-mono text-cyan-400 mt-1">{caseDetail.timeline_events.length}</p>
                  <span className="text-[10px] font-mono text-slate-400">Chronological Nodes</span>
                </div>
                <div className="p-4 rounded-xl bg-[#0c1322] border border-slate-800">
                  <span className="text-[10px] font-mono uppercase text-slate-500 block">INTEGRITY STATUS</span>
                  <p className="text-2xl font-black font-mono text-slate-100 mt-1">100%</p>
                  <span className="text-[10px] font-mono text-emerald-400">SHA-256 Intact</span>
                </div>
              </div>

              {/* Observed Facts vs Analyst Interpretations */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Verified Facts Column */}
                <div className="bg-[#0c1322] border border-emerald-900/40 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase text-emerald-400 font-bold flex items-center space-x-1.5">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Observed Facts (Cryptographically Verified)</span>
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                      FACTS
                    </span>
                  </div>

                  <div className="space-y-3">
                    {caseDetail.notes.filter(n => n.is_finding === 'verified_fact' || n.is_finding === 'observation').map(note => (
                      <div key={note.id} className="p-3.5 rounded-lg bg-[#080d17] border border-emerald-900/30 space-y-1.5 text-xs font-mono">
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span className="text-emerald-400 font-bold">{note.author} ({note.badge_number})</span>
                          <span>{new Date(note.created_at).toLocaleDateString()}</span>
                        </div>
                        <p className="text-slate-200 leading-relaxed">{note.content}</p>
                      </div>
                    ))}
                    {caseDetail.notes.filter(n => n.is_finding === 'verified_fact' || n.is_finding === 'observation').length === 0 && (
                      <p className="text-xs text-slate-500 italic p-3 text-center">No observed facts recorded yet</p>
                    )}
                  </div>
                </div>

                {/* Analyst Hypotheses Column */}
                <div className="bg-[#0c1322] border border-amber-900/40 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase text-amber-400 font-bold flex items-center space-x-1.5">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Analyst Hypotheses & Deductive Assessments</span>
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
                      INTERPRETATION
                    </span>
                  </div>

                  <div className="space-y-3">
                    {caseDetail.notes.filter(n => n.is_finding === 'interpretation' || n.is_finding === 'hypothesis').map(note => (
                      <div key={note.id} className="p-3.5 rounded-lg bg-[#080d17] border border-amber-900/30 space-y-1.5 text-xs font-mono">
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span className="text-amber-400 font-bold">{note.author} ({note.badge_number})</span>
                          <span>{new Date(note.created_at).toLocaleDateString()}</span>
                        </div>
                        <p className="text-slate-200 leading-relaxed">{note.content}</p>
                      </div>
                    ))}
                    {caseDetail.notes.filter(n => n.is_finding === 'interpretation' || n.is_finding === 'hypothesis').length === 0 && (
                      <p className="text-xs text-slate-500 italic p-3 text-center">No analyst hypotheses recorded yet</p>
                    )}
                  </div>
                </div>

              </div>

              {/* Add Note / Finding Form */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
                <span className="text-xs font-mono uppercase text-cyan-400 font-bold flex items-center space-x-1.5">
                  <FileText className="w-4 h-4" />
                  <span>Document Case Finding into Dossier</span>
                </span>

                <form onSubmit={handleAddNote} className="space-y-3 text-xs font-mono">
                  <textarea
                    rows={3}
                    required
                    placeholder="Document technical observation, memory string match, or hypothesis..."
                    value={noteContent}
                    onChange={(e) => setNoteContent(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center space-x-4">
                      <label className="flex items-center space-x-1.5 cursor-pointer">
                        <input
                          type="radio"
                          name="noteType"
                          value="verified_fact"
                          checked={noteType === 'verified_fact'}
                          onChange={() => setNoteType('verified_fact')}
                          className="text-emerald-500 focus:ring-0"
                        />
                        <span className="text-emerald-400 font-bold">Observed Fact (Baseline)</span>
                      </label>
                      <label className="flex items-center space-x-1.5 cursor-pointer">
                        <input
                          type="radio"
                          name="noteType"
                          value="interpretation"
                          checked={noteType === 'interpretation'}
                          onChange={() => setNoteType('interpretation')}
                          className="text-amber-500 focus:ring-0"
                        />
                        <span className="text-amber-400 font-bold">Analyst Interpretation</span>
                      </label>
                    </div>

                    <button
                      type="submit"
                      disabled={submittingNote}
                      className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                    >
                      {submittingNote ? 'Recording...' : 'Commit Finding to Dossier'}
                    </button>
                  </div>
                </form>
              </div>

            </div>
          )}

          {/* TAB 2: Relationship Visualization */}
          {activeTab === 'graph' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
                    <Share2 className="w-4 h-4 text-cyan-400" />
                    <span>Evidence & Threat Relationship Graph</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Interactive correlation map connecting cases, quarantined evidence artifacts, threat indicators, and timeline milestones.
                  </p>
                </div>
              </div>

              {graphData ? (
                <EvidenceGraph 
                  graphData={graphData} 
                  onSelectEvidence={() => setActiveTab('evidence')} 
                />
              ) : (
                <div className="h-64 flex items-center justify-center bg-[#070b14] border border-slate-800 rounded-xl text-xs font-mono text-slate-400">
                  Loading relationship network...
                </div>
              )}
            </div>
          )}

          {/* TAB 3: Interactive Evidence Workspace */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
                    <Archive className="w-4 h-4 text-emerald-400" />
                    <span>Quarantined Artifact Workspace ({caseDetail.evidence_items.length} Items)</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Perform on-demand cryptographic audits, inspect custody histories, or transfer custody.
                  </p>
                </div>

                {onNavigateToComparison && (
                  <button
                    onClick={onNavigateToComparison}
                    className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-xs font-mono font-semibold flex items-center space-x-1.5"
                  >
                    <span>Launch Side-by-Side Artifact Comparison</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              <div className="space-y-4">
                {caseDetail.evidence_items.map((ev) => (
                  <div key={ev.id} className="p-5 rounded-xl bg-[#0c1322] border border-slate-800 hover:border-slate-700 space-y-4 transition-all">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-cyan-400">{ev.id}</span>
                          <StatusBadge status={ev.integrity_status} size="sm" />
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            {ev.mime_type}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-slate-100 mt-1">{ev.name}</h4>
                        <p className="text-xs text-slate-400 font-mono">File: {ev.original_filename} | Size: {ev.file_size_bytes.toLocaleString()} bytes</p>
                      </div>

                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleRunAudit(ev.id)}
                          disabled={verifyingEvidenceId === ev.id}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 flex items-center space-x-1.5"
                          title="Recalculate SHA-256 on physical disk"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${verifyingEvidenceId === ev.id ? 'animate-spin text-cyan-400' : ''}`} />
                          <span>Audit Integrity</span>
                        </button>

                        <button
                          onClick={() => {
                            setSelectedEvidenceForTransfer(ev);
                            setShowTransferModal(true);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 text-xs font-mono text-emerald-300 border border-emerald-800/60 flex items-center space-x-1.5"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          <span>Transfer Custody</span>
                        </button>
                      </div>
                    </div>

                    {/* Fingerprint Baseline */}
                    <div className="p-2.5 rounded-lg bg-[#080d17] border border-slate-800 flex items-center justify-between text-xs font-mono">
                      <div className="truncate mr-3">
                        <span className="text-[10px] uppercase text-slate-500 block">Baseline SHA-256 Digest:</span>
                        <span className="text-slate-200 select-all font-bold">{ev.sha256}</span>
                      </div>
                      <button
                        onClick={() => copyHash(ev.sha256)}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 shrink-0"
                      >
                        {copiedHash === ev.sha256 ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>

                    {/* Custody Ledger Checkpoints */}
                    {ev.custody_logs && ev.custody_logs.length > 0 && (
                      <div className="pt-2 border-t border-slate-800 space-y-2">
                        <span className="text-[10px] font-mono uppercase text-slate-500 block">Chain of Custody History ({ev.custody_logs.length} Checkpoints)</span>
                        <div className="space-y-1.5">
                          {ev.custody_logs.slice(0, 3).map((log) => (
                            <div key={log.id} className="p-2 rounded bg-[#080d17] border border-slate-800/80 text-[11px] font-mono flex items-center justify-between text-slate-300">
                              <span><strong>{log.action}</strong> by {log.performed_by} ({log.badge_number})</span>
                              <span className="text-slate-500">{new Date(log.timestamp).toLocaleDateString()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: Advanced Investigation Timeline */}
          {activeTab === 'timeline' && (
            <div className="space-y-6">
              
              {/* Interactive Timeline Filter Controls */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                
                {/* Category Filters */}
                <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                  <span className="text-slate-500 mr-1 flex items-center space-x-1">
                    <Filter className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Category:</span>
                  </span>
                  {[
                    { id: 'all', label: 'All' },
                    { id: 'artifact', label: 'Artifact' },
                    { id: 'network', label: 'Network' },
                    { id: 'email', label: 'Email' },
                    { id: 'custody', label: 'Custody' },
                    { id: 'intel', label: 'Intel' },
                  ].map(cat => (
                    <button
                      key={cat.id}
                      onClick={() => setTimelineCategoryFilter(cat.id)}
                      className={`px-2 py-1 rounded text-[11px] transition-colors ${
                        timelineCategoryFilter === cat.id
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {cat.label}
                    </button>
                  ))}
                </div>

                {/* Severity & Search Filters */}
                <div className="flex items-center space-x-3">
                  <select
                    value={timelineSeverityFilter}
                    onChange={(e) => setTimelineSeverityFilter(e.target.value)}
                    className="bg-[#080d17] border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-slate-300"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="info">Informational</option>
                  </select>

                  <div className="relative w-48">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
                    <input
                      type="text"
                      placeholder="Search timeline..."
                      value={timelineSearch}
                      onChange={(e) => setTimelineSearch(e.target.value)}
                      className="w-full bg-[#080d17] border border-slate-800 rounded-lg pl-7 pr-3 py-1 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

              </div>

              {/* Chronological Milestone Sequence */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-6 space-y-6">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-cyan-400 font-bold flex items-center space-x-1.5">
                    <Clock className="w-4 h-4" />
                    <span>Chronological Attack & Investigation Sequence ({filteredTimeline.length} Events)</span>
                  </span>
                </div>

                <div className="relative pl-6 border-l-2 border-cyan-900/50 space-y-6 my-2">
                  {filteredTimeline.map((evt) => (
                    <div key={evt.id} className="relative space-y-1.5">
                      <div className="absolute -left-[33px] top-1 w-3.5 h-3.5 rounded-full bg-cyan-500 border-2 border-[#0c1322]" />
                      <div className="p-4 rounded-xl bg-[#080d17] border border-slate-800 space-y-2 text-xs font-mono">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-slate-100 text-sm">{evt.title}</span>
                            <StatusBadge status={evt.severity} size="sm" />
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-cyan-300">
                              #{evt.category}
                            </span>
                          </div>
                          <span className="text-slate-500 text-[11px]">
                            {new Date(evt.timestamp).toUTCString()}
                          </span>
                        </div>

                        {evt.description && (
                          <p className="text-slate-300 leading-relaxed">{evt.description}</p>
                        )}

                        <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-500 pt-1 border-t border-slate-800/60">
                          <span>Source / Origin: <strong className="text-slate-400">{evt.source}</strong></span>
                          {evt.raw_reference && (
                            <span className="text-cyan-400/80 select-all truncate max-w-sm">
                              Witness Reference: {evt.raw_reference}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                  {filteredTimeline.length === 0 && (
                    <p className="text-xs text-slate-500 italic p-6 text-center">No timeline milestones matched current filter parameters</p>
                  )}
                </div>
              </div>

              {/* Append Milestone Form */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
                <span className="text-xs font-mono uppercase text-cyan-400 font-bold">
                  Append New Milestone to Case Timeline
                </span>

                <form onSubmit={handleAddTimeline} className="space-y-3 text-xs font-mono">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-2">
                      <input
                        type="text"
                        required
                        placeholder="Event Title (e.g. Reverse Shell Beacon Established)"
                        value={timelineTitle}
                        onChange={(e) => setTimelineTitle(e.target.value)}
                        className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                      />
                    </div>
                    <div>
                      <select
                        value={timelineSev}
                        onChange={(e) => setTimelineSev(e.target.value)}
                        className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                      >
                        <option value="critical">Critical Severity</option>
                        <option value="high">High Severity</option>
                        <option value="medium">Medium Severity</option>
                        <option value="low">Low Severity</option>
                        <option value="info">Informational</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <select
                        value={timelineCat}
                        onChange={(e) => setTimelineCat(e.target.value)}
                        className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                      >
                        <option value="artifact">Artifact Analysis</option>
                        <option value="network">Network Traffic</option>
                        <option value="email">Email Event</option>
                        <option value="custody">Custody Checkpoint</option>
                        <option value="intel">Threat Intelligence</option>
                        <option value="system">Host System</option>
                      </select>
                    </div>
                    <div>
                      <input
                        type="text"
                        placeholder="Raw Reference (e.g. Evidence SHA-256 or Target IP)"
                        value={timelineRef}
                        onChange={(e) => setTimelineRef(e.target.value)}
                        className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                      />
                    </div>
                  </div>

                  <textarea
                    rows={2}
                    placeholder="Milestone technical context and forensic evidence links..."
                    value={timelineDesc}
                    onChange={(e) => setTimelineDesc(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                    >
                      Append Milestone Node
                    </button>
                  </div>
                </form>
              </div>

            </div>
          )}

          {/* TAB 5: Threat IOCs */}
          {activeTab === 'iocs' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span>Correlated Indicators of Compromise ({caseDetail.iocs.length} IOCs)</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Network IPs, C2 domains, and malware hashes tracked in this investigation.
                  </p>
                </div>

                <button
                  onClick={() => setShowAddIocModal(true)}
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-1"
                >
                  <Plus className="w-4 h-4" />
                  <span>Associate IOC</span>
                </button>
              </div>

              <div className="space-y-3">
                {caseDetail.iocs.map((ioc) => (
                  <div key={ioc.id} className="p-4 rounded-xl bg-[#0c1322] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="uppercase px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 text-[10px] font-bold">
                          {ioc.ioc_type}
                        </span>
                        <span className="text-sm font-bold text-slate-100 select-all">{ioc.value}</span>
                        <StatusBadge status={ioc.classification} size="sm" />
                      </div>
                      {ioc.notes && (
                        <p className="text-slate-400 text-[11px]">{ioc.notes}</p>
                      )}
                    </div>

                    <div className="text-right text-[11px] text-slate-400 shrink-0">
                      <p className="font-bold text-slate-200">Threat Score: {ioc.threat_score}/100</p>
                      <p className="text-slate-500">Source: {ioc.attribution_source}</p>
                    </div>
                  </div>
                ))}
                {caseDetail.iocs.length === 0 && (
                  <p className="text-xs text-slate-500 italic p-6 text-center">No IOCs associated with this case yet.</p>
                )}
              </div>
            </div>
          )}

          {/* TAB 6: Report Export */}
          {activeTab === 'export' && (
            <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-6 space-y-6">
              <div>
                <h3 className="text-base font-bold font-mono text-slate-100 flex items-center space-x-2">
                  <FileDown className="w-5 h-5 text-cyan-400" />
                  <span>Certified Forensic Dossier Generation</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Export high-fidelity documentation suitable for legal disclosure, executive review, or SIEM integration.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Signatory Examiner Name</label>
                  <input
                    type="text"
                    value={examinerSig}
                    onChange={(e) => setExaminerSig(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2.5 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Examiner Badge Number</label>
                  <input
                    type="text"
                    value={badgeNum}
                    onChange={(e) => setBadgeNum(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2.5 text-slate-200"
                  />
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs font-mono text-slate-400">
                <strong className="text-slate-200 block">Report Guarantee:</strong>
                Includes complete cryptographic hash baselines, audit trail, timeline reconstruction, and strictly categorizes observed technical facts separately from analytical deductions.
              </div>

              <div className="flex flex-wrap items-center gap-4 pt-2">
                <button
                  onClick={handleDownloadPdf}
                  disabled={exportingPdf}
                  className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono flex items-center space-x-2 transition-all shadow-[0_0_20px_rgba(6,182,212,0.25)]"
                >
                  {exportingPdf ? (
                    <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Download className="w-4 h-4" />
                  )}
                  <span>Download Certified Forensic PDF Report</span>
                </button>

                <button
                  onClick={handleExportJson}
                  disabled={exportingJson}
                  className="px-6 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs font-mono flex items-center space-x-2 border border-slate-700 transition-all"
                >
                  {exportingJson ? (
                    <span className="w-4 h-4 border-2 border-slate-200 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <FileText className="w-4 h-4" />
                  )}
                  <span>Export Structured JSON Dossier</span>
                </button>
              </div>
            </div>
          )}

        </div>
      )}

      {/* Custody Transfer Modal */}
      {showTransferModal && selectedEvidenceForTransfer && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b121e] border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block">Chain of Custody Handover</span>
                <h3 className="text-sm font-bold font-mono text-slate-100 mt-0.5">
                  Transfer: {selectedEvidenceForTransfer.id} ({selectedEvidenceForTransfer.name})
                </h3>
              </div>
              <button
                onClick={() => setShowTransferModal(false)}
                className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleExecuteTransfer} className="p-5 space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Recipient Examiner</label>
                  <input
                    type="text"
                    required
                    value={txRecipient}
                    onChange={(e) => setTxRecipient(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Recipient Badge #</label>
                  <input
                    type="text"
                    required
                    value={txBadge}
                    onChange={(e) => setTxBadge(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Destination Vault / Lab Location</label>
                <input
                  type="text"
                  required
                  value={txLocation}
                  onChange={(e) => setTxLocation(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Legal Reason for Transfer</label>
                <input
                  type="text"
                  required
                  value={txReason}
                  onChange={(e) => setTxReason(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Transfer Notes</label>
                <textarea
                  rows={2}
                  value={txNotes}
                  onChange={(e) => setTxNotes(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowTransferModal(false)}
                  className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold"
                >
                  Execute Custody Transfer
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add IOC Modal */}
      {showAddIocModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b121e] border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span>Associate Indicator of Compromise (IOC)</span>
              </h3>
              <button
                onClick={() => setShowAddIocModal(false)}
                className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddIOC} className="p-5 space-y-4 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Indicator Type</label>
                  <select
                    value={iocType}
                    onChange={(e) => setIocType(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain Name</option>
                    <option value="url">URL</option>
                    <option value="hash">File Hash</option>
                    <option value="email">Email Address</option>
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Category</label>
                  <select
                    value={iocCategory}
                    onChange={(e) => setIocCategory(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  >
                    <option value="c2">Command & Control (C2)</option>
                    <option value="phishing">Phishing Infrastructure</option>
                    <option value="dropzone">Malware Dropzone</option>
                    <option value="tor_exit">Tor Exit / Scanner</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Indicator Value</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.44 or bad-domain.net"
                  value={iocValue}
                  onChange={(e) => setIocValue(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Threat Score (0-100)</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={iocScore}
                    onChange={(e) => setIocScore(parseFloat(e.target.value) || 0)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Classification</label>
                  <select
                    value={iocClassification}
                    onChange={(e) => setIocClassification(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  >
                    <option value="malicious">Malicious</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="benign">Benign</option>
                  </select>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Correlation Notes</label>
                <textarea
                  rows={2}
                  placeholder="Where this indicator was observed in the investigation..."
                  value={iocNotes}
                  onChange={(e) => setIocNotes(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowAddIocModal(false)}
                  className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  Associate with Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Case Creation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b121e] border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-base font-bold font-mono text-slate-100 flex items-center space-x-2">
                <FolderGit2 className="w-4 h-4 text-cyan-400" />
                <span>Initialize New Investigation</span>
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="p-5 space-y-4 text-xs font-mono">
              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Investigation Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Operation CobaltStrike Egress Triage"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-400 uppercase text-[10px]">Case Objective & Scope</label>
                <textarea
                  rows={3}
                  placeholder="Describe incident background, compromised assets, and forensic hypothesis..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Priority Level</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  >
                    <option value="critical">Critical Severity</option>
                    <option value="high">High Severity</option>
                    <option value="medium">Medium Severity</option>
                    <option value="low">Low Severity</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-slate-400 uppercase text-[10px]">Lead Analyst</label>
                  <input
                    type="text"
                    required
                    value={newAnalyst}
                    onChange={(e) => setNewAnalyst(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                >
                  Initialize Dossier
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};
