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
  X
} from 'lucide-react';
import { investigationsApi, reportsApi } from '../services/api';
import { InvestigationDetail, InvestigationSummary } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface InvestigationsProps {
  initialCaseId?: string;
}

export const Investigations: React.FC<InvestigationsProps> = ({ initialCaseId }) => {
  const [cases, setCases] = useState<InvestigationSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(initialCaseId || 'INV-2026-001');
  const [caseDetail, setCaseDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'iocs' | 'timeline' | 'export'>('overview');

  // Modals & form state
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
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
        source: 'Investigator Action'
      });
      setTimelineTitle('');
      setTimelineDesc('');
      loadCaseDetail(caseDetail.id);
    } catch (err) {
      console.error('Failed to add timeline event:', err);
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
      a.download = `TRACEX_Report_${caseDetail.id}.pdf`;
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

  return (
    <div className="space-y-6 animate-fadeIn">
      
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs mb-1">
            <FolderGit2 className="w-4 h-4" />
            <span>MODULE 06 & 07 // INVESTIGATION WORKSPACE & REPORTING</span>
          </div>
          <h1 className="text-xl md:text-2xl font-bold font-mono text-slate-100">
            Investigation Dossiers & Reports
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage evidence correlations, event timelines, analyst findings, and generate certified forensic reports.
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

      {/* Case Selector Tabs */}
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
          
          {/* Case Header Dossier Card */}
          <div className="p-6 rounded-2xl bg-[#0c1424] border border-slate-800 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono font-bold text-cyan-400">{caseDetail.id}</span>
                  <StatusBadge status={caseDetail.status} size="sm" />
                  <StatusBadge status={caseDetail.priority} size="sm" />
                </div>
                <h2 className="text-xl font-bold font-mono text-slate-100 mt-1">
                  {caseDetail.title}
                </h2>
              </div>

              <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
                <div className="p-2.5 rounded-lg bg-[#080d17] border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">LEAD EXAMINER</span>
                  <span className="text-slate-200 font-bold">{caseDetail.lead_analyst}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-[#080d17] border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">REGISTERED</span>
                  <span className="text-slate-200 font-bold">{new Date(caseDetail.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            </div>

            {caseDetail.description && (
              <p className="text-xs text-slate-300 leading-relaxed bg-[#080d17] p-3 rounded-xl border border-slate-800/80">
                {caseDetail.description}
              </p>
            )}

            {/* Sub-Navigation Tabs */}
            <div className="flex items-center space-x-2 border-t border-slate-800 pt-3">
              {[
                { id: 'overview', label: `Findings & Facts (${caseDetail.notes.length})` },
                { id: 'evidence', label: `Artifacts (${caseDetail.evidence_items.length})` },
                { id: 'iocs', label: `Threat IOCs (${caseDetail.iocs.length})` },
                { id: 'timeline', label: `Timeline Milestones (${caseDetail.timeline_events.length})` },
                { id: 'export', label: 'Export Certified Dossier' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
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

          {/* TAB 1: Findings (Facts vs Analyst Interpretations) */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              
              {/* Important Legal Forensic Standard Callout */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/30 to-cyan-950/30 border border-cyan-800/40 text-xs font-mono text-cyan-300 flex items-start space-x-3">
                <CheckCircle2 className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="block text-slate-100 uppercase tracking-wider mb-0.5">
                    Defensive Forensic Standard: Strict Separation of Evidentiary Categories
                  </strong>
                  To ensure legal admissibility and scientific rigor, TRACEX strictly bifurcates observed physical/cryptographic facts from speculative analyst hypotheses.
                </div>
              </div>

              {/* Grid: Observed Facts vs Analyst Interpretations */}
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
                  <span>Record Case Finding or Forensic Observation</span>
                </span>

                <form onSubmit={handleAddNote} className="space-y-3 text-xs font-mono">
                  <textarea
                    rows={3}
                    required
                    placeholder="Document technical finding, packet observation, or behavioral hypothesis..."
                    value={noteContent}
                    onChange={(e) => setNoteContent(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-3 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center space-x-3">
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

          {/* TAB 2: Evidence Artifacts */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-400">
                  Forensic artifacts linked to case <strong className="text-cyan-400">{caseDetail.id}</strong>:
                </p>
              </div>

              <div className="space-y-3">
                {caseDetail.evidence_items.map((ev) => (
                  <div key={ev.id} className="p-4 rounded-xl bg-[#0c1322] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-cyan-400 font-bold">{ev.id}</span>
                        <StatusBadge status={ev.integrity_status} size="sm" />
                      </div>
                      <h4 className="text-sm font-bold text-slate-100">{ev.name}</h4>
                      <p className="text-slate-400">File: {ev.original_filename} ({ev.file_size_bytes} bytes)</p>
                      <p className="text-cyan-400/80 truncate max-w-xl">SHA-256: {ev.sha256}</p>
                    </div>

                    <div className="text-right text-slate-500 text-[11px] shrink-0">
                      <p>Seized By: {ev.acquired_by}</p>
                      <p>Timestamp: {new Date(ev.acquisition_timestamp).toLocaleDateString()}</p>
                    </div>
                  </div>
                ))}
                {caseDetail.evidence_items.length === 0 && (
                  <p className="text-xs text-slate-500 italic p-6 text-center">No evidence artifacts associated with this case yet.</p>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: Threat IOCs */}
          {activeTab === 'iocs' && (
            <div className="space-y-4">
              <p className="text-xs text-slate-400">
                Threat indicators correlated with this investigation:
              </p>

              <div className="space-y-2">
                {caseDetail.iocs.map((ioc) => (
                  <div key={ioc.id} className="p-3.5 rounded-xl bg-[#0c1322] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="uppercase px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 text-[10px]">
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

          {/* TAB 4: Timeline */}
          {activeTab === 'timeline' && (
            <div className="space-y-6">
              
              {/* Timeline Events List */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider">
                  <Clock className="w-4 h-4" />
                  <span>Chronological Attack & Investigation Sequence</span>
                </div>

                <div className="relative pl-6 border-l border-cyan-900/60 space-y-5 my-2">
                  {caseDetail.timeline_events.map((evt) => (
                    <div key={evt.id} className="relative space-y-1">
                      <div className="absolute -left-[31px] top-1 w-3 h-3 rounded-full bg-cyan-500 border-2 border-[#0c1322]" />
                      <div className="p-3.5 rounded-lg bg-[#080d17] border border-slate-800 space-y-1.5 text-xs font-mono">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-100">{evt.title}</span>
                          <StatusBadge status={evt.severity} size="sm" />
                        </div>
                        {evt.description && (
                          <p className="text-slate-300 leading-relaxed">{evt.description}</p>
                        )}
                        <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                          <span>Source: {evt.source}</span>
                          <span>Timestamp: {new Date(evt.timestamp).toUTCString()}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Add Milestone Form */}
              <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-3">
                <span className="text-xs font-mono uppercase text-cyan-400 font-bold">
                  Add Milestone to Investigation Timeline
                </span>

                <form onSubmit={handleAddTimeline} className="space-y-3 text-xs font-mono">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-2">
                      <input
                        type="text"
                        required
                        placeholder="Milestone Event Title (e.g. Reverse Shell Beacon Detected)"
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
                        <option value="info">Informational</option>
                      </select>
                    </div>
                  </div>

                  <textarea
                    rows={2}
                    placeholder="Milestone narrative and technical context..."
                    value={timelineDesc}
                    onChange={(e) => setTimelineDesc(e.target.value)}
                    className="w-full bg-[#080d17] border border-slate-800 rounded-lg p-2 text-slate-200"
                  />

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                    >
                      Append Timeline Milestone
                    </button>
                  </div>
                </form>
              </div>

            </div>
          )}

          {/* TAB 5: Report Export */}
          {activeTab === 'export' && (
            <div className="space-y-6">
              
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

            </div>
          )}

        </div>
      )}

      {/* Case Creation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
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
