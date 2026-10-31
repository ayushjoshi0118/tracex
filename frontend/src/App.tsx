import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Dashboard } from './pages/Dashboard';
import { FileForensics } from './pages/FileForensics';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { EmailForensics } from './pages/EmailForensics';
import { NetworkForensics } from './pages/NetworkForensics';
import { EvidenceLocker } from './pages/EvidenceLocker';
import { Investigations } from './pages/Investigations';
import { ShieldCheck, Lock, Terminal, Activity } from 'lucide-react';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [targetCaseId, setTargetCaseId] = useState<string | undefined>(undefined);

  const handleNavigate = (tab: string, contextId?: string) => {
    if (contextId) {
      setTargetCaseId(contextId);
    }
    setCurrentTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-300">
      
      {/* Platform Header Navigation */}
      <Navbar currentTab={currentTab} setCurrentTab={setCurrentTab} />

      {/* Main Forensic Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {currentTab === 'dashboard' && <Dashboard onNavigate={handleNavigate} />}
        {currentTab === 'files' && <FileForensics />}
        {currentTab === 'intel' && <ThreatIntelligence />}
        {currentTab === 'email' && <EmailForensics />}
        {currentTab === 'network' && <NetworkForensics />}
        {currentTab === 'evidence' && <EvidenceLocker />}
        {currentTab === 'investigations' && <Investigations initialCaseId={targetCaseId} />}
      </main>

      {/* Platform Forensic Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070a12] py-6 px-4 lg:px-8 mt-12 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <span className="text-slate-300 font-bold tracking-wider">TRACEX</span>
            <span>•</span>
            <span className="text-slate-400">Investigate. Analyze. Correlate. Discover.</span>
          </div>

          <div className="flex items-center space-x-6 text-[11px]">
            <span className="flex items-center space-x-1.5 text-emerald-400/80">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Immutable Chain of Custody</span>
            </span>
            <span className="flex items-center space-x-1.5 text-cyan-400/80">
              <Lock className="w-3.5 h-3.5" />
              <span>Zero-Execution Quarantine</span>
            </span>
            <span className="flex items-center space-x-1.5 text-slate-400">
              <Terminal className="w-3.5 h-3.5" />
              <span>SHA-256 Baseline Integrity</span>
            </span>
          </div>
        </div>
      </footer>

    </div>
  );
}

export default App;
