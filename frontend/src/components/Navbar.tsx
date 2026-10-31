import React from 'react';
import { 
  ShieldAlert, 
  FileSearch, 
  Globe, 
  Mail, 
  Network, 
  Archive, 
  FolderGit2,
  Activity
} from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, setCurrentTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Overview', icon: Activity },
    { id: 'files', label: 'File Forensics', icon: FileSearch },
    { id: 'intel', label: 'Threat Intel', icon: Globe },
    { id: 'email', label: 'Email Forensics', icon: Mail },
    { id: 'network', label: 'PCAP Inspector', icon: Network },
    { id: 'evidence', label: 'Evidence Locker', icon: Archive },
    { id: 'investigations', label: 'Investigations', icon: FolderGit2 },
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#090e17]/95 backdrop-blur border-b border-slate-800/80 px-4 lg:px-8 py-3 transition-colors">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Brand & Platform Tagline */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setCurrentTab('dashboard')}>
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 via-cyan-500/10 to-emerald-500/20 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <div className="absolute -bottom-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-[#090e17]" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xl font-black tracking-wider text-slate-100 font-mono">TRACEX</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                DEFENSE V1.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono tracking-tight">
              Investigate. Analyze. Correlate. Discover.
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center flex-wrap gap-1 bg-[#0d1424] p-1 rounded-xl border border-slate-800">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Live Integrity / Guard Status */}
        <div className="hidden lg:flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded-md bg-emerald-950/30 border border-emerald-800/40 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>VAULT DEFENSE ACTIVE</span>
          </div>
        </div>

      </div>
    </header>
  );
};
