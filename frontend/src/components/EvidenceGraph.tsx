import React, { useState, useMemo } from 'react';
import { 
  FolderGit2, 
  Archive, 
  Globe, 
  Clock, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Layers, 
  X,
  ExternalLink,
  Info
} from 'lucide-react';
import { InvestigationGraphResponse, GraphNode, GraphEdge } from '../types';
import { StatusBadge } from './StatusBadge';

interface EvidenceGraphProps {
  graphData: InvestigationGraphResponse;
  onSelectEvidence?: (evidenceId: string) => void;
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({ graphData, onSelectEvidence }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Calculate coordinates for nodes in a radial forensic layout around the root case node
  const layoutNodes = useMemo(() => {
    const width = 900;
    const height = 550;
    const centerX = width / 2;
    const centerY = height / 2;

    const caseNode = graphData.nodes.find(n => n.type === 'case');
    const evidenceNodes = graphData.nodes.filter(n => n.type === 'evidence');
    const iocNodes = graphData.nodes.filter(n => n.type.startsWith('ioc_'));
    const milestoneNodes = graphData.nodes.filter(n => n.type === 'milestone');

    const positions: Record<string, { x: number; y: number }> = {};

    // Center root case node
    if (caseNode) {
      positions[caseNode.id] = { x: centerX, y: centerY };
    }

    // Inner ring: Evidence items (radius: 170px)
    evidenceNodes.forEach((node, idx) => {
      const angle = (idx / Math.max(evidenceNodes.length, 1)) * 2 * Math.PI - Math.PI / 2;
      positions[node.id] = {
        x: centerX + 175 * Math.cos(angle),
        y: centerY + 140 * Math.sin(angle)
      };
    });

    // Outer ring: Threat IOCs (radius: 290px, top and right hemisphere)
    iocNodes.forEach((node, idx) => {
      const angle = (idx / Math.max(iocNodes.length, 1)) * Math.PI + Math.PI; // top arc
      positions[node.id] = {
        x: centerX + 320 * Math.cos(angle),
        y: centerY + 220 * Math.sin(angle)
      };
    });

    // Bottom arc: Timeline Milestones
    milestoneNodes.forEach((node, idx) => {
      const angle = (idx / Math.max(milestoneNodes.length, 1)) * Math.PI; // bottom arc
      positions[node.id] = {
        x: centerX + 320 * Math.cos(angle),
        y: centerY + 220 * Math.sin(angle)
      };
    });

    return positions;
  }, [graphData]);

  // Filter nodes based on active filter and search query
  const visibleNodes = useMemo(() => {
    return graphData.nodes.filter(node => {
      const matchesFilter = filterType === 'all' || 
        (filterType === 'evidence' && node.type === 'evidence') ||
        (filterType === 'ioc' && node.type.startsWith('ioc_')) ||
        (filterType === 'milestone' && node.type === 'milestone');

      const matchesSearch = !searchTerm || 
        node.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
        node.id.toLowerCase().includes(searchTerm.toLowerCase());

      return (matchesFilter && matchesSearch) || node.type === 'case';
    });
  }, [graphData.nodes, filterType, searchTerm]);

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    return graphData.edges.filter(edge => 
      visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)
    );
  }, [graphData.edges, visibleNodeIds]);

  // Connected edges for selected node
  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) return [];
    return graphData.edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, graphData.edges]);

  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging) {
      setPanOffset({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const getNodeColor = (type: string, isSelected: boolean) => {
    if (isSelected) return '#38bdf8'; // light sky blue highlight
    if (type === 'case') return '#0284c7';
    if (type === 'evidence') return '#10b981';
    if (type.startsWith('ioc_')) return '#f43f5e';
    if (type === 'milestone') return '#f59e0b';
    return '#64748b';
  };

  return (
    <div className="space-y-4">
      
      {/* Controls Bar */}
      <div className="bg-[#0b121e] border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
        
        {/* Category Filters */}
        <div className="flex items-center space-x-1.5 text-xs font-mono">
          <span className="text-slate-500 mr-1 flex items-center space-x-1">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Layer:</span>
          </span>
          {[
            { id: 'all', label: `All (${graphData.total_nodes})` },
            { id: 'evidence', label: 'Evidence Artifacts' },
            { id: 'ioc', label: 'Threat IOCs' },
            { id: 'milestone', label: 'Timeline Milestones' },
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setFilterType(f.id)}
              className={`px-2.5 py-1 rounded-lg transition-colors ${
                filterType === f.id
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Search & Viewport Tools */}
        <div className="flex items-center space-x-2">
          <div className="relative w-44">
            <Search className="w-3 h-3 absolute left-2.5 top-2 text-slate-500" />
            <input
              type="text"
              placeholder="Find entity..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#070b14] border border-slate-800 rounded-md pl-7 pr-2 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center space-x-1 border-l border-slate-800 pl-2">
            <button
              onClick={() => setZoomLevel(prev => Math.min(prev + 0.15, 2.0))}
              className="p-1 rounded bg-slate-900 text-slate-400 hover:text-slate-200"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(prev => Math.max(prev - 0.15, 0.5))}
              className="p-1 rounded bg-slate-900 text-slate-400 hover:text-slate-200"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setZoomLevel(1); setPanOffset({ x: 0, y: 0 }); }}
              className="p-1 rounded bg-slate-900 text-slate-400 hover:text-slate-200"
              title="Reset Center"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

      </div>

      {/* Main Interactive Graph Viewport */}
      <div 
        className="relative bg-[#070b14] border border-slate-800 rounded-2xl h-[560px] overflow-hidden select-none cursor-grab active:cursor-grabbing"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
      >
        <svg 
          className="w-full h-full"
          viewBox="0 0 900 550"
        >
          {/* Background Grid Mesh */}
          <defs>
            <pattern id="gridPattern" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#101929" strokeWidth="0.8" />
            </pattern>
            <marker id="arrowhead" markerWidth="6" markerHeight="6" refX="16" refY="3" orient="auto">
              <polygon points="0 0, 6 3, 0 6" fill="#334155" />
            </marker>
            <marker id="arrowhead-highlight" markerWidth="7" markerHeight="7" refX="18" refY="3.5" orient="auto">
              <polygon points="0 0, 7 3.5, 0 7" fill="#38bdf8" />
            </marker>
          </defs>

          <rect width="100%" height="100%" fill="url(#gridPattern)" />

          <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
            
            {/* Draw Relationships (Edges) */}
            {visibleEdges.map(edge => {
              const srcPos = layoutNodes[edge.source];
              const tgtPos = layoutNodes[edge.target];
              if (!srcPos || !tgtPos) return null;

              const isEdgeHighlighted = selectedNode && (edge.source === selectedNode.id || edge.target === selectedNode.id);

              return (
                <g key={edge.id} className="transition-all duration-200">
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke={isEdgeHighlighted ? '#38bdf8' : '#1e293b'}
                    strokeWidth={isEdgeHighlighted ? 2.5 : 1.2}
                    strokeDasharray={edge.relation === 'contains_evidence' ? 'none' : '4,3'}
                    markerEnd={isEdgeHighlighted ? 'url(#arrowhead-highlight)' : 'url(#arrowhead)'}
                  />
                  {/* Midpoint Label on hover or highlight */}
                  {isEdgeHighlighted && (
                    <text
                      x={(srcPos.x + tgtPos.x) / 2}
                      y={(srcPos.y + tgtPos.y) / 2 - 6}
                      fill="#93c5fd"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="bg-black px-1"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Draw Graph Entity Nodes */}
            {visibleNodes.map(node => {
              const pos = layoutNodes[node.id];
              if (!pos) return null;

              const isSelected = selectedNode?.id === node.id;
              const nodeColor = getNodeColor(node.type, isSelected);
              const nodeRadius = node.type === 'case' ? 24 : node.type === 'evidence' ? 18 : 14;

              return (
                <g 
                  key={node.id} 
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                  }}
                  className="cursor-pointer group"
                >
                  {/* Outer pulse aura if selected */}
                  {isSelected && (
                    <circle
                      r={nodeRadius + 8}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth="2"
                      strokeOpacity="0.6"
                      className="animate-ping"
                    />
                  )}

                  {/* Core Node Circle */}
                  <circle
                    r={nodeRadius}
                    fill="#0d1526"
                    stroke={nodeColor}
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-transform group-hover:scale-110"
                  />

                  {/* Node Type Indicator Dot */}
                  <circle
                    r={nodeRadius / 3}
                    fill={nodeColor}
                  />

                  {/* Text Label Below Node */}
                  <text
                    y={nodeRadius + 14}
                    fill={isSelected ? '#ffffff' : '#94a3b8'}
                    fontSize="10"
                    fontFamily="monospace"
                    textAnchor="middle"
                    className="font-semibold pointer-events-none drop-shadow"
                  >
                    {node.label.length > 22 ? `${node.label.slice(0, 20)}...` : node.label}
                  </text>
                </g>
              );
            })}

          </g>
        </svg>

        {/* Legend */}
        <div className="absolute bottom-3 left-3 bg-[#090f1c]/90 backdrop-blur-sm border border-slate-800 rounded-lg p-2.5 text-[10px] font-mono space-y-1">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span className="text-slate-300">Root Case Dossier</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-slate-300">Quarantined Evidence Artifact</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span className="text-slate-300">Correlated Threat IOC</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span className="text-slate-300">Timeline Milestone</span>
          </div>
        </div>

        {/* Selected Entity Inspector Flyout */}
        {selectedNode && (
          <div className="absolute top-3 right-3 w-80 bg-[#0d1424]/95 backdrop-blur-md border border-slate-700/80 rounded-xl p-4 shadow-2xl space-y-3 animate-fadeIn">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                  {selectedNode.type}
                </span>
                <h4 className="text-sm font-bold font-mono text-slate-100 mt-1 select-all break-all">
                  {selectedNode.label}
                </h4>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono text-slate-300 border-t border-slate-800 pt-2 max-h-64 overflow-y-auto">
              {Object.entries(selectedNode.data).map(([key, value]) => {
                if (value === null || value === undefined || typeof value === 'object') return null;
                return (
                  <div key={key} className="bg-[#080d17] p-2 rounded border border-slate-800/80">
                    <span className="text-[10px] uppercase text-slate-500 block">{key.replace(/_/g, ' ')}</span>
                    <span className="text-slate-200 font-bold select-all break-all">{String(value)}</span>
                  </div>
                );
              })}
            </div>

            {/* Connected Relationships Counter */}
            <div className="text-[11px] font-mono text-slate-400 border-t border-slate-800 pt-2 flex items-center justify-between">
              <span>Connected Correlations:</span>
              <strong className="text-cyan-400">{selectedNodeEdges.length} Links</strong>
            </div>

            {selectedNode.type === 'evidence' && onSelectEvidence && (
              <button
                onClick={() => onSelectEvidence(selectedNode.data.id)}
                className="w-full py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs font-mono transition-colors flex items-center justify-center space-x-1"
              >
                <span>Inspect in Evidence Locker</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        )}

      </div>

    </div>
  );
};
