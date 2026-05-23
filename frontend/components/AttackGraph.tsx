import React from 'react';
import { useSOCStore } from '../lib/store';
import { Network, ShieldAlert, Cpu, Activity, Play } from 'lucide-react';

declare global {
  interface Window {
    cytoscape?: any;
  }
}

export default function AttackGraph() {
  const { graphData } = useSOCStore();
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = React.useState<any>(null);
  const [blastRadius, setBlastRadius] = React.useState<string[]>([]);
  const [cyInstance, setCyInstance] = React.useState<any>(null);

  // Default mock data if backend has empty graph
  const defaultNodes = [
    { id: 'gw-01', label: 'DMZ Gateway', type: 'gateway', ip: '192.168.1.1', severity: 'MEDIUM', os: 'Linux (Alpine)', crown_jewel: false },
    { id: 'srv-web', label: 'Web Server', type: 'server', ip: '10.0.2.15', severity: 'HIGH', os: 'Ubuntu 22.04', crown_jewel: false },
    { id: 'usr-analyst', label: 'Workstation 04', type: 'workstation', ip: '10.0.5.40', severity: 'LOW', os: 'Windows 11', crown_jewel: false },
    { id: 'db-prod', label: 'Crown Jewel Database', type: 'database', ip: '10.0.10.5', severity: 'CRITICAL', os: 'RHEL 9 (Postgres)', crown_jewel: true },
    { id: 'ad-controller', label: 'AD Domain Controller', type: 'ad_controller', ip: '10.0.10.2', severity: 'CRITICAL', os: 'Windows Server 2022', crown_jewel: true },
  ];

  const defaultEdges = [
    { source: 'gw-01', target: 'srv-web', label: 'HTTPS (443)' },
    { source: 'srv-web', target: 'ad-controller', label: 'Kerberos (88)' },
    { source: 'usr-analyst', target: 'ad-controller', label: 'LDAP (389)' },
    { source: 'ad-controller', target: 'db-prod', label: 'SQL (5432)' },
    { source: 'srv-web', target: 'db-prod', label: 'Indirect Access' },
  ];

  const nodesToUse = graphData.nodes && graphData.nodes.length > 0 ? graphData.nodes : defaultNodes;
  const edgesToUse = graphData.edges && graphData.edges.length > 0 ? graphData.edges : defaultEdges;

  React.useEffect(() => {
    // Dynamically load cytoscape to prevent SSR issues
    let active = true;
    
    import('cytoscape').then((cytoscapeModule) => {
      const cytoscape = cytoscapeModule.default;
      
      if (!active || !containerRef.current) return;

      const elements = [
        ...nodesToUse.map((n: any) => ({
          data: { 
            id: n.id, 
            label: `${n.label}\n(${n.ip || 'N/A'})`, 
            type: n.type || 'server', 
            crown_jewel: n.crown_jewel || false,
            ip: n.ip,
            os: n.os || 'Unknown OS',
            severity: n.severity || 'LOW'
          }
        })),
        ...edgesToUse.map((e: any) => ({
          data: { 
            source: e.source, 
            target: e.target, 
            label: e.label || 'Connection' 
          }
        }))
      ];

      try {
        const cy = cytoscape({
          container: containerRef.current,
          elements: elements,
          style: [
            {
              selector: 'node',
              style: {
                'label': 'data(label)',
                'color': '#94a3b8',
                'font-family': 'monospace',
                'font-size': '8px',
                'text-wrap': 'wrap',
                'text-valign': 'bottom',
                'text-margin-y': 4,
                'width': 26,
                'height': 26,
                'background-color': '#131b31',
                'border-width': 1.5,
                'border-color': '#00f0ff',
                'transition-property': 'background-color, border-color, width, height',
                'transition-duration': 0.2
              }
            },
            {
              selector: 'node[type="gateway"]',
              style: {
                'border-color': '#00ff88',
                'background-color': '#00ff88/10'
              }
            },
            {
              selector: 'node[type="database"]',
              style: {
                'width': 32,
                'height': 32,
                'border-color': '#ff3366',
                'background-color': '#ff3366/15'
              }
            },
            {
              selector: 'node[type="ad_controller"]',
              style: {
                'width': 32,
                'height': 32,
                'border-color': '#ff3366',
                'background-color': '#ff3366/15'
              }
            },
            {
              selector: 'node[?crown_jewel]',
              style: {
                'border-color': '#ff3366',
                'border-width': 3.5
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 1.5,
                'line-color': '#334155',
                'target-arrow-shape': 'triangle',
                'target-arrow-color': '#334155',
                'curve-style': 'bezier',
                'label': 'data(label)',
                'font-family': 'monospace',
                'font-size': '7px',
                'color': '#475569',
                'text-rotation': 'autorotate',
                'text-margin-y': -8
              }
            },
            {
              selector: '.highlighted',
              style: {
                'background-color': '#ff3366',
                'border-color': '#ff3366',
                'line-color': '#ff3366',
                'target-arrow-color': '#ff3366',
                'color': '#ff3366'
              }
            }
          ],
          layout: {
            name: 'cose',
            animate: false,
            componentSpacing: 60,
            nodeRepulsion: () => 4000,
            idealEdgeLength: () => 60
          }
        });

        cy.on('tap', 'node', (evt: any) => {
          const node = evt.target;
          setSelectedNode(node.data());
          setBlastRadius([]);
        });

        cy.on('tap', (evt: any) => {
          if (evt.target === cy) {
            setSelectedNode(null);
            setBlastRadius([]);
            cy.elements().removeClass('highlighted');
          }
        });

        setCyInstance(cy);
      } catch (err) {
        console.error('Cytoscape render error:', err);
      }
    });

    return () => {
      active = false;
    };
  }, [nodesToUse, edgesToUse]);

  const handleSimulateBlast = () => {
    if (!cyInstance || !selectedNode) return;
    
    cyInstance.elements().removeClass('highlighted');
    
    // Find BFS reachable nodes
    const bfs = cyInstance.elements().bfs({
      roots: `#${selectedNode.id}`,
      visit: () => {},
      directed: true
    });

    const affectedIds: string[] = [];
    bfs.path.forEach((ele: any) => {
      ele.addClass('highlighted');
      if (ele.isNode()) {
        affectedIds.push(ele.id());
      }
    });

    setBlastRadius(affectedIds);
  };

  return (
    <div className="flex-grow flex p-6 h-[calc(100vh-64px)] bg-[#050814] text-white gap-6 overflow-hidden">
      {/* Network Canvas */}
      <div className="flex-1 flex flex-col bg-[#0d1326]/60 border border-[#1e293b]/50 rounded-2xl overflow-hidden relative">
        <div className="p-4 bg-[#0d1326] border-b border-[#1e293b]/50 flex items-center justify-between z-10">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-[#00f0ff]" />
            <span className="font-mono text-xs font-bold tracking-wider uppercase">Enterprise Attack Topology</span>
          </div>
          <span className="text-[9px] font-mono text-[#64748b] bg-[#131b31] px-2 py-0.5 border border-[#1e293b] rounded">
            CYTOSCAPE.JS ACTIVE
          </span>
        </div>
        
        {/* Cytoscape Container */}
        <div ref={containerRef} className="flex-grow w-full h-full bg-[#070b19]" />
      </div>

      {/* Control / Inspector Side Panel */}
      <div className="w-[380px] bg-[#0d1326] border border-[#1e293b]/80 rounded-2xl p-5 flex flex-col justify-between flex-shrink-0">
        <div>
          <div className="flex items-center gap-2 pb-3 border-b border-[#1e293b]/80 mb-4">
            <ShieldAlert className="w-4 h-4 text-[#ff3366]" />
            <h3 className="font-mono font-bold tracking-wider text-xs">ASSET INSPECTOR</h3>
          </div>

          {selectedNode ? (
            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">ASSET ID</span>
                <span className="text-xs font-mono text-white block">{selectedNode.id}</span>
              </div>

              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">NODE NAME</span>
                <span className="text-sm font-mono font-bold text-[#00f0ff]">{selectedNode.label.split('\n')[0]}</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-[10px] font-mono text-[#64748b] block">IP ADDRESS</span>
                  <span className="text-xs font-mono text-white">{selectedNode.ip || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] font-mono text-[#64748b] block">OPERATING SYSTEM</span>
                  <span className="text-xs font-mono text-white truncate block">{selectedNode.os}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-[10px] font-mono text-[#64748b] block">CROWN JEWEL</span>
                  <span className={`text-xs font-mono font-bold ${selectedNode.crown_jewel ? 'text-[#ff3366]' : 'text-[#64748b]'}`}>
                    {selectedNode.crown_jewel ? 'YES (CRITICAL)' : 'NO'}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] font-mono text-[#64748b] block">THREAT LEVEL</span>
                  <span className={`text-xs font-mono font-bold ${
                    selectedNode.severity === 'CRITICAL' ? 'text-[#ff3366]' :
                    selectedNode.severity === 'HIGH' ? 'text-[#ff9900]' : 'text-[#00ff88]'
                  }`}>{selectedNode.severity}</span>
                </div>
              </div>

              {blastRadius.length > 0 && (
                <div className="p-3.5 bg-[#ff3366]/5 border border-[#ff3366]/20 rounded-xl mt-4">
                  <span className="text-[10px] font-mono text-[#ff3366] block font-bold mb-1">BLAST RADIUS SIMULATION</span>
                  <p className="text-xs font-mono text-[#cbd5e1] leading-relaxed">
                    Compromise of this node exposes **{blastRadius.length - 1}** other assets via lateral movement vectors.
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {blastRadius.map(id => id !== selectedNode.id && (
                      <span key={id} className="text-[9px] font-mono bg-black/45 border border-[#ff3366]/35 text-[#ff3366] px-1.5 py-0.5 rounded">
                        {id}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center border border-[#1e293b]/40 border-dashed rounded-xl bg-[#131b31]/15 text-[#64748b] font-mono text-center px-4">
              <Activity className="w-6 h-6 mb-2 text-[#64748b] animate-pulse" />
              <p className="text-xs">SELECT ANY NODE IN THE TOPOLOGY TO BEGIN BLAST RADIUS DIAGNOSTICS & GRAPH TRAVERSAL</p>
            </div>
          )}
        </div>

        {selectedNode && (
          <button
            onClick={handleSimulateBlast}
            className="w-full flex items-center justify-center gap-2 py-2 px-4 bg-[#ff3366]/15 hover:bg-[#ff3366]/25 border border-[#ff3366]/40 text-[#ff3366] font-mono text-xs rounded-xl transition-all shadow-[0_0_12px_rgba(255,51,102,0.1)]"
          >
            <Play className="w-4 h-4" />
            SIMULATE LATERAL BLAST RADIUS
          </button>
        )}
      </div>
    </div>
  );
}
