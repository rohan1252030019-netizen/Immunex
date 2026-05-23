import React from 'react';
import { useSOCStore } from '../lib/store';
import { Target, HelpCircle, Activity } from 'lucide-react';

interface TacticItem {
  id: string;
  name: string;
  techniques: { code: string; name: string }[];
}

export default function MitreHeatmap() {
  const { mitreData } = useSOCStore();

  const matrixData: TacticItem[] = [
    {
      id: 'TA0043',
      name: 'Reconnaissance',
      techniques: [
        { code: 'T1595', name: 'Active Scanning' },
        { code: 'T1592', name: 'Gather Host Info' },
        { code: 'T1590', name: 'Gather Network Info' }
      ]
    },
    {
      id: 'TA0042',
      name: 'Resource Dev',
      techniques: [
        { code: 'T1583', name: 'Acquire Infra' },
        { code: 'T1584', name: 'Compromise Infra' },
        { code: 'T1588', name: 'Obtain Capabilities' }
      ]
    },
    {
      id: 'TA0001',
      name: 'Initial Access',
      techniques: [
        { code: 'T1190', name: 'Exploit Public App' },
        { code: 'T1566', name: 'Phishing' },
        { code: 'T1133', name: 'External Services' }
      ]
    },
    {
      id: 'TA0002',
      name: 'Execution',
      techniques: [
        { code: 'T1059', name: 'Command & Scripting' },
        { code: 'T1204', name: 'User Execution' },
        { code: 'T1106', name: 'Native API' }
      ]
    },
    {
      id: 'TA0003',
      name: 'Persistence',
      techniques: [
        { code: 'T1547', name: 'Registry Run Keys' },
        { code: 'T1053', name: 'Scheduled Task' },
        { code: 'T1136', name: 'Create Account' }
      ]
    },
    {
      id: 'TA0004',
      name: 'Privilege Esc',
      techniques: [
        { code: 'T1548', name: 'Bypass UAC' },
        { code: 'T1068', name: 'Exploration for Privs' },
        { code: 'T1055', name: 'Process Injection' }
      ]
    },
    {
      id: 'TA0005',
      name: 'Defense Evasion',
      techniques: [
        { code: 'T1027', name: 'Obfuscation' },
        { code: 'T1070', name: 'Indicator Removal' },
        { code: 'T1562', name: 'Impair Defenses' }
      ]
    },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        { code: 'T1003', name: 'OS Cred Dumping' },
        { code: 'T1555', name: 'Credentials from Store' },
        { code: 'T1110', name: 'Brute Force' }
      ]
    },
    {
      id: 'TA0007',
      name: 'Discovery',
      techniques: [
        { code: 'T1087', name: 'Account Discovery' },
        { code: 'T1046', name: 'Network Service Discovery' },
        { code: 'T1082', name: 'System Info Discovery' }
      ]
    },
    {
      id: 'TA0008',
      name: 'Lateral Movement',
      techniques: [
        { code: 'T1021', name: 'Remote Services' },
        { code: 'T1090', name: 'Proxy Connection' },
        { code: 'T1570', name: 'Lateral Tool Transfer' }
      ]
    },
    {
      id: 'TA0009',
      name: 'Collection',
      techniques: [
        { code: 'T1114', name: 'Email Collection' },
        { code: 'T1005', name: 'Local Data Collection' },
        { code: 'T1560', name: 'Archive Collected Data' }
      ]
    },
    {
      id: 'TA0011',
      name: 'Command & Control',
      techniques: [
        { code: 'T1071', name: 'Application Layer Protocol' },
        { code: 'T1095', name: 'Non-Standard Port' },
        { code: 'T1105', name: 'Ingress Tool Transfer' }
      ]
    },
    {
      id: 'TA0010',
      name: 'Exfiltration',
      techniques: [
        { code: 'T1048', name: 'Exfiltration Over Port' },
        { code: 'T1041', name: 'Exfiltration Over C2' },
        { code: 'T1567', name: 'Exfiltration to Cloud' }
      ]
    },
    {
      id: 'TA0040',
      name: 'Impact',
      techniques: [
        { code: 'T1486', name: 'Ransomware / Encryption' },
        { code: 'T1489', name: 'Service Stop' },
        { code: 'T1490', name: 'Inhibit System Recovery' }
      ]
    }
  ];

  // Helper to find alert count for a specific technique code
  const getTechniqueAlertCount = (techCode: string) => {
    // In our backend, the mitre Data maps tactic names to count, techniques, etc.
    // Let's check if the techniques array contains the given code
    let count = 0;
    Object.values(mitreData.tactics || {}).forEach((t: any) => {
      if (t.techniques && t.techniques.includes(techCode)) {
        count += 1; // Increment count if found
      }
    });
    return count;
  };

  const getHeatIntensity = (count: number) => {
    if (count === 0) return 'bg-[#0f1526]/50 border-[#1e293b]/50 text-[#64748b]';
    if (count <= 2) return 'bg-[#ff9900]/10 border-[#ff9900]/40 text-[#ff9900] shadow-[0_0_8px_rgba(255,153,0,0.15)]';
    if (count <= 5) return 'bg-[#ff3366]/15 border-[#ff3366]/40 text-[#ff3366] shadow-[0_0_12px_rgba(255,51,102,0.25)]';
    return 'bg-[#ff3366]/30 border-[#ff3366] text-white shadow-[0_0_20px_rgba(255,51,102,0.5)] animate-pulse';
  };

  return (
    <div className="flex-1 flex flex-col bg-[#050814] p-6 h-[calc(100vh-64px)] overflow-hidden text-white font-mono">
      {/* Title */}
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-[#1e293b]/50">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-[#00f0ff]" />
          <h2 className="font-bold text-sm tracking-wider uppercase">MITRE ATT&CK Matrix Heatmap</h2>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 bg-[#0f1526]/50 border border-[#1e293b]/50 rounded" />
            <span className="text-[#64748b]">No Alerts</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 bg-[#ff9900]/20 border border-[#ff9900]/50 rounded shadow-[0_0_5px_rgba(255,153,0,0.2)]" />
            <span className="text-[#ff9900]">Low Activity (1-2)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 bg-[#ff3366]/30 border border-[#ff3366] rounded shadow-[0_0_8px_rgba(255,51,102,0.4)]" />
            <span className="text-[#ff3366]">Hostile Activity (3+)</span>
          </div>
        </div>
      </div>

      {/* Grid Container */}
      <div className="flex-1 overflow-x-auto overflow-y-auto pb-4 scrollbar-thin">
        <div className="grid grid-cols-7 lg:grid-cols-14 gap-2.5 min-w-[1200px] h-full items-start">
          {matrixData.map((tactic) => {
            // Check if there are active alerts on this tactic
            // The API can return the tactic name or ID
            const tacticAlerts = mitreData.tactics?.[tactic.name] || mitreData.tactics?.[tactic.id] || { count: 0 };
            const activeTacticCount = tacticAlerts.count || 0;

            return (
              <div key={tactic.id} className="flex flex-col gap-2.5 h-full">
                {/* Tactic Header */}
                <div className={`p-3 border rounded-xl flex flex-col items-center justify-between text-center min-h-[90px] ${
                  activeTacticCount > 0 
                    ? 'border-[#ff3366] bg-[#ff3366]/5 shadow-[0_0_10px_rgba(255,51,102,0.1)]' 
                    : 'border-[#1e293b]/50 bg-[#0d1326]/60'
                }`}>
                  <span className="text-[10px] font-bold text-white tracking-wide truncate w-full">
                    {tactic.name}
                  </span>
                  <span className="text-[9px] text-[#64748b] block mt-1">
                    {tactic.id}
                  </span>
                  {activeTacticCount > 0 && (
                    <span className="text-[9px] font-bold px-2 py-0.5 mt-2 bg-[#ff3366]/20 border border-[#ff3366]/30 text-[#ff3366] rounded-full">
                      {activeTacticCount} ALERTS
                    </span>
                  )}
                </div>

                {/* Techniques */}
                <div className="flex flex-col gap-2">
                  {tactic.techniques.map((tech) => {
                    const techCount = getTechniqueAlertCount(tech.code);
                    return (
                      <div
                        key={tech.code}
                        className={`p-2.5 border rounded-lg text-left flex flex-col justify-between min-h-[85px] transition-all duration-300 ${getHeatIntensity(techCount)}`}
                      >
                        <div>
                          <span className="text-[9px] font-bold block">{tech.code}</span>
                          <span className="text-[10px] block mt-1 leading-snug line-clamp-2">
                            {tech.name}
                          </span>
                        </div>
                        {techCount > 0 && (
                          <div className="flex items-center justify-between mt-2">
                            <span className="text-[8px] tracking-wider uppercase font-bold text-white bg-black/45 px-1.5 py-0.5 rounded">
                              TRIGGERED
                            </span>
                            <span className="text-[9px] font-bold">{techCount}</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
