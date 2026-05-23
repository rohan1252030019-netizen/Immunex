import React from 'react';
import { useSOCStore } from '../lib/store';
import { ShieldCheck, HelpCircle, Activity, Globe, Award, TrendingDown } from 'lucide-react';

export default function ExecutiveDash() {
  const { alerts } = useSOCStore();

  const complianceFrameworks = [
    { name: 'SOC2 Type II', percentage: 92, color: 'stroke-[#00ff88]', textColor: 'text-[#00ff88]', trustControl: 'CC6.1 - System Boundaries' },
    { name: 'ISO 27001', percentage: 86, color: 'stroke-[#00f0ff]', textColor: 'text-[#00f0ff]', trustControl: 'A.12.4.1 - Event Logging' },
    { name: 'NIST 800-53', percentage: 81, color: 'stroke-[#ff9900]', textColor: 'text-[#ff9900]', trustControl: 'AU-2 - Event Monitoring' },
    { name: 'PCI-DSS v4.0', percentage: 95, color: 'stroke-[#00ff88]', textColor: 'text-[#00ff88]', trustControl: 'Req 10.2 - Log Auditing' },
    { name: 'HIPAA Security', percentage: 88, color: 'stroke-[#00f0ff]', textColor: 'text-[#00f0ff]', trustControl: '164.312(b) - Audit Controls' },
  ];

  // Auto containment rate calculation
  const totalAlerts = alerts.length;
  const containedAlerts = alerts.filter(a => a.mitigated).length;
  const containmentRate = totalAlerts > 0 ? (containedAlerts / totalAlerts) * 100 : 100;

  return (
    <div className="flex-grow flex flex-col bg-[#050814] p-6 h-[calc(100vh-64px)] overflow-y-auto text-white font-mono scrollbar-thin">
      {/* Title & Summary */}
      <div className="flex items-center justify-between mb-8 pb-4 border-b border-[#1e293b]/50 flex-shrink-0">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-[#00ff88]" />
          <h2 className="font-bold text-sm tracking-wider uppercase">CISO EXECUTIVE THREAT POSTURE</h2>
        </div>
        <span className="text-[10px] text-[#64748b] bg-[#0d1326] px-3 py-1 border border-[#1e293b]/50 rounded uppercase tracking-wider font-bold">
          SECURE STATUS &bull; ALL ENGINES ACTIVE
        </span>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Posture Score */}
        <div className="bg-[#0d1326]/60 border border-[#1e293b]/50 rounded-2xl p-5 flex flex-col justify-between items-center text-center">
          <span className="text-[10px] text-[#64748b] font-bold tracking-widest uppercase">System Threat Posture Rating</span>
          <div className="my-6 relative flex items-center justify-center">
            <div className="w-32 h-32 rounded-full border-4 border-[#00ff88] border-t-transparent animate-spin duration-1000 absolute" />
            <div className="w-28 h-28 rounded-full bg-[#131b31]/40 border border-[#1e293b] flex items-center justify-center flex-col">
              <span className="text-5xl font-black text-[#00ff88] shadow-[0_0_15px_rgba(0,255,136,0.3)] font-sans">A+</span>
            </div>
          </div>
          <p className="text-xs text-[#cbd5e1] leading-relaxed">
            Zero active unmitigated high-priority compromises detected in the security fabric.
          </p>
        </div>

        {/* Auto Containment Rate */}
        <div className="bg-[#0d1326]/60 border border-[#1e293b]/50 rounded-2xl p-5 flex flex-col justify-between items-center text-center">
          <span className="text-[10px] text-[#64748b] font-bold tracking-widest uppercase">Autonomous Mitigation Efficiency</span>
          
          <div className="my-6 relative flex items-center justify-center">
            <svg className="w-32 h-32 transform -rotate-90">
              <circle cx="64" cy="64" r="50" className="stroke-[#131b31]" strokeWidth="8" fill="transparent" />
              <circle 
                cx="64" 
                cy="64" 
                r="50" 
                className="stroke-[#00f0ff]" 
                strokeWidth="8" 
                fill="transparent" 
                strokeDasharray="314"
                strokeDashoffset={314 - (314 * containmentRate) / 100}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-2xl font-bold font-mono text-white">{containmentRate.toFixed(0)}%</span>
              <span className="text-[8px] text-[#64748b]">AUTO-RESOLVE</span>
            </div>
          </div>

          <p className="text-xs text-[#cbd5e1] leading-relaxed">
            {totalAlerts > 0 
              ? `System quarantined and mitigated ${containedAlerts} of ${totalAlerts} active anomalies.` 
              : 'Zero active network anomalies are pending quarantine.'}
          </p>
        </div>

        {/* Threat Stats Cards */}
        <div className="bg-[#0d1326]/60 border border-[#1e293b]/50 rounded-2xl p-5 flex flex-col justify-between">
          <span className="text-[10px] text-[#64748b] font-bold tracking-widest uppercase block mb-4">SOC OVERVIEW STATISTICS</span>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e293b]/40 pb-2">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#00f0ff]" />
                <span className="text-xs text-[#cbd5e1]">Crown Jewel Vulnerabilities</span>
              </div>
              <span className="text-xs text-[#cbd5e1] font-bold">0 Active</span>
            </div>
            
            <div className="flex items-center justify-between border-b border-[#1e293b]/40 pb-2">
              <div className="flex items-center gap-2">
                <Award className="w-4 h-4 text-[#00ff88]" />
                <span className="text-xs text-[#cbd5e1]">MITRE ATT&CK Matrix Coverage</span>
              </div>
              <span className="text-xs text-[#cbd5e1] font-bold">14 / 14 Tactics</span>
            </div>

            <div className="flex items-center justify-between pb-1">
              <div className="flex items-center gap-2">
                <TrendingDown className="w-4 h-4 text-[#ff9900]" />
                <span className="text-xs text-[#cbd5e1]">Mean Containment Response Time</span>
              </div>
              <span className="text-xs text-[#cbd5e1] font-bold">&lt; 15 seconds</span>
            </div>
          </div>
          <div className="mt-4 p-2.5 bg-[#050814] rounded-lg border border-[#1e293b] text-[9px] text-[#64748b]">
            IMMUNEX Reinforcement Learning policy models calibrated.
          </div>
        </div>
      </div>

      {/* Compliance Frameworks Section */}
      <h3 className="text-xs font-bold tracking-widest text-[#64748b] mb-4 uppercase">COMPLIANCE CONTROL MAPS</h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {complianceFrameworks.map((cf) => (
          <div 
            key={cf.name}
            className="p-4 bg-[#0d1326]/60 border border-[#1e293b]/50 rounded-2xl flex flex-col justify-between relative overflow-hidden transition-all duration-300 hover:scale-[1.02]"
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold text-white tracking-wide truncate">{cf.name}</span>
              <span className={`text-xs font-mono font-bold ${cf.textColor}`}>{cf.percentage}%</span>
            </div>

            {/* Circular Gauge */}
            <div className="my-3 relative flex items-center justify-center">
              <svg className="w-20 h-20 transform -rotate-90">
                <circle cx="40" cy="40" r="30" className="stroke-[#131b31]" strokeWidth="5" fill="transparent" />
                <circle 
                  cx="40" 
                  cy="40" 
                  r="30" 
                  className={cf.color} 
                  strokeWidth="5" 
                  fill="transparent" 
                  strokeDasharray="188"
                  strokeDashoffset={188 - (188 * cf.percentage) / 100}
                  strokeLinecap="round"
                />
              </svg>
            </div>

            <div className="mt-2 text-[9px] font-mono text-[#cbd5e1]">
              <span className="text-[#64748b] block text-[8px] tracking-wider uppercase mb-0.5">Satisfied Rule:</span>
              {cf.trustControl}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
