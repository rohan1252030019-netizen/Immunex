import React from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  Zap, 
  Award, 
  Terminal, 
  Clock, 
  ShieldAlert, 
  Eye, 
  Fingerprint,
  RefreshCw
} from 'lucide-react';
import { motion } from 'framer-motion';

interface ControlRule {
  id: string;
  directive: string;
  requirement: string;
  department: string;
  status: 'PASS' | 'WARNING' | 'FAIL';
  riskScore: number;
  remediation: string;
}

const RBI_CONTROLS: ControlRule[] = [
  {
    id: 'RBI-DPS-3.1',
    directive: 'Logical Access Controls',
    requirement: 'Enforce multi-factor authorization for UPI/Banking transactions exceeding INR 10,000.',
    department: 'CORE_BANKING',
    status: 'PASS',
    riskScore: 10,
    remediation: 'N/A - Validated on all customer terminals.'
  },
  {
    id: 'RBI-DPS-4.2',
    directive: 'Device Fingerprinting Binding',
    requirement: 'Prevent duplicate session token generation on distinct geographic configurations.',
    department: 'IT_INFRASTRUCTURE',
    status: 'WARNING',
    riskScore: 45,
    remediation: 'Verify emulator blocking profiles on mobile applications. Force re-authentication on mismatch.'
  },
  {
    id: 'RBI-DPS-6.1',
    directive: 'Continuous Authentication timing',
    requirement: 'Utilize behavioral typing keystroke dynamics checks to block robotic session scripts.',
    department: 'INFORMATION_SECURITY',
    status: 'PASS',
    riskScore: 15,
    remediation: 'N/A - Biometric timing captures active.'
  },
  {
    id: 'RBI-DPS-7.3',
    directive: 'Insider Access Dual-Control',
    requirement: 'Require four-eyes manager token verification for clerk transactions exceeding 25 Lakhs.',
    department: 'OPERATIONS',
    status: 'FAIL',
    riskScore: 95,
    remediation: 'IMMEDIATE ACTION: Dual-control approval tokens missing on high-value transaction ID FRD-401. Session flagged.'
  },
  {
    id: 'RBI-DPS-8.4',
    directive: 'Loan Collateral Document Verification',
    requirement: 'Perform OCR and metadata structure validation on uploaded mortgage deeds and land records.',
    department: 'AUDIT',
    status: 'FAIL',
    riskScore: 88,
    remediation: 'PDF manipulation software patterns matched on loan statement uploads. Trigger forensic verification.'
  }
];

export default function ComplianceScorecard() {
  const [selectedControl, setSelectedControl] = React.useState<ControlRule>(RBI_CONTROLS[3]); // Default to the failing dual-control rule
  const [compliancePercentage, setCompliancePercentage] = React.useState(60);

  const handleRecalculate = () => {
    // Simulate re-calculating audit metrics
    setCompliancePercentage(prev => (prev === 60 ? 80 : 60));
  };

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#050814] font-mono text-[#cbd5e1] p-6 scrollbar-thin">
      
      {/* Top Header */}
      <div className="flex justify-between items-center border-b border-[#1e2d5a]/40 pb-4 mb-6">
        <div>
          <h2 className="text-lg font-black text-white flex items-center gap-2">
            <Award className="w-5 h-5 text-[#eab308]" /> RBI Compliance Intelligence Center
          </h2>
          <span className="text-[10px] text-[#64748b] tracking-wider uppercase font-bold mt-0.5 block">
            Reserve Bank of India (RBI) Digital Payment security regulatory scorecard
          </span>
        </div>

        <button 
          onClick={handleRecalculate}
          className="flex items-center gap-2 px-3 py-1.5 bg-[#131b35] hover:bg-[#1c284e] border border-[#1e2d5a] rounded-xl text-xs font-bold text-white transition-all active:scale-[0.98]"
        >
          <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Recalculate Compliance
        </button>
      </div>

      {/* Compliance Ring and Explainable AI Panel Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch mb-6">
        
        {/* Compliance ring visualization */}
        <div className="lg:col-span-4 bg-[#0a0f24] border border-[#1e2d5a]/60 rounded-3xl p-5 shadow-[0_0_20px_rgba(0,0,0,0.4)] flex flex-col items-center justify-between">
          <span className="text-xs font-black text-white block border-b border-[#1e2d5a]/40 pb-2 mb-4 w-full text-center uppercase tracking-wider">
            Overall Compliance Posture
          </span>

          <div className="relative w-40 h-40 flex items-center justify-center mb-4 select-none">
            {/* Glowing ring background */}
            <svg className="w-full h-full transform -rotate-90">
              <circle 
                cx="80" 
                cy="80" 
                r="70" 
                stroke="#131b33" 
                strokeWidth="10" 
                fill="transparent" 
              />
              <circle 
                cx="80" 
                cy="80" 
                r="70" 
                stroke={compliancePercentage > 70 ? '#00ff88' : '#ff3366'} 
                strokeWidth="10" 
                fill="transparent" 
                strokeDasharray="439.8" 
                strokeDashoffset={439.8 * (1 - compliancePercentage / 100)}
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute flex flex-col items-center">
              <span className={`text-3xl font-black ${compliancePercentage > 70 ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>
                {compliancePercentage}%
              </span>
              <span className="text-[8px] text-[#64748b] tracking-wider uppercase font-bold mt-1">COMPLIANT</span>
            </div>
          </div>

          <div className="w-full space-y-2 text-[10px]">
            <div className="flex justify-between items-center p-2 bg-[#050814] rounded-lg border border-[#1e2d5a]/20">
              <span className="text-[#64748b]">Total Ingested Directives</span>
              <span className="text-white font-bold">5 Guidelines</span>
            </div>
            <div className="flex justify-between items-center p-2 bg-[#050814] rounded-lg border border-[#1e2d5a]/20">
              <span className="text-[#64748b]">Failing Guidelines</span>
              <span className="text-[#ff3366] font-bold">2 Directives</span>
            </div>
          </div>
        </div>

        {/* Explainable AI Analyst Panel */}
        <div className="lg:col-span-8 bg-[#0a0f24] border border-[#1e2d5a]/60 rounded-3xl p-6 shadow-[0_0_20px_rgba(0,0,0,0.4)] flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center border-b border-[#1e2d5a]/40 pb-3 mb-4">
              <span className="text-xs font-black text-white flex items-center gap-1.5">
                <Fingerprint className="w-4 h-4 text-[#00f0ff]" /> Explainable AI (XAI) Risk Reasonings
              </span>
              <span className={`text-[10px] px-2 py-0.5 rounded font-black tracking-widest font-mono uppercase ${
                selectedControl.status === 'FAIL' 
                  ? 'bg-[#ff3366]/10 text-[#ff3366] border border-[#ff3366]/20'
                  : selectedControl.status === 'WARNING'
                    ? 'bg-[#eab308]/10 text-[#eab308] border border-[#eab308]/20'
                    : 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20'
              }`}>
                {selectedControl.status} (Score: {selectedControl.riskScore})
              </span>
            </div>

            <div className="space-y-4 text-[11px] leading-relaxed">
              <div>
                <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">RBI DIRECTIVE MAPPED:</span>
                <p className="text-white font-bold">{selectedControl.id} - {selectedControl.directive}</p>
              </div>

              <div>
                <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">REGULATORY COMPLIANCE DESCRIPTION:</span>
                <p className="text-[#cbd5e1]">{selectedControl.requirement}</p>
              </div>

              <div>
                <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">XAI DECISION DETECTOR ANALYSIS:</span>
                <div className="bg-[#050814] p-3 rounded-xl border border-[#1e2d5a]/40 text-[#00f0ff]">
                  {selectedControl.status === 'FAIL' 
                    ? `CRITICAL COMPLIANCE FAILURE: Insider Teller Session hijacked. The system detected inconsistent keystroke dynamics (mean timing latency 50ms vs normal 120ms) paired with an unauthorized privilege change to administrator role. Standard dual-control manager authentication signature token was bypasses, violating RBI Sec. 7.3.`
                    : selectedControl.status === 'WARNING'
                      ? `WARNING DETECTED: Mobile emulator signature detected during UPI transfer. Although location coordinates align with India, execution inside an Android emulator sandbox triggers a device binding breach under RBI Sec. 4.2.`
                      : `NORMAL / SECURE: Behavioral biometric authentication patterns conform exactly to historical baseline timings. Multi-factor verification signature verified.`
                  }
                </div>
              </div>

              <div>
                <span className="text-[#64748b] block font-bold uppercase tracking-wider mb-1">AUTOMATED SUGGESTED REMEDIATION:</span>
                <p className="text-[#a855f7] font-semibold">{selectedControl.remediation}</p>
              </div>
            </div>
          </div>

          <div className="border-t border-[#1e2d5a]/40 pt-4 mt-4 text-[10px] text-[#64748b] flex justify-between items-center">
            <span>Owner Department: <span className="text-white">{selectedControl.department}</span></span>
            <span className="flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Continuous Audit: ACTIVE</span>
          </div>
        </div>

      </div>

      {/* Real-time Audit Matrix Table */}
      <div className="bg-[#0a0f24] border border-[#1e2d5a]/60 rounded-3xl p-5 shadow-[0_0_20px_rgba(0,0,0,0.4)] flex-grow">
        <h3 className="text-xs font-black tracking-widest text-[#00f0ff] uppercase mb-4 flex items-center gap-1.5">
          <Terminal className="w-4 h-4" /> RBI Regulatory Compliance Audit Matrix
        </h3>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[10px] leading-relaxed">
            <thead>
              <tr className="border-b border-[#1e2d5a] text-[#64748b] uppercase tracking-wider">
                <th className="py-2.5 px-3">RBI Control ID</th>
                <th className="py-2.5 px-3">Directive Category</th>
                <th className="py-2.5 px-3">Operational Department</th>
                <th className="py-2.5 px-3 text-center">Status</th>
                <th className="py-2.5 px-3 text-center">Risk Score</th>
                <th className="py-2.5 px-3">Remediation Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d5a]/30">
              {RBI_CONTROLS.map((ctrl) => (
                <tr 
                  key={ctrl.id} 
                  onClick={() => setSelectedControl(ctrl)}
                  className={`hover:bg-[#131b33]/40 transition-all cursor-pointer ${
                    selectedControl.id === ctrl.id ? 'bg-[#131b33]/60' : ''
                  }`}
                >
                  <td className="py-3 px-3 font-bold text-white">{ctrl.id}</td>
                  <td className="py-3 px-3 font-bold">{ctrl.directive}</td>
                  <td className="py-3 px-3 text-[#94a3b8]">{ctrl.department}</td>
                  <td className="py-3 px-3 text-center">
                    <span className={`px-2 py-0.5 rounded font-black tracking-widest font-mono uppercase ${
                      ctrl.status === 'FAIL' 
                        ? 'bg-[#ff3366]/10 text-[#ff3366] border border-[#ff3366]/20'
                        : ctrl.status === 'WARNING'
                          ? 'bg-[#eab308]/10 text-[#eab308] border border-[#eab308]/20'
                          : 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20'
                    }`}>
                      {ctrl.status}
                    </span>
                  </td>
                  <td className={`py-3 px-3 text-center font-black ${
                    ctrl.riskScore > 80 ? 'text-[#ff3366]' : ctrl.riskScore > 30 ? 'text-[#eab308]' : 'text-[#00ff88]'
                  }`}>
                    {ctrl.riskScore}
                  </td>
                  <td className="py-3 px-3 text-[#94a3b8] truncate max-w-[200px]">{ctrl.remediation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
