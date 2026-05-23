import React from 'react';
import { useSOCStore, Alert } from '../lib/store';
import { copilotApi } from '../lib/api';
import { 
  ShieldAlert, 
  Search, 
  Terminal, 
  Code, 
  Binary, 
  Play, 
  CheckCircle,
  Copy,
  ExternalLink
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function AlertStream() {
  const { alerts, activeAlertDetails, setActiveAlertDetails, addChatMessage, setActiveTab } = useSOCStore();
  const [searchTerm, setSearchTerm] = React.useState('');
  const [filterSeverity, setFilterSeverity] = React.useState('ALL');
  const [loadingAction, setLoadingAction] = React.useState<string | null>(null);
  const [ruleModal, setRuleModal] = React.useState<{ type: 'sigma' | 'yara'; rule: string; alertId: string } | null>(null);

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'border-[#ff3366] bg-[#ff3366]/5 text-[#ff3366] shadow-[0_0_8px_rgba(255,51,102,0.1)]';
      case 'HIGH':
        return 'border-[#ff9900] bg-[#ff9900]/5 text-[#ff9900] shadow-[0_0_8px_rgba(255,153,0,0.1)]';
      case 'MEDIUM':
        return 'border-[#00f0ff] bg-[#00f0ff]/5 text-[#00f0ff]';
      case 'LOW':
      default:
        return 'border-[#94a3b8] bg-[#94a3b8]/5 text-[#94a3b8]';
    }
  };

  const handleInvestigate = async (alert: Alert) => {
    setActiveTab('copilot');
    const store = useSOCStore.getState();
    // Add user question
    store.addChatMessage({
      id: Math.random().toString(),
      sender: 'user',
      text: `/investigate ${alert.id}`,
      timestamp: new Date().toLocaleTimeString(),
    });

    try {
      // Direct call to investigate API
      const result = await copilotApi.investigate(alert.id);
      store.addChatMessage({
        id: Math.random().toString(),
        sender: 'copilot',
        text: `Autonomous Graph Investigation launched for alert **${alert.id}** (${alert.event_type}).`,
        timestamp: new Date().toLocaleTimeString(),
        investigationDetails: result,
      });
    } catch (err) {
      store.addChatMessage({
        id: Math.random().toString(),
        sender: 'copilot',
        text: `Error during graph investigation: ${err instanceof Error ? err.message : 'Unknown error'}`,
        timestamp: new Date().toLocaleTimeString(),
      });
    }
  };

  const handleGenerateRule = async (alert: Alert, type: 'sigma' | 'yara') => {
    setLoadingAction(`${alert.id}-${type}`);
    try {
      const result = type === 'sigma' 
        ? await copilotApi.generateSigma(alert.id)
        : await copilotApi.generateYara(alert.id);
      
      setRuleModal({
        type,
        rule: result.rule || result.sigma || result.yara || 'Rule could not be generated.',
        alertId: alert.id
      });
    } catch (err) {
      console.error(err);
      window.alert(`Error generating ${type.toUpperCase()} rule`);
    } finally {
      setLoadingAction(null);
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = 
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.destination_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesSeverity = filterSeverity === 'ALL' || alert.severity === filterSeverity;
    
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="flex-1 flex gap-6 p-6 h-[calc(100vh-64px)] overflow-hidden bg-[#050814] text-white">
      {/* Stream Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Filters Header */}
        <div className="flex items-center justify-between gap-4 mb-4 p-4 bg-[#0d1326] border border-[#1e293b]/50 rounded-xl">
          <div className="flex items-center gap-2 flex-1 max-w-md relative">
            <Search className="w-4 h-4 text-[#64748b] absolute left-3" />
            <input 
              type="text"
              placeholder="Search threat indicators (IP, Event Type, Description)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#131b31] border border-[#1e293b]/80 rounded-lg pl-10 pr-4 py-2 text-sm text-[#e2e8f0] focus:outline-none focus:border-[#00f0ff]/50 font-mono"
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-[#64748b] font-mono uppercase tracking-wider">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-[#131b31] border border-[#1e293b]/80 text-sm text-[#e2e8f0] rounded-lg px-3 py-1.5 focus:outline-none focus:border-[#00f0ff]/50 font-mono"
            >
              <option value="ALL">ALL LEVELS</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>

        {/* Live List */}
        <div className="flex-1 overflow-y-auto pr-2 space-y-3 scrollbar-thin">
          <AnimatePresence initial={false}>
            {filteredAlerts.length === 0 ? (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center h-48 border border-[#1e293b]/30 rounded-xl bg-[#0d1326]/30"
              >
                <CheckCircle className="w-8 h-8 text-[#00ff88] mb-2 animate-bounce" />
                <span className="text-sm font-mono text-[#64748b]">SYSTEM CLEAR — NO ACTIVE THREATS</span>
              </motion.div>
            ) : (
              filteredAlerts.map((alert) => (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, x: -100 }}
                  transition={{ duration: 0.2 }}
                  onClick={() => setActiveAlertDetails(alert)}
                  className={`p-4 border rounded-xl bg-[#0d1326]/75 hover:bg-[#131b31] cursor-pointer transition-all duration-200 relative group ${
                    activeAlertDetails?.id === alert.id ? 'border-[#00f0ff] ring-1 ring-[#00f0ff]/30 shadow-[0_0_15px_rgba(0,240,255,0.05)]' : 'border-[#1e293b]/50'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 border rounded-lg ${getSeverityStyle(alert.severity)}`}>
                        <ShieldAlert className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[#1e293b] text-[#cbd5e1] border border-[#334155]/50">
                            {alert.event_type}
                          </span>
                          <span className="text-[10px] text-[#64748b] font-mono">
                            {alert.timestamp.substring(11, 19) || alert.timestamp}
                          </span>
                        </div>
                        <p className="text-sm font-semibold mt-1 text-[#f1f5f9] font-mono line-clamp-1">
                          {alert.description}
                        </p>
                        <div className="flex items-center gap-2 mt-2 text-xs font-mono text-[#94a3b8]">
                          <span className="text-[#00f0ff]">{alert.source_ip}</span>
                          <span>&rarr;</span>
                          <span className="text-[#ff3366]">{alert.destination_ip}</span>
                        </div>
                      </div>
                    </div>

                    {/* Threat Score & Actions */}
                    <div className="flex flex-col items-end gap-2">
                      <span className="text-sm font-bold font-mono text-[#ff3366] bg-[#ff3366]/10 px-2 py-0.5 rounded border border-[#ff3366]/20">
                        ANOMALY: {(alert.anomaly_score * 100).toFixed(0)}%
                      </span>
                      <div className="flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={(e) => { e.stopPropagation(); handleInvestigate(alert); }}
                          title="Auto Investigate"
                          className="p-1.5 bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/20 rounded-lg transition-all"
                        >
                          <Play className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleGenerateRule(alert, 'sigma'); }}
                          title="Generate Sigma"
                          className="p-1.5 bg-[#ff9900]/10 hover:bg-[#ff9900]/20 text-[#ff9900] border border-[#ff9900]/20 rounded-lg transition-all"
                        >
                          {loadingAction === `${alert.id}-sigma` ? (
                            <div className="w-3.5 h-3.5 border-2 border-t-transparent border-[#ff9900] rounded-full animate-spin" />
                          ) : (
                            <Code className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleGenerateRule(alert, 'yara'); }}
                          title="Generate YARA"
                          className="p-1.5 bg-[#00ff88]/10 hover:bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/20 rounded-lg transition-all"
                        >
                          {loadingAction === `${alert.id}-yara` ? (
                            <div className="w-3.5 h-3.5 border-2 border-t-transparent border-[#00ff88] rounded-full animate-spin" />
                          ) : (
                            <Binary className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Details Side Panel */}
      {activeAlertDetails && (
        <motion.div 
          initial={{ width: 0, opacity: 0 }}
          animate={{ width: 420, opacity: 1 }}
          className="flex flex-col bg-[#0d1326] border border-[#1e293b]/80 rounded-2xl overflow-hidden p-5 flex-shrink-0"
        >
          <div className="flex items-center justify-between pb-3 border-b border-[#1e293b]/80">
            <h3 className="font-mono font-bold tracking-wider text-[#00f0ff]">INCIDENT FORENSICS</h3>
            <button 
              onClick={() => setActiveAlertDetails(null)}
              className="text-xs font-mono text-[#64748b] hover:text-white px-2 py-1 bg-[#131b31] border border-[#1e293b]/80 rounded"
            >
              CLOSE
            </button>
          </div>

          <div className="flex-grow overflow-y-auto space-y-4 pt-4 scrollbar-thin">
            <div>
              <span className="text-[10px] font-mono text-[#64748b] block">INCIDENT ID</span>
              <span className="text-xs font-mono text-white block select-all">{activeAlertDetails.id}</span>
            </div>

            <div>
              <span className="text-[10px] font-mono text-[#64748b] block">DESCRIPTION</span>
              <p className="text-sm font-mono text-[#e2e8f0]">{activeAlertDetails.description}</p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">SOURCE IP</span>
                <span className="text-xs font-mono text-[#00f0ff]">{activeAlertDetails.source_ip}</span>
              </div>
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">DESTINATION IP</span>
                <span className="text-xs font-mono text-[#ff3366]">{activeAlertDetails.destination_ip}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">SEVERITY LEVEL</span>
                <span className={`text-xs font-mono font-bold ${
                  activeAlertDetails.severity === 'CRITICAL' ? 'text-[#ff3366]' :
                  activeAlertDetails.severity === 'HIGH' ? 'text-[#ff9900]' : 'text-[#00f0ff]'
                }`}>{activeAlertDetails.severity}</span>
              </div>
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block">MITIGATION STATUS</span>
                <span className={`text-xs font-mono ${activeAlertDetails.mitigated ? 'text-[#00ff88]' : 'text-[#ff3366]'}`}>
                  {activeAlertDetails.mitigated ? 'ISOLATED' : 'ACTIVE THREAT'}
                </span>
              </div>
            </div>

            {activeAlertDetails.mitre_techniques && activeAlertDetails.mitre_techniques.length > 0 && (
              <div>
                <span className="text-[10px] font-mono text-[#64748b] block mb-1">MITRE ATT&CK TECHNIQUES</span>
                <div className="flex flex-wrap gap-1">
                  {activeAlertDetails.mitre_techniques.map(tech => (
                    <span key={tech} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#131b31] border border-[#00f0ff]/30 text-[#00f0ff]">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div>
              <span className="text-[10px] font-mono text-[#64748b] block mb-1.5">TELEMETRY PAYLOAD</span>
              <pre className="text-[10px] font-mono p-3 bg-[#070a14] rounded-lg border border-[#1e293b]/80 overflow-x-auto text-[#cbd5e1] max-h-48 scrollbar-thin">
                {JSON.stringify(activeAlertDetails.raw_payload || activeAlertDetails, null, 2)}
              </pre>
            </div>
          </div>

          <div className="border-t border-[#1e293b]/80 pt-4 space-y-2">
            <button
              onClick={() => handleInvestigate(activeAlertDetails)}
              className="w-full flex items-center justify-center gap-2 py-2 px-4 bg-gradient-to-r from-[#00f0ff]/20 to-[#00f0ff]/5 hover:from-[#00f0ff]/30 hover:to-[#00f0ff]/10 text-white font-mono text-xs border border-[#00f0ff]/40 rounded-xl transition-all shadow-[0_0_12px_rgba(0,240,255,0.1)]"
            >
              <Terminal className="w-4 h-4 text-[#00f0ff]" />
              LAUNCH GRAPH INVESTIGATION
            </button>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => handleGenerateRule(activeAlertDetails, 'sigma')}
                className="flex items-center justify-center gap-2 py-2 px-4 bg-[#ff9900]/10 hover:bg-[#ff9900]/20 text-[#ff9900] border border-[#ff9900]/30 rounded-xl font-mono text-xs transition-all"
              >
                <Code className="w-3.5 h-3.5" />
                SIGMA RULE
              </button>
              <button
                onClick={() => handleGenerateRule(activeAlertDetails, 'yara')}
                className="flex items-center justify-center gap-2 py-2 px-4 bg-[#00ff88]/10 hover:bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/30 rounded-xl font-mono text-xs transition-all"
              >
                <Binary className="w-3.5 h-3.5" />
                YARA RULE
              </button>
            </div>
          </div>
        </motion.div>
      )}

      {/* Signature Code Modal */}
      {ruleModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-6">
          <motion.div 
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="w-full max-w-3xl bg-[#0d1326] border border-[#1e293b] rounded-2xl overflow-hidden flex flex-col max-h-[85vh] shadow-[0_0_50px_rgba(0,240,255,0.15)]"
          >
            <div className="flex items-center justify-between p-4 border-b border-[#1e293b] bg-[#131b31]">
              <div className="flex items-center gap-2">
                {ruleModal.type === 'sigma' ? <Code className="w-5 h-5 text-[#ff9900]" /> : <Binary className="w-5 h-5 text-[#00ff88]" />}
                <span className="font-mono text-sm font-bold uppercase tracking-wider text-white">
                  {ruleModal.type.toUpperCase()} DETECTION SIGNATURE ({ruleModal.alertId.substring(0, 8)})
                </span>
              </div>
              <button 
                onClick={() => setRuleModal(null)}
                className="text-xs font-mono text-[#64748b] hover:text-white px-2 py-1 bg-[#0d1326] border border-[#1e293b] rounded"
              >
                CLOSE
              </button>
            </div>
            <div className="flex-1 p-5 overflow-auto bg-[#050814]">
              <pre className="text-xs font-mono p-4 bg-[#070a14] rounded-xl border border-[#1e293b]/60 overflow-x-auto text-[#cbd5e1] select-all scrollbar-thin">
                {ruleModal.rule}
              </pre>
            </div>
            <div className="p-4 border-t border-[#1e293b] bg-[#131b31] flex justify-end gap-2">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(ruleModal.rule);
                  alert('Copied to clipboard!');
                }}
                className="flex items-center gap-1.5 py-1.5 px-4 bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/30 rounded-lg text-xs font-mono transition-all"
              >
                <Copy className="w-3.5 h-3.5" />
                COPY TO CLIPBOARD
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
}
