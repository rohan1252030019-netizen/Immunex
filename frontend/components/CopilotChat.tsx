import React from 'react';
import { useSOCStore, ChatMessage } from '../lib/store';
import { copilotApi } from '../lib/api';
import { 
  Bot, 
  Send, 
  Terminal, 
  Search, 
  ShieldCheck, 
  AlertTriangle,
  Code,
  Binary,
  Copy,
  FolderLock
} from 'lucide-react';
import { motion } from 'framer-motion';

export default function CopilotChat() {
  const { chatMessages, addChatMessage } = useSOCStore();
  const [input, setInput] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const scrollRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [chatMessages]);

  const handleSendMessage = async (text: string) => {
    if (!text.trim()) return;

    const userMsg: ChatMessage = {
      id: Math.random().toString(),
      sender: 'user',
      text: text,
      timestamp: new Date().toLocaleTimeString(),
    };
    addChatMessage(userMsg);
    setInput('');
    setLoading(true);

    try {
      let responseText = '';
      let sigmaRule = undefined;
      let yaraRule = undefined;
      let complianceControls = undefined;
      let investigationDetails = undefined;
      let mitreMapping = undefined;

      // Handle Slash commands
      const trimmedText = text.trim();
      if (trimmedText.startsWith('/hunt')) {
        const query = trimmedText.replace('/hunt', '').trim();
        const result = await copilotApi.hunt(query || 'score > 0.6');
        responseText = `Autonomous Hunt Completed. Found **${result.events_matched?.length || result.results?.length || 0}** events matching your hunting heuristics.`;
        investigationDetails = result;
      } 
      else if (trimmedText.startsWith('/investigate')) {
        const alertId = trimmedText.replace('/investigate', '').trim();
        const result = await copilotApi.investigate(alertId || 'last');
        responseText = `Blast Radius & Attack Chain analysis completed for threat node **${result.node_id || alertId}**. System generated containment actions.`;
        investigationDetails = result;
        complianceControls = result.compliance_impact;
        mitreMapping = result.mitre_explainer;
      } 
      else if (trimmedText.startsWith('/sigma')) {
        const alertId = trimmedText.replace('/sigma', '').trim();
        const result = await copilotApi.generateSigma(alertId || 'last');
        responseText = `Sigma Detection Signature generated successfully for mitigation ingestion.`;
        sigmaRule = result.rule || result.sigma || result.yaml;
      } 
      else if (trimmedText.startsWith('/yara')) {
        const alertId = trimmedText.replace('/yara', '').trim();
        const result = await copilotApi.generateYara(alertId || 'last');
        responseText = `YARA Binary Signature generated successfully for host quarantine scanning.`;
        yaraRule = result.rule || result.yara;
      } 
      else {
        // Standard Ask
        const result = await copilotApi.ask(text);
        responseText = result.answer || result.response || "I've analyzed the request, but no response was generated.";
        complianceControls = result.compliance;
        mitreMapping = result.mitre_explainer;
      }

      addChatMessage({
        id: Math.random().toString(),
        sender: 'copilot',
        text: responseText,
        timestamp: new Date().toLocaleTimeString(),
        sigmaRule,
        yaraRule,
        complianceControls,
        investigationDetails,
        mitreMapping
      });
    } catch (err) {
      addChatMessage({
        id: Math.random().toString(),
        sender: 'copilot',
        text: `Command error: ${err instanceof Error ? err.message : 'Unknown exception while interacting with backend copilot fabric.'}`,
        timestamp: new Date().toLocaleTimeString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  const suggestedPrompts = [
    { label: 'Examine Critical Paths to Crown Jewels', cmd: '/investigate last' },
    { label: 'Hunt suspicious process anomalies', cmd: '/hunt score > 0.8' },
    { label: 'Generate YARA filter for active memory threat', cmd: '/yara last' },
    { label: 'Assess system status against SOC2 controls', cmd: 'Are we compliant with SOC2 CC6.1?' },
  ];

  return (
    <div className="flex-1 flex flex-col bg-[#050814] h-[calc(100vh-64px)] overflow-hidden text-white">
      {/* Messages Window */}
      <div ref={scrollRef} className="flex-grow overflow-y-auto p-6 space-y-6 scrollbar-thin">
        {chatMessages.map((msg) => (
          <div key={msg.id} className={`flex gap-4 ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {msg.sender === 'copilot' && (
              <div className="w-9 h-9 rounded-xl bg-[#00f0ff]/10 border border-[#00f0ff]/30 flex items-center justify-center text-[#00f0ff] flex-shrink-0 shadow-[0_0_10px_rgba(0,240,255,0.2)]">
                <Bot className="w-5 h-5" />
              </div>
            )}
            
            <div className="max-w-[75%] space-y-2">
              <div className={`p-4 rounded-2xl border ${
                msg.sender === 'user'
                  ? 'bg-[#1b254b]/75 border-[#00f0ff]/30 text-white rounded-tr-none'
                  : 'bg-[#0d1326]/75 border-[#1e293b]/50 text-[#cbd5e1] rounded-tl-none shadow-[0_4px_20px_rgba(0,0,0,0.2)]'
              }`}>
                <p className="text-sm font-mono leading-relaxed select-text whitespace-pre-wrap">
                  {msg.text}
                </p>
                
                {/* Special Inline Renderers */}
                
                {/* YARA / Sigma Rules */}
                {(msg.sigmaRule || msg.yaraRule) && (
                  <div className="mt-4 border border-[#1e293b] rounded-xl bg-[#050814] overflow-hidden">
                    <div className="flex items-center justify-between p-2.5 bg-[#131b31] border-b border-[#1e293b] text-xs font-mono">
                      <div className="flex items-center gap-1.5 text-[#00f0ff]">
                        {msg.sigmaRule ? <Code className="w-4 h-4 text-[#ff9900]" /> : <Binary className="w-4 h-4 text-[#00ff88]" />}
                        <span>{msg.sigmaRule ? 'SIGMA RULE' : 'YARA RULE'}</span>
                      </div>
                      <button 
                        onClick={() => handleCopy(msg.sigmaRule || msg.yaraRule || '')}
                        className="flex items-center gap-1 hover:text-[#00f0ff] transition-all"
                      >
                        <Copy className="w-3.5 h-3.5" />
                        COPY
                      </button>
                    </div>
                    <pre className="p-3 text-[10px] font-mono overflow-x-auto max-h-48 text-[#94a3b8] scrollbar-thin select-all">
                      {msg.sigmaRule || msg.yaraRule}
                    </pre>
                  </div>
                )}

                {/* Compliance Accordion */}
                {msg.complianceControls && (
                  <div className="mt-4 border border-[#1e293b] rounded-xl bg-[#050814] overflow-hidden p-3 space-y-2">
                    <div className="flex items-center gap-1.5 text-[#00ff88] text-xs font-mono mb-2">
                      <ShieldCheck className="w-4 h-4" />
                      <span>APPLICABLE COMPLIANCE CONTROLS</span>
                    </div>
                    <div className="grid grid-cols-1 gap-2">
                      {Object.entries(msg.complianceControls).map(([framework, control]: any) => (
                        <div key={framework} className="text-[11px] font-mono bg-[#131b31]/40 border border-[#1e293b] p-2 rounded">
                          <span className="text-[#00f0ff] uppercase block font-bold mb-0.5">{framework}</span>
                          <span className="text-white font-bold">{control.control || control}</span>
                          {control.description && <p className="text-[9px] text-[#64748b] mt-1">{control.description}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Investigation / Lateral Movement Outputs */}
                {msg.investigationDetails && (
                  <div className="mt-4 border border-[#1e293b] rounded-xl bg-[#050814] overflow-hidden p-4 space-y-3">
                    <div className="flex items-center gap-1.5 text-[#ff3366] text-xs font-mono mb-2">
                      <AlertTriangle className="w-4 h-4" />
                      <span>GRAPH TRAVERSAL FINDINGS</span>
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                      <div>
                        <span className="text-[#64748b] block text-[9px]">Crown Jewel Infiltration</span>
                        <span className={`font-bold ${msg.investigationDetails.crown_jewel_exposed ? 'text-[#ff3366]' : 'text-[#00ff88]'}`}>
                          {msg.investigationDetails.crown_jewel_exposed ? 'EXPOSED' : 'PROTECTED'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[#64748b] block text-[9px]">Affected Nodes Count</span>
                        <span className="font-bold text-white">
                          {msg.investigationDetails.blast_radius?.length || msg.investigationDetails.affected_nodes || 0} Assets
                        </span>
                      </div>
                    </div>

                    {msg.investigationDetails.containment_playbook && (
                      <div className="text-[11px] font-mono bg-[#ef4444]/5 border border-[#ef4444]/20 p-2.5 rounded-lg mt-2">
                        <span className="text-[#ff3366] font-bold block mb-1">CONTAINMENT PLAYBOOK</span>
                        <p className="text-[#cbd5e1] leading-relaxed">{msg.investigationDetails.containment_playbook}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
              
              <span className={`text-[9px] font-mono text-[#64748b] block ${msg.sender === 'user' ? 'text-right' : 'text-left'}`}>
                {msg.timestamp}
              </span>
            </div>

            {msg.sender === 'user' && (
              <div className="w-9 h-9 rounded-xl bg-[#1b254b]/50 border border-[#00f0ff]/20 flex items-center justify-center text-white flex-shrink-0">
                <span className="font-mono text-xs uppercase font-bold">OP</span>
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-4">
            <div className="w-9 h-9 rounded-xl bg-[#00f0ff]/10 border border-[#00f0ff]/30 flex items-center justify-center text-[#00f0ff] flex-shrink-0 animate-pulse">
              <Bot className="w-5 h-5" />
            </div>
            <div className="p-4 bg-[#0d1326]/50 border border-[#1e293b]/30 rounded-2xl rounded-tl-none max-w-[70%]">
              <div className="flex gap-1.5 items-center">
                <span className="w-2 h-2 bg-[#00f0ff] rounded-full animate-bounce [animation-delay:-0.3s]" />
                <span className="w-2 h-2 bg-[#00f0ff] rounded-full animate-bounce [animation-delay:-0.15s]" />
                <span className="w-2 h-2 bg-[#00f0ff] rounded-full animate-bounce" />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Suggested Prompts Grid */}
      {chatMessages.length <= 1 && (
        <div className="px-6 py-2 grid grid-cols-1 md:grid-cols-2 gap-2 bg-[#050814]/80">
          {suggestedPrompts.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(p.cmd)}
              className="text-left p-2 border border-[#1e293b]/50 rounded-xl bg-[#0d1326]/40 hover:bg-[#131b31]/50 text-xs font-mono text-[#94a3b8] hover:text-white transition-all"
            >
              {p.label}
            </button>
          ))}
        </div>
      )}

      {/* Input Bar */}
      <div className="p-4 border-t border-[#1e293b]/50 bg-[#070b19]">
        <div className="flex gap-3 bg-[#0d1326] border border-[#1e293b] rounded-xl px-4 py-2 relative items-center">
          <Terminal className="w-4 h-4 text-[#64748b] flex-shrink-0" />
          <input
            type="text"
            placeholder="Instruct copilot (e.g. /hunt anomaly_score > 0.7, /investigate last_alert, or regular questions)..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSendMessage(input);
            }}
            disabled={loading}
            className="flex-grow bg-transparent border-none outline-none text-sm text-[#e2e8f0] font-mono focus:ring-0 placeholder-[#64748b]"
          />
          <button
            onClick={() => handleSendMessage(input)}
            disabled={loading || !input.trim()}
            className="p-1.5 bg-[#00f0ff] hover:bg-[#00d8e6] disabled:bg-[#1e293b] disabled:text-[#64748b] text-[#050814] rounded-lg transition-all shadow-[0_0_10px_rgba(0,240,255,0.4)] disabled:shadow-none"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
