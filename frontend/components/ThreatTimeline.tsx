import React from 'react';
import { useSOCStore } from '../lib/store';
import { socApi } from '../lib/api';
import { Clock, ShieldAlert, Cpu, CheckCircle } from 'lucide-react';

interface TimelineItem {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  event_type: string;
  anomaly_score: number;
  description: string;
  mitigated: boolean;
}

export default function ThreatTimeline() {
  const { alerts } = useSOCStore();
  const [timelineItems, setTimelineItems] = React.useState<TimelineItem[]>([]);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    const fetchTimeline = async () => {
      setLoading(true);
      try {
        const result = await socApi.getTimeline();
        // Fallback to alerts if timeline is empty
        if (result && result.length > 0) {
          setTimelineItems(result);
        } else {
          // Construct timeline from alerts sorted chronologically
          const sorted = [...alerts]
            .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
          setTimelineItems(sorted);
        }
      } catch (err) {
        console.error('Error fetching timeline:', err);
        const sorted = [...alerts]
          .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        setTimelineItems(sorted);
      } finally {
        setLoading(false);
      }
    };
    fetchTimeline();
  }, [alerts]);

  return (
    <div className="flex-1 flex flex-col bg-[#050814] p-6 h-[calc(100vh-64px)] overflow-hidden text-white font-mono">
      <div className="flex items-center gap-2 mb-6 pb-4 border-b border-[#1e293b]/50">
        <Clock className="w-5 h-5 text-[#00f0ff]" />
        <h2 className="font-bold text-sm tracking-wider uppercase">Chronological Threat Timeline</h2>
      </div>

      <div className="flex-grow overflow-y-auto pr-4 relative scrollbar-thin">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-6 h-6 border-2 border-t-transparent border-[#00f0ff] rounded-full animate-spin" />
          </div>
        ) : timelineItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 border border-[#1e293b]/30 rounded-xl bg-[#0d1326]/30">
            <CheckCircle className="w-8 h-8 text-[#00ff88] mb-2" />
            <span className="text-xs text-[#64748b]">NO INCIDENTS REGISTERED IN THE HISTORICAL TIMELINE</span>
          </div>
        ) : (
          <div className="relative border-l-2 border-[#1e293b] ml-4 pl-8 py-4 space-y-8">
            {timelineItems.map((item, index) => (
              <div key={item.id || index} className="relative">
                {/* Node Dot */}
                <div className={`absolute -left-[41px] top-1.5 w-6 h-6 rounded-full border flex items-center justify-center ${
                  item.mitigated 
                    ? 'bg-[#050814] border-[#00ff88] text-[#00ff88]' 
                    : 'bg-[#050814] border-[#ff3366] text-[#ff3366] shadow-[0_0_8px_rgba(255,51,102,0.3)] animate-pulse'
                }`}>
                  {item.mitigated ? <CheckCircle className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                </div>

                {/* Card */}
                <div className="p-4 bg-[#0d1326]/70 border border-[#1e293b]/60 rounded-xl relative max-w-3xl transition-all hover:border-[#00f0ff]/40">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] text-[#64748b] block">{item.timestamp}</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      item.mitigated ? 'bg-[#00ff88]/10 text-[#00ff88]' : 'bg-[#ff3366]/10 text-[#ff3366]'
                    }`}>
                      {item.mitigated ? 'CONTAINED' : 'EXPOSED'}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 bg-[#1e293b] text-[#cbd5e1] border border-[#334155]/50">
                      {item.event_type}
                    </span>
                    <span className="text-[10px] font-bold text-[#ff3366]">ANOMALY: {(item.anomaly_score * 100).toFixed(0)}%</span>
                  </div>

                  <p className="text-xs text-[#cbd5e1] leading-relaxed mb-3">{item.description}</p>

                  <div className="flex items-center gap-2 text-[10px] text-[#64748b]">
                    <span>Source IP:</span> <span className="text-[#00f0ff]">{item.source_ip}</span>
                    <span className="mx-1">|</span>
                    <span>Dest IP:</span> <span className="text-[#ff3366]">{item.destination_ip}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
