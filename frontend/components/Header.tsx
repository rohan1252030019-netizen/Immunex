import React from 'react';
import { useSOCStore } from '../lib/store';
import { 
  Zap, 
  Clock, 
  Cpu, 
  Activity, 
  HelpCircle,
  Database
} from 'lucide-react';

export default function Header() {
  const { metrics, alerts } = useSOCStore();
  const [time, setTime] = React.useState('');

  React.useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Compute threat level based on critical and high alerts
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL' && !a.mitigated).length;
  const highCount = alerts.filter(a => a.severity === 'HIGH' && !a.mitigated).length;

  let infracon = 'LEVEL 5 - SAFE';
  let colorClass = 'text-[#00ff88] border-[#00ff88]/30 bg-[#00ff88]/5 shadow-[0_0_10px_rgba(0,255,136,0.2)]';
  
  if (criticalCount > 0) {
    infracon = 'LEVEL 1 - CRISIS';
    colorClass = 'text-[#ff3366] border-[#ff3366]/40 bg-[#ff3366]/10 shadow-[0_0_15px_rgba(255,51,102,0.3)] animate-pulse';
  } else if (highCount > 0) {
    infracon = 'LEVEL 2 - HOSTILE';
    colorClass = 'text-[#ff9900] border-[#ff9900]/30 bg-[#ff9900]/5 shadow-[0_0_10px_rgba(255,153,0,0.2)]';
  } else if (alerts.length > 0) {
    infracon = 'LEVEL 3 - ACTIVE';
    colorClass = 'text-[#00f0ff] border-[#00f0ff]/30 bg-[#00f0ff]/5 shadow-[0_0_10px_rgba(0,240,255,0.2)]';
  }

  return (
    <header className="h-16 border-b border-[#1e293b]/50 bg-[#070b19] px-6 flex items-center justify-between text-white flex-shrink-0">
      {/* Title & Threat Level */}
      <div className="flex items-center gap-6">
        <div className="flex flex-col">
          <h1 className="text-sm font-semibold tracking-wider font-mono uppercase text-[#e2e8f0]">
            Command Console
          </h1>
          <p className="text-[10px] font-mono text-[#64748b]">
            SYSTEM INTEGRITY MONITOR
          </p>
        </div>
        
        {/* INFRA CON Badge */}
        <div className={`px-3 py-1 text-xs border font-mono rounded tracking-widest ${colorClass}`}>
          {infracon}
        </div>
      </div>

      {/* Real-time stats */}
      <div className="flex items-center gap-6">
        {/* EPS */}
        <div className="flex items-center gap-2 border-r border-[#1e293b]/50 pr-4">
          <Zap className="w-4 h-4 text-[#00f0ff]" />
          <div className="flex flex-col">
            <span className="text-xs font-mono font-bold text-white">{metrics.eps.toFixed(1)}</span>
            <span className="text-[9px] font-mono text-[#64748b] tracking-wider">EVENTS/SEC</span>
          </div>
        </div>

        {/* Latency */}
        <div className="flex items-center gap-2 border-r border-[#1e293b]/50 pr-4">
          <Cpu className="w-4 h-4 text-[#00f0ff]" />
          <div className="flex flex-col">
            <span className="text-xs font-mono font-bold text-white">
              {metrics.latency.toFixed(1)} ms
            </span>
            <span className="text-[9px] font-mono text-[#64748b] tracking-wider">LATENCY</span>
          </div>
        </div>

        {/* Total Processed */}
        <div className="flex items-center gap-2 border-r border-[#1e293b]/50 pr-4">
          <Activity className="w-4 h-4 text-[#00f0ff]" />
          <div className="flex flex-col">
            <span className="text-xs font-mono font-bold text-white">
              {metrics.events_processed.toLocaleString()}
            </span>
            <span className="text-[9px] font-mono text-[#64748b] tracking-wider">TOTAL INGEST</span>
          </div>
        </div>

        {/* Database Mode */}
        <div className="flex items-center gap-2 border-r border-[#1e293b]/50 pr-4 text-[#00ff88]">
          <Database className="w-4 h-4" />
          <div className="flex flex-col text-[#94a3b8]">
            <span className="text-[10px] font-mono font-bold uppercase text-[#00ff88]">OFFLINE-SEC</span>
            <span className="text-[8px] font-mono tracking-wider">LOCAL DATASTORE</span>
          </div>
        </div>

        {/* Clock */}
        <div className="flex items-center gap-2 text-[#94a3b8] font-mono text-xs">
          <Clock className="w-4 h-4 text-[#64748b]" />
          <span className="tracking-wider tabular-nums">{time}</span>
        </div>
      </div>
    </header>
  );
}
