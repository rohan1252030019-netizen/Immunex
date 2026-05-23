import React from 'react';
import { useSOCStore } from '../lib/store';
import { 
  Zap, 
  Clock, 
  Cpu, 
  Activity, 
  ShieldAlert,
  Server
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, YAxis } from 'recharts';

export default function MetricsPanel() {
  const { metrics, alerts } = useSOCStore();
  const [epsHistory, setEpsHistory] = React.useState<{ time: number; eps: number }[]>([]);

  // Maintain a running history of EPS for the graph
  React.useEffect(() => {
    const interval = setInterval(() => {
      setEpsHistory(prev => {
        const next = [...prev, { time: Date.now(), eps: metrics.eps + (Math.random() - 0.5) * 0.5 }];
        if (next.length > 20) next.shift();
        return next;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [metrics.eps]);

  const cards = [
    {
      title: 'EVENTS PER SECOND',
      value: metrics.eps.toFixed(1),
      subtext: 'Real-time telemetry intake',
      icon: Zap,
      color: 'text-[#00f0ff]',
      bgColor: 'bg-[#00f0ff]/5',
      borderColor: 'border-[#00f0ff]/20',
      shadowColor: 'rgba(0, 240, 255, 0.1)',
    },
    {
      title: 'DETECTION LATENCY',
      value: `${metrics.latency.toFixed(2)} ms`,
      subtext: 'Model inference overhead',
      icon: Cpu,
      color: 'text-[#ff9900]',
      bgColor: 'bg-[#ff9900]/5',
      borderColor: 'border-[#ff9900]/20',
      shadowColor: 'rgba(255, 153, 0, 0.1)',
    },
    {
      title: 'MEAN TIME TO RESOLVE',
      value: metrics.mttr || '1.8m',
      subtext: 'Auto-containment speed',
      icon: Clock,
      color: 'text-[#00ff88]',
      bgColor: 'bg-[#00ff88]/5',
      borderColor: 'border-[#00ff88]/20',
      shadowColor: 'rgba(0, 255, 136, 0.1)',
    },
    {
      title: 'ACTIVE CAMPAIGNS',
      value: metrics.campaigns.toString(),
      subtext: 'Correlated attack chains',
      icon: ShieldAlert,
      color: 'text-[#ff3366]',
      bgColor: 'bg-[#ff3366]/5',
      borderColor: 'border-[#ff3366]/20',
      shadowColor: 'rgba(255, 51, 102, 0.1)',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 p-6 bg-[#050814]">
      {cards.map((card, idx) => (
        <div 
          key={idx}
          className={`p-5 rounded-2xl border ${card.bgColor} ${card.borderColor} flex flex-col relative overflow-hidden transition-all duration-300 hover:scale-[1.02]`}
          style={{ boxShadow: `0 4px 20px ${card.shadowColor}` }}
        >
          <div className="flex items-center justify-between mb-4">
            <span className="text-[10px] font-mono font-bold tracking-widest text-[#94a3b8]">
              {card.title}
            </span>
            <card.icon className={`w-5 h-5 ${card.color}`} />
          </div>

          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-2xl font-bold font-mono text-white tracking-wider">
              {card.value}
            </span>
          </div>

          <span className="text-xs font-mono text-[#64748b]">
            {card.subtext}
          </span>

          {/* Sparkline for EPS card */}
          {card.title === 'EVENTS PER SECOND' && epsHistory.length > 1 && (
            <div className="h-12 w-full mt-4 -mx-5 -mb-5 flex-grow opacity-60">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={epsHistory}>
                  <defs>
                    <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <YAxis domain={['dataMin - 0.5', 'dataMax + 0.5']} hide />
                  <Area 
                    type="monotone" 
                    dataKey="eps" 
                    stroke="#00f0ff" 
                    strokeWidth={1.5}
                    fillOpacity={1} 
                    fill="url(#epsGrad)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
