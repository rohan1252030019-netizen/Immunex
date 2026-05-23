import React from 'react';
import { useSOCStore } from '../lib/store';
import { socApi } from '../lib/api';
import { 
  Server, 
  Cpu, 
  Activity, 
  Database, 
  Layers, 
  ShieldCheck, 
  AlertCircle
} from 'lucide-react';

export default function ClusterMonitor() {
  const { clusterStatus, setClusterStatus } = useSOCStore();
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    const fetchStatus = async () => {
      setLoading(true);
      try {
        const data = await socApi.getClusterStatus();
        if (data) setClusterStatus(data);
      } catch (err) {
        console.error('Error fetching cluster status:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [setClusterStatus]);

  // Default Mock data if offline/empty
  const mockWorkers = [
    { id: 'worker-01', type: 'Telemetry Ingest', status: 'healthy', throughput: 145.2, latency: 1.2, cpu: 12, ram: 14 },
    { id: 'worker-02', type: 'Reasoning Ensemble', status: 'healthy', throughput: 14.8, latency: 12.4, cpu: 45, ram: 38 },
    { id: 'worker-03', type: 'Graph Analytics (GNN)', status: 'healthy', throughput: 8.5, latency: 22.1, cpu: 60, ram: 52 },
    { id: 'worker-04', type: 'Correlation Engine', status: 'healthy', throughput: 120.4, latency: 4.8, cpu: 22, ram: 18 },
    { id: 'worker-05', type: 'Mitigation Executor', status: 'healthy', throughput: 2.1, latency: 0.8, cpu: 5, ram: 10 },
  ];

  const workers = clusterStatus.workers && clusterStatus.workers.length > 0 ? clusterStatus.workers : mockWorkers;
  
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
      case 'online':
        return <ShieldCheck className="w-4 h-4 text-[#00ff88]" />;
      case 'throttled':
      case 'degraded':
        return <Activity className="w-4 h-4 text-[#ff9900] animate-pulse" />;
      case 'offline':
      default:
        return <AlertCircle className="w-4 h-4 text-[#ff3366] animate-pulse" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
      case 'online':
        return 'text-[#00ff88] border-[#00ff88]/20 bg-[#00ff88]/5';
      case 'throttled':
      case 'degraded':
        return 'text-[#ff9900] border-[#ff9900]/20 bg-[#ff9900]/5';
      case 'offline':
      default:
        return 'text-[#ff3366] border-[#ff3366]/20 bg-[#ff3366]/5';
    }
  };

  return (
    <div className="flex-1 flex flex-col bg-[#050814] p-6 h-[calc(100vh-64px)] overflow-y-auto text-white font-mono scrollbar-thin">
      {/* Title */}
      <div className="flex items-center gap-2 mb-6 pb-4 border-b border-[#1e293b]/50 flex-shrink-0">
        <Server className="w-5 h-5 text-[#00f0ff]" />
        <h2 className="font-bold text-sm tracking-wider uppercase">Hyper-Scale Cluster Node Monitor</h2>
      </div>

      {/* Grid of Infrastructure */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8 flex-shrink-0">
        {/* ClickHouse */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getStatusColor(clusterStatus.clickhouse?.status || 'online')}`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold tracking-widest text-[#94a3b8]">CLICKHOUSE SECURE STORE</span>
            {getStatusIcon(clusterStatus.clickhouse?.status || 'online')}
          </div>
          <div className="my-3">
            <span className="text-xl font-bold font-mono text-white block">
              {(clusterStatus.clickhouse?.throughput || 1420.5).toLocaleString()} EPS
            </span>
            <span className="text-[9px] text-[#64748b]">Real-time persistence rate</span>
          </div>
          <div className="text-[9px] text-[#94a3b8] flex justify-between">
            <span>Batch depth: {clusterStatus.clickhouse?.batch_depth || 12}</span>
            <span>Storage: Partitioned</span>
          </div>
        </div>

        {/* Redis */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getStatusColor(clusterStatus.redis?.status || 'online')}`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold tracking-widest text-[#94a3b8]">REDIS THREAT CACHE</span>
            {getStatusIcon(clusterStatus.redis?.status || 'online')}
          </div>
          <div className="my-3">
            <span className="text-xl font-bold font-mono text-white block">
              {(clusterStatus.redis?.keys_cached || 1485).toLocaleString()} Keys
            </span>
            <span className="text-[9px] text-[#64748b]">Threat indicators cached</span>
          </div>
          <div className="text-[9px] text-[#94a3b8] flex justify-between">
            <span>Hit rate: {clusterStatus.redis?.hit_rate || '99.4%'}</span>
            <span>Policy: LFU Cache</span>
          </div>
        </div>

        {/* MinIO */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getStatusColor(clusterStatus.minio?.status || 'online')}`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold tracking-widest text-[#94a3b8]">MINIO OBJECT STORE</span>
            {getStatusIcon(clusterStatus.minio?.status || 'online')}
          </div>
          <div className="my-3">
            <span className="text-xl font-bold font-mono text-white block">
              {clusterStatus.minio?.total_buckets || 3} Buckets
            </span>
            <span className="text-[9px] text-[#64748b]">Evidence snapshots archived</span>
          </div>
          <div className="text-[9px] text-[#94a3b8] flex justify-between">
            <span>Forensics: Immutable</span>
            <span>Format: Parquet</span>
          </div>
        </div>

        {/* Kafka */}
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getStatusColor(clusterStatus.kafka?.status || 'online')}`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold tracking-widest text-[#94a3b8]">KAFKA INGEST FABRIC</span>
            {getStatusIcon(clusterStatus.kafka?.status || 'online')}
          </div>
          <div className="my-3">
            <span className="text-xl font-bold font-mono text-white block">
              Queue Lag: {clusterStatus.kafka?.lag || 0}
            </span>
            <span className="text-[9px] text-[#64748b]">Topic partition consumer lag</span>
          </div>
          <div className="text-[9px] text-[#94a3b8] flex justify-between">
            <span>Throughput: Stable</span>
            <span>Priority: Multiqueue</span>
          </div>
        </div>
      </div>

      {/* Workers Grid */}
      <h3 className="text-xs font-bold tracking-widest text-[#64748b] mb-4 uppercase">DISTRIBUTED GRPC WORKERS</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 flex-grow">
        {workers.map((worker: any) => (
          <div key={worker.id} className="p-4 bg-[#0d1326]/60 border border-[#1e293b]/60 rounded-xl space-y-3 hover:border-[#00f0ff]/30 transition-all">
            <div className="flex items-center justify-between pb-2 border-b border-[#1e293b]/30">
              <span className="text-xs font-bold text-white block">{worker.id}</span>
              <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${getStatusColor(worker.status)}`}>
                {worker.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-[#64748b] text-[10px]">WORKER TYPE</span>
                <span className="font-bold text-[#00f0ff] block mt-0.5">{worker.type}</span>
              </div>
              <div>
                <span className="text-[#64748b] text-[10px]">THROUGHPUT</span>
                <span className="font-bold text-white block mt-0.5">{worker.throughput.toFixed(1)} EPS</span>
              </div>
            </div>

            <div className="space-y-1.5 pt-2 border-t border-[#1e293b]/20">
              <div className="flex justify-between items-center text-[10px] text-[#cbd5e1]">
                <span className="flex items-center gap-1"><Cpu className="w-3.5 h-3.5 text-[#64748b]" /> CPU LOAD</span>
                <span className="font-mono">{worker.cpu}%</span>
              </div>
              <div className="w-full bg-[#131b31] h-1.5 rounded-full overflow-hidden">
                <div className="bg-[#00f0ff] h-full rounded-full" style={{ width: `${worker.cpu}%` }} />
              </div>

              <div className="flex justify-between items-center text-[10px] text-[#cbd5e1] mt-2">
                <span className="flex items-center gap-1"><Layers className="w-3.5 h-3.5 text-[#64748b]" /> RAM CONSUMPTION</span>
                <span className="font-mono">{worker.ram}%</span>
              </div>
              <div className="w-full bg-[#131b31] h-1.5 rounded-full overflow-hidden">
                <div className="bg-[#00ff88] h-full rounded-full" style={{ width: `${worker.ram}%` }} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
