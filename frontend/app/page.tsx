'use client';

import React from 'react';
import { useSOCStore } from '../lib/store';
import { authApi } from '../lib/api';
import { connectWebSocket, disconnectWebSocket } from '../lib/websocket';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import MetricsPanel from '../components/MetricsPanel';
import AlertStream from '../components/AlertStream';
import AttackGraph from '../components/AttackGraph';
import MitreHeatmap from '../components/MitreHeatmap';
import CopilotChat from '../components/CopilotChat';
import ThreatTimeline from '../components/ThreatTimeline';
import ClusterMonitor from '../components/ClusterMonitor';
import ExecutiveDash from '../components/ExecutiveDash';
import UnderwritingConsole from '../components/UnderwritingConsole';
import ComplianceScorecard from '../components/ComplianceScorecard';

import { Shield, Lock, User, Terminal, AlertTriangle, Key } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function Home() {
  const { 
    isAuthenticated, 
    setAuthenticated, 
    activeTab, 
    fetchInitialData, 
    alerts 
  } = useSOCStore();

  const [usernameInput, setUsernameInput] = React.useState('admin');
  const [passwordInput, setPasswordInput] = React.useState('administrator_secret_soc');
  const [loginError, setLoginError] = React.useState('');
  const [loading, setLoading] = React.useState(false);

  // Check if token exists in localStorage on mount
  React.useEffect(() => {
    const token = authApi.getToken();
    const user = authApi.getUser();
    if (token && user) {
      setAuthenticated(true, user);
      fetchInitialData();
      connectWebSocket(token);
    }
  }, [setAuthenticated, fetchInitialData]);

  // Clean up WebSocket on unmount
  React.useEffect(() => {
    return () => {
      disconnectWebSocket();
    };
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError('');
    setLoading(true);

    try {
      const data = await authApi.login(usernameInput, passwordInput);
      if (data && data.access_token) {
        setAuthenticated(true, usernameInput);
        await fetchInitialData();
        connectWebSocket(data.access_token);
      } else {
        setLoginError('Authentication failed. No token generated.');
      }
    } catch (err: any) {
      console.error(err);
      setLoginError(err.response?.data?.detail || 'Invalid authorization credentials.');
    } finally {
      setLoading(false);
    }
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <div className="flex-1 flex flex-col overflow-y-auto scrollbar-thin">
            <MetricsPanel />
            <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 p-6 min-h-0 bg-[#050814]">
              {/* Executive Posture Gauge */}
              <div className="lg:col-span-4 flex flex-col h-[500px]">
                <ExecutiveDash />
              </div>
              {/* Live Mini Attack Graph */}
              <div className="lg:col-span-8 flex flex-col h-[500px]">
                <AttackGraph />
              </div>
            </div>
          </div>
        );
      case 'alerts':
        return <AlertStream />;
      case 'underwriting':
        return <UnderwritingConsole />;
      case 'compliance':
        return <ComplianceScorecard />;
      case 'graph':
        return <AttackGraph />;
      case 'mitre':
        return <MitreHeatmap />;
      case 'copilot':
        return <CopilotChat />;
      case 'timeline':
        return <ThreatTimeline />;
      case 'cluster':
        return <ClusterMonitor />;
      default:
        return <AlertStream />;
    }
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#050814] font-mono text-[#cbd5e1] relative overflow-hidden">
        {/* Animated matrix grid effect */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#131a35_1px,transparent_1px),linear-gradient(to_bottom,#131a35_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]opacity-40" />

        <motion.div 
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-md bg-[#0a0f24]/90 border border-[#1e2d5a]/60 rounded-3xl p-8 z-10 shadow-[0_0_50px_rgba(0,240,255,0.15)] backdrop-blur-md relative"
        >
          {/* Neon Glow top-line */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-[#00f0ff] via-[#ff3366] to-[#00ff88] rounded-t-3xl" />

          {/* Logo Title */}
          <div className="flex flex-col items-center mb-8">
            <div className="p-3 bg-gradient-to-tr from-[#00f0ff] to-[#ff3366] rounded-2xl shadow-[0_0_20px_rgba(0,240,255,0.5)] mb-4">
              <Shield className="w-8 h-8 text-white animate-pulse" />
            </div>
            <h2 className="text-xl font-extrabold tracking-widest text-white uppercase bg-gradient-to-r from-white via-[#e2e8f0] to-[#94a3b8] bg-clip-text text-transparent">
              IMMUNEX ENTERPRISE
            </h2>
            <span className="text-[10px] tracking-[0.25em] text-[#00f0ff] font-bold mt-1.5 uppercase">
              Autonomous AI Cyber-Defense SOC
            </span>
          </div>

          {/* Alert messages */}
          <AnimatePresence mode="wait">
            {loginError && (
              <motion.div 
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="mb-6 p-3 rounded-xl border border-[#ff3366]/30 bg-[#ff3366]/5 text-[#ff3366] text-xs flex items-center gap-2"
              >
                <AlertTriangle className="w-4 h-4 flex-shrink-0 animate-bounce" />
                <span>{loginError}</span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="text-[10px] tracking-wider text-[#64748b] block mb-1.5 uppercase font-bold">Analyst Profile Identity</label>
              <div className="flex bg-[#070b1b] border border-[#1e2d5a] rounded-xl px-4 py-2.5 items-center gap-3 focus-within:border-[#00f0ff]/50 transition-all">
                <User className="w-4 h-4 text-[#64748b]" />
                <input 
                  type="text"
                  placeholder="admin"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  className="bg-transparent border-none outline-none text-sm text-white flex-grow focus:ring-0 placeholder-[#64748b]"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] tracking-wider text-[#64748b] block mb-1.5 uppercase font-bold">Secure Access Cipher</label>
              <div className="flex bg-[#070b1b] border border-[#1e2d5a] rounded-xl px-4 py-2.5 items-center gap-3 focus-within:border-[#00f0ff]/50 transition-all">
                <Lock className="w-4 h-4 text-[#64748b]" />
                <input 
                  type="password"
                  placeholder="••••••••••••••"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  className="bg-transparent border-none outline-none text-sm text-white flex-grow focus:ring-0 placeholder-[#64748b]"
                  required
                />
              </div>
            </div>

            <div className="p-3 bg-[#131a35]/40 border border-[#1e2d5a]/40 rounded-xl space-y-1.5">
              <span className="text-[9px] text-[#64748b] uppercase tracking-wider block font-bold flex items-center gap-1">
                <Key className="w-3 h-3 text-[#ff9900]" /> DEMO SECURE ACCESS PRESET
              </span>
              <div className="text-[10px] text-[#cbd5e1] font-bold">
                Identity: <span className="text-[#00f0ff]">admin</span>
              </div>
              <div className="text-[10px] text-[#cbd5e1] font-bold">
                Cipher: <span className="text-[#00ff88]">administrator_secret_soc</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 bg-gradient-to-r from-[#00f0ff] to-[#00ff88] hover:from-[#00d8e6] hover:to-[#00e67a] disabled:from-[#131a35] disabled:to-[#131a35] text-[#050814] font-bold rounded-xl tracking-wider text-xs transition-all shadow-[0_0_15px_rgba(0,240,255,0.4)] disabled:shadow-none hover:scale-[1.01]"
            >
              {loading ? 'CALIBRATING SECURITY FABRIC...' : 'AUTHORIZE DECK ACCESS'}
            </button>
          </form>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-[#050814] text-white overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar />

      {/* Main Container Deck */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Dashboard Header Banner */}
        <Header />

        {/* Dynamic Inner Panel Viewport */}
        {renderActiveView()}
      </div>
    </div>
  );
}
