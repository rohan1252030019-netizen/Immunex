import React from 'react';
import { useSOCStore } from '../lib/store';
import { 
  Shield, 
  Terminal, 
  Network, 
  Target, 
  Bot, 
  Server, 
  Clock, 
  LogOut,
  ChevronLeft,
  ChevronRight,
  User,
  Radio,
  FileText,
  Award
} from 'lucide-react';
import { motion } from 'framer-motion';

export default function Sidebar() {
  const { activeTab, setActiveTab, username, isWsConnected, logout } = useSOCStore();
  const [collapsed, setCollapsed] = React.useState(false);

  const menuItems = [
    { id: 'dashboard', label: 'Command Center', icon: Shield },
    { id: 'alerts', label: 'Alert Stream', icon: Terminal },
    { id: 'underwriting', label: 'Underwriting Desk', icon: FileText },
    { id: 'compliance', label: 'RBI Compliance', icon: Award },
    { id: 'graph', label: 'Attack Graph', icon: Network },
    { id: 'mitre', label: 'MITRE Matrix', icon: Target },
    { id: 'copilot', label: 'AI Copilot Chat', icon: Bot },
    { id: 'timeline', label: 'Threat Timeline', icon: Clock },
    { id: 'cluster', label: 'Cluster Monitor', icon: Server },
  ];

  return (
    <motion.div 
      animate={{ width: collapsed ? 72 : 260 }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="flex flex-col h-screen bg-[#0d1326] border-r border-[#1e293b]/50 text-[#e2e8f0] relative"
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-[#1e293b]/50">
        {!collapsed && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center gap-2"
          >
            <div className="p-1.5 bg-gradient-to-tr from-[#00f0ff] to-[#ff3366] rounded-lg shadow-[0_0_10px_rgba(0,240,255,0.4)]">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg tracking-wider bg-gradient-to-r from-white to-[#a1a1aa] bg-clip-text text-transparent">
              IMMUNEX
            </span>
            <span className="text-[10px] text-[#00f0ff] border border-[#00f0ff]/30 px-1 rounded uppercase tracking-widest font-mono">
              SOC
            </span>
          </motion.div>
        )}
        {collapsed && (
          <div className="p-1.5 bg-gradient-to-tr from-[#00f0ff] to-[#ff3366] rounded-lg shadow-[0_0_10px_rgba(0,240,255,0.4)] mx-auto">
            <Shield className="w-5 h-5 text-white" />
          </div>
        )}
        <button 
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-5 p-1 bg-[#1e293b] border border-[#334155] rounded-full hover:bg-[#334155] transition-all text-[#94a3b8] hover:text-white"
        >
          {collapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Connection Indicator */}
      <div className="px-4 py-2 bg-[#131b31]/40 border-b border-[#1e293b]/30 flex items-center justify-center gap-2">
        <Radio className={`w-3.5 h-3.5 animate-pulse ${isWsConnected ? 'text-[#00ff88]' : 'text-[#ff3366]'}`} />
        {!collapsed && (
          <span className="text-[11px] font-mono uppercase tracking-widest text-[#94a3b8]">
            {isWsConnected ? 'FABRIC STREAMING' : 'STREAM DISCONNECTED'}
          </span>
        )}
      </div>

      {/* Menu List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-3 rounded-lg font-medium text-sm transition-all relative ${
                isActive 
                  ? 'bg-gradient-to-r from-[#00f0ff]/20 to-[#00f0ff]/5 text-white border-l-2 border-[#00f0ff]' 
                  : 'text-[#94a3b8] hover:text-white hover:bg-[#1a233d]/50'
              }`}
            >
              <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-[#00f0ff]' : ''}`} />
              {!collapsed && (
                <motion.span 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="font-mono tracking-wide"
                >
                  {item.label}
                </motion.span>
              )}
              {isActive && (
                <div className="absolute right-3 w-1.5 h-1.5 bg-[#00f0ff] rounded-full shadow-[0_0_8px_rgba(0,240,255,0.8)]" />
              )}
            </button>
          );
        })}
      </nav>

      {/* User Info / Profile & Logout */}
      <div className="p-3 border-t border-[#1e293b]/50 space-y-2">
        <div className="flex items-center gap-3 p-2 bg-[#1a233d]/40 rounded-lg border border-[#1e293b]/20">
          <div className="w-8 h-8 rounded-full bg-[#00f0ff]/10 border border-[#00f0ff]/30 flex items-center justify-center text-[#00f0ff]">
            <User className="w-4 h-4" />
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-white truncate font-mono">{username || 'analyst'}</p>
              <p className="text-[10px] text-[#94a3b8] tracking-widest font-mono uppercase">Role: ADMIN</p>
            </div>
          )}
        </div>
        
        <button 
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-[#ef4444]/15 hover:bg-[#ef4444]/25 text-[#ef4444] transition-all font-mono text-xs border border-[#ef4444]/20"
        >
          <LogOut className="w-4 h-4 flex-shrink-0" />
          {!collapsed && <span>ABORT DECK</span>}
        </button>
      </div>
    </motion.div>
  );
}
