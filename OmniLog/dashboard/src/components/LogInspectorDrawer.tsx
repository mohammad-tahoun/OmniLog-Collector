import React, { useState } from 'react';
import { UnifiedLogEvent } from './LiveLogStream';

interface LogInspectorDrawerProps {
  event: UnifiedLogEvent | null;
  onClose: () => void;
}

export const LogInspectorDrawer: React.FC<LogInspectorDrawerProps> = ({ event, onClose }) => {
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw' | 'forensics'>('normalized');
  const [copied, setCopied] = useState<boolean>(false);

  if (!event) return null;

  const handleCopyJSON = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full md:w-[700px] lg:w-[800px] bg-slate-950 border-l border-slate-800 shadow-2xl z-50 flex flex-col font-mono">
      {/* 1. Drawer Header */}
      <div className="p-4 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase font-bold">
              {event.event?.category} : {event.event?.action}
            </span>
            <span className="text-xs text-slate-400">ID: {event.event_id.slice(0, 8)}...</span>
          </div>
          <h3 className="text-sm font-semibold text-slate-100 mt-1 font-sans">
            {event.agent?.hostname} — {event.event?.source_channel}
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => handleCopyJSON(activeTab === 'raw' ? event.full_raw_payload : event)}
            className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center transition-colors"
          >
            {copied ? '✓ Copied!' : '📋 Copy JSON'}
          </button>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-base"
          >
            ✕
          </button>
        </div>
      </div>

      {/* 2. Mode Tabs */}
      <div className="flex border-b border-slate-800 bg-slate-900/50 text-xs font-sans">
        <button
          onClick={() => setActiveTab('normalized')}
          className={`flex-1 py-2.5 text-center font-medium transition-colors border-b-2 ${
            activeTab === 'normalized'
              ? 'border-cyan-400 text-cyan-400 bg-slate-900'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Normalized AI Schema (Stage 2)
        </button>
        <button
          onClick={() => setActiveTab('raw')}
          className={`flex-1 py-2.5 text-center font-medium transition-colors border-b-2 ${
            activeTab === 'raw'
              ? 'border-cyan-400 text-cyan-400 bg-slate-900'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          100% Original Raw Log (Stage 1)
        </button>
        <button
          onClick={() => setActiveTab('forensics')}
          className={`flex-1 py-2.5 text-center font-medium transition-colors border-b-2 ${
            activeTab === 'forensics'
              ? 'border-cyan-400 text-cyan-400 bg-slate-900'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Visual Forensics Summary
        </button>
      </div>

      {/* 3. Drawer Body */}
      <div className="flex-1 overflow-y-auto p-4 text-xs">
        {activeTab === 'normalized' && (
          <div className="space-y-3">
            <div className="p-3 bg-cyan-950/30 border border-cyan-800/40 rounded-lg text-cyan-300 text-[11px] font-sans">
              ℹ This is the normalized JSON schema delivered directly to Force-Fields Stage 3 AI Classifier & Hybrid Threat models.
            </div>
            <pre className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto leading-relaxed">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        )}

        {activeTab === 'raw' && (
          <div className="space-y-3">
            <div className="p-3 bg-amber-950/30 border border-amber-800/40 rounded-lg text-amber-300 text-[11px] font-sans">
              ℹ 100% unmodified raw telemetry captured directly from the OS endpoint for complete forensic fidelity.
            </div>
            <div className="text-[11px] text-slate-400 font-mono mb-2">
              Raw Log Reference ID: <span className="text-slate-200">{event.raw_log_ref}</span>
            </div>
            <pre className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 text-emerald-300 font-mono text-[11px] overflow-x-auto leading-relaxed">
              {JSON.stringify(event.full_raw_payload, null, 2)}
            </pre>
          </div>
        )}

        {activeTab === 'forensics' && (
          <div className="space-y-4 font-sans text-xs">
            {/* Actor Card */}
            <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
              <h4 className="text-cyan-400 font-semibold mb-2 flex items-center">
                👤 Actor Identity & Privileges
              </h4>
              <div className="grid grid-cols-2 gap-2 text-slate-300 font-mono">
                <div>User: <span className="text-white font-semibold">{event.actor?.user || 'SYSTEM'}</span></div>
                <div>User SID / UID: <span className="text-white">{event.actor?.user_id || '-'}</span></div>
                <div>Elevated Privileges: <span className={event.actor?.elevated ? 'text-amber-400 font-bold' : 'text-slate-400'}>{event.actor?.elevated ? 'YES (Elevated)' : 'NO'}</span></div>
                <div>Hostname: <span className="text-white">{event.agent?.hostname}</span></div>
              </div>
            </div>

            {/* Process Lineage Card */}
            <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
              <h4 className="text-cyan-400 font-semibold mb-2 flex items-center">
                ⚙️ Process Execution Lineage
              </h4>
              <div className="space-y-2 text-slate-300 font-mono">
                <div>PID: <span className="text-white font-bold">{event.process?.pid || '-'}</span> | PPID: <span className="text-white font-bold">{event.process?.ppid || '-'}</span></div>
                <div>Executable: <span className="text-white break-all">{event.process?.executable || '-'}</span></div>
                <div>
                  Command Line:
                  <div className="p-2 mt-1 bg-slate-950 rounded border border-slate-800 text-cyan-300 text-[11px] break-all">
                    {event.process?.command_line || 'None'}
                  </div>
                </div>
                {event.process?.parent_name && (
                  <div>
                    Parent Process: <span className="text-white">{event.process.parent_name}</span>
                    {event.process.parent_command_line && (
                      <div className="p-2 mt-1 bg-slate-950 rounded border border-slate-800 text-slate-400 text-[11px] break-all">
                        {event.process.parent_command_line}
                      </div>
                    )}
                  </div>
                )}
                {event.process?.hash_sha256 && (
                  <div>SHA-256 Hash: <span className="text-amber-300 text-[10px] break-all">{event.process.hash_sha256}</span></div>
                )}
              </div>
            </div>

            {/* Network 5-Tuple Card */}
            {(event.network?.src_ip || event.network?.dst_ip || event.network?.dns_query) && (
              <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                <h4 className="text-cyan-400 font-semibold mb-2 flex items-center">
                  🌐 Network 5-Tuple & DNS
                </h4>
                <div className="grid grid-cols-2 gap-2 text-slate-300 font-mono">
                  <div>Protocol: <span className="text-white uppercase">{event.network?.protocol || 'TCP'}</span></div>
                  <div>DNS Query: <span className="text-cyan-300">{event.network?.dns_query || '-'}</span></div>
                  <div>Source: <span className="text-white">{event.network?.src_ip || '*'}:{event.network?.src_port || '*'}</span></div>
                  <div>Destination: <span className="text-white">{event.network?.dst_ip || '*'}:{event.network?.dst_port || '*'}</span></div>
                </div>
              </div>
            )}

            {/* File / Registry Card */}
            {event.file_or_registry?.target_path && (
              <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                <h4 className="text-cyan-400 font-semibold mb-2 flex items-center">
                  📁 File / Registry Activity
                </h4>
                <div className="space-y-1 text-slate-300 font-mono">
                  <div>Operation: <span className="text-white uppercase font-bold">{event.file_or_registry.operation || 'MODIFY'}</span></div>
                  <div>Path / Target: <span className="text-cyan-300 break-all">{event.file_or_registry.target_path}</span></div>
                  {event.file_or_registry.details && (
                    <div>Details: <span className="text-slate-400">{event.file_or_registry.details}</span></div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
