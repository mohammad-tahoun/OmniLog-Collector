import React, { useState } from 'react';

interface AgentEnrollModalProps {
  isOpen: boolean;
  onClose: () => void;
  defaultManagerUrl?: string;
  enrollToken?: string;
}

export const AgentEnrollModal: React.FC<AgentEnrollModalProps> = ({
  isOpen,
  onClose,
  defaultManagerUrl = 'http://localhost:8000',
  enrollToken = 'FORCEFIELDS-DEFAULT-ENROLL-KEY'
}) => {
  const [selectedOS, setSelectedOS] = useState<'windows' | 'linux'>('windows');
  const [managerUrl, setManagerUrl] = useState<string>(
    window.location.origin.includes('localhost') ? defaultManagerUrl : window.location.origin
  );
  const [token, setToken] = useState<string>(enrollToken);
  const [copiedStep, setCopiedStep] = useState<string | null>(null);

  if (!isOpen) return null;

  const copyToClipboard = (text: string, stepId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedStep(stepId);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  const winSetupCmd = `powershell -ExecutionPolicy Bypass -File .\\setup-windows-telemetry.ps1`;
  const winEnrollCmd = `.\\forcefields-agent-windows-amd64.exe --enroll --manager ${managerUrl} --token ${token}`;
  const winServiceCmd = `.\\forcefields-agent-windows-amd64.exe --install-service`;

  const linuxSetupCmd = `sudo bash ./setup-linux-telemetry.sh`;
  const linuxEnrollCmd = `sudo ./forcefields-agent-linux-amd64 --enroll --manager ${managerUrl} --token ${token}`;
  const linuxServiceCmd = `sudo ./forcefields-agent-linux-amd64 --install-service`;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-sans">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center">
              <span className="text-cyan-400 mr-2 text-lg">⚡</span> Enroll Dedicated Endpoint Agent
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Generate native single-binary deployment commands for Windows or Linux.
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 overflow-y-auto max-h-[80vh]">
          {/* OS Switcher */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-2 uppercase">Select Target OS Platform</label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setSelectedOS('windows')}
                className={`py-3 px-4 rounded-xl border text-sm font-semibold flex items-center justify-center space-x-2 transition-all ${
                  selectedOS === 'windows'
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 shadow-md ring-1 ring-cyan-500'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-800/60'
                }`}
              >
                <span>🪟</span>
                <span>Windows 10/11 / Windows Server</span>
              </button>
              <button
                type="button"
                onClick={() => setSelectedOS('linux')}
                className={`py-3 px-4 rounded-xl border text-sm font-semibold flex items-center justify-center space-x-2 transition-all ${
                  selectedOS === 'linux'
                    ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 shadow-md ring-1 ring-cyan-500'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-800/60'
                }`}
              >
                <span>🐧</span>
                <span>Ubuntu Server / Linux Endpoint</span>
              </button>
            </div>
          </div>

          {/* Config Parameters */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">MANAGER URL</label>
              <input
                type="text"
                value={managerUrl}
                onChange={e => setManagerUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">ENROLLMENT TOKEN</label>
              <input
                type="text"
                value={token}
                onChange={e => setToken(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Step-by-Step Commands */}
          <div className="space-y-4">
            <h4 className="text-xs font-bold text-slate-300 font-mono uppercase tracking-wide">
              Deployment Steps for {selectedOS === 'windows' ? 'Windows' : 'Linux'}:
            </h4>

            {/* Step 1: Telemetry Setup */}
            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-cyan-400 font-semibold">1. Configure OS Auditing & Telemetry</span>
                <button
                  onClick={() => copyToClipboard(selectedOS === 'windows' ? winSetupCmd : linuxSetupCmd, 'step1')}
                  className="text-cyan-400 hover:underline"
                >
                  {copiedStep === 'step1' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-[11px] text-slate-400">
                {selectedOS === 'windows'
                  ? 'Applies Advanced Audit Policy, enables CommandLine auditing, and deploys Sysmon.'
                  : 'Installs auditd and loads comprehensive process/file/network rules.'}
              </p>
              <pre className="p-2.5 bg-slate-900 rounded border border-slate-800/80 text-slate-200 text-xs font-mono overflow-x-auto">
                {selectedOS === 'windows' ? winSetupCmd : linuxSetupCmd}
              </pre>
            </div>

            {/* Step 2: Enroll Agent */}
            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-cyan-400 font-semibold">2. Enroll Endpoint Hardware Fingerprint</span>
                <button
                  onClick={() => copyToClipboard(selectedOS === 'windows' ? winEnrollCmd : linuxEnrollCmd, 'step2')}
                  className="text-cyan-400 hover:underline"
                >
                  {copiedStep === 'step2' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-[11px] text-slate-400">
                Auto-classifies OS category, receives unique Agent ID & API Key, and saves configuration.
              </p>
              <pre className="p-2.5 bg-slate-900 rounded border border-slate-800/80 text-cyan-300 text-xs font-mono overflow-x-auto">
                {selectedOS === 'windows' ? winEnrollCmd : linuxEnrollCmd}
              </pre>
            </div>

            {/* Step 3: Install Service */}
            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-cyan-400 font-semibold">3. Run as Native Background Daemon</span>
                <button
                  onClick={() => copyToClipboard(selectedOS === 'windows' ? winServiceCmd : linuxServiceCmd, 'step3')}
                  className="text-cyan-400 hover:underline"
                >
                  {copiedStep === 'step3' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-[11px] text-slate-400">
                {selectedOS === 'windows'
                  ? 'Installs as a native auto-start Windows Service with persistent local disk buffering.'
                  : 'Registers and activates systemd background daemon with store-and-forward queue.'}
              </p>
              <pre className="p-2.5 bg-slate-900 rounded border border-slate-800/80 text-slate-200 text-xs font-mono overflow-x-auto">
                {selectedOS === 'windows' ? winServiceCmd : linuxServiceCmd}
              </pre>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
