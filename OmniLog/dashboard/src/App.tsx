import React, { useState, useEffect } from 'react';
import { FleetOverview, FleetSummary } from './components/FleetOverview';
import { LiveLogStream, UnifiedLogEvent } from './components/LiveLogStream';
import { LogInspectorDrawer } from './components/LogInspectorDrawer';
import { AgentEnrollModal } from './components/AgentEnrollModal';

export const App: React.FC = () => {
  const [fleet, setFleet] = useState<FleetSummary | null>(null);
  const [activeTab, setActiveTab] = useState<'fleet' | 'stream' | 'ai'>('fleet');
  const [selectedEvent, setSelectedEvent] = useState<UnifiedLogEvent | null>(null);
  const [isEnrollModalOpen, setIsEnrollModalOpen] = useState<boolean>(false);
  const [managerHealth, setManagerHealth] = useState<string>('ONLINE');

  const fetchFleet = async () => {
    try {
      const res = await fetch('/api/v1/fleet');
      if (res.ok) {
        const data = await res.json();
        setFleet(data);
        setManagerHealth('ONLINE');
      } else {
        setManagerHealth('DEGRADED');
      }
    } catch {
      setManagerHealth('OFFLINE');
    }
  };

  useEffect(() => {
    fetchFleet();
    const interval = setInterval(fetchFleet, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* 1. Global SOC Topbar */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center font-bold text-white shadow-lg shadow-cyan-950/60 ring-1 ring-cyan-400/30">
              FF
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold tracking-tight text-white text-sm sm:text-base">
                  FORCE-FIELDS
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  AI-SOC TELEMETRY
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono hidden sm:block">
                Stage 1 (Granular OS Collection) + Stage 2 (Unified JSON Normalization)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Health Ticker */}
            <div className="hidden md:flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800">
              <span className={`w-2 h-2 rounded-full ${managerHealth === 'ONLINE' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
              <span className="text-slate-400">MANAGER:</span>
              <span className={managerHealth === 'ONLINE' ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                {managerHealth}
              </span>
            </div>

            {/* Export JSONL for Stage 3 AI */}
            <a
              href="/api/v1/ai/export/jsonl"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 transition-colors"
            >
              ⬇ Export AI JSONL
            </a>

            {/* Enroll Agent Button */}
            <button
              onClick={() => setIsEnrollModalOpen(true)}
              className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium px-4 py-2 rounded-lg shadow-md shadow-cyan-950/60 transition-all flex items-center"
            >
              <span className="mr-1.5 font-bold">+</span> Enroll Agent
            </button>
          </div>
        </div>

        {/* 2. Navigation Tabs */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-6 border-t border-slate-900 text-xs font-mono">
          <button
            onClick={() => setActiveTab('fleet')}
            className={`py-3 font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'fleet'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>🖥️</span>
            <span>FLEET OVERVIEW</span>
            {fleet && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full bg-slate-800 text-slate-300 text-[10px]">
                {fleet.total_agents}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('stream')}
            className={`py-3 font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'stream'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>⚡</span>
            <span>LIVE SOC STREAM</span>
          </button>

          <button
            onClick={() => setActiveTab('ai')}
            className={`py-3 font-semibold border-b-2 transition-all flex items-center space-x-2 ${
              activeTab === 'ai'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>🤖</span>
            <span>STAGE 3 AI BRIDGE</span>
          </button>
        </div>
      </header>

      {/* 3. Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'fleet' && (
          <FleetOverview
            fleet={fleet}
            onOpenEnrollModal={() => setIsEnrollModalOpen(true)}
          />
        )}

        {activeTab === 'stream' && (
          <LiveLogStream
            onSelectEvent={ev => setSelectedEvent(ev)}
            selectedEventId={selectedEvent?.event_id}
          />
        )}

        {activeTab === 'ai' && (
          <div className="space-y-6">
            <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-2xl shadow-xl">
              <div className="flex items-center space-x-3 mb-4">
                <span className="text-3xl">🤖</span>
                <div>
                  <h2 className="text-lg font-bold text-slate-100">Force-Fields Stage 3 AI Integration Bridge</h2>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Real-time WebSocket and batched REST endpoints for downstream AI Threat Classification.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-6 font-mono text-xs">
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="text-slate-400">UNPROCESSED AI QUEUE</div>
                  <div className="text-2xl font-bold text-cyan-400 mt-1">/api/v1/ai/unprocessed</div>
                  <div className="text-[11px] text-slate-500 mt-1">Batch pull with ACK tracking</div>
                </div>
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="text-slate-400">WEBSOCKET REAL-TIME STREAM</div>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">/api/v1/ai/stream</div>
                  <div className="text-[11px] text-slate-500 mt-1">Push stream to live inference models</div>
                </div>
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="text-slate-400">OFFLINE TRAINING EXPORT</div>
                  <div className="text-2xl font-bold text-purple-400 mt-1">/api/v1/ai/export/jsonl</div>
                  <div className="text-[11px] text-slate-500 mt-1">Streaming JSON Lines file</div>
                </div>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <h3 className="font-semibold text-slate-200 uppercase tracking-wider">
                  Python Integration Example for AI Classifier:
                </h3>
                <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-cyan-300 overflow-x-auto leading-relaxed">
{`import asyncio
import websockets
import json

async def stream_normalized_telemetry():
    uri = "ws://localhost:8000/api/v1/ai/stream"
    async with websockets.connect(uri) as ws:
        print("[+] Connected to Force-Fields AI Stream.")
        while True:
            raw_event = await ws.recv()
            event = json.loads(raw_event)
            
            # Feed standardized schema directly to Stage 3 AI Model:
            actor = event["actor"]
            proc = event["process"]
            net = event["network"]
            category = event["event"]["category"]
            
            print(f"[AI Ingest] {event['event_timestamp']} | {event['agent']['hostname']} | {category} | {proc.get('command_line')}")

asyncio.run(stream_normalized_telemetry())`}
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* 4. Log Inspector Drawer */}
      <LogInspectorDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* 5. Agent Enrollment Modal */}
      <AgentEnrollModal
        isOpen={isEnrollModalOpen}
        onClose={() => setIsEnrollModalOpen(false)}
      />
    </div>
  );
};

export default App;
