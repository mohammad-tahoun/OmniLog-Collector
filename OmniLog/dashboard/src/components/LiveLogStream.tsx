import React, { useState, useEffect, useRef } from 'react';

export interface UnifiedLogEvent {
  event_id: string;
  raw_log_ref: string;
  ingest_timestamp: string;
  event_timestamp: string;
  agent: {
    agent_id: string;
    hostname: string;
    os_category: string;
    os_version: string;
    ip_address: string;
  };
  event: {
    source_channel: string;
    source_event_id?: string;
    category: string;
    action: string;
    outcome: string;
    severity_hint: string;
  };
  actor: {
    user?: string;
    user_id?: string;
    elevated?: boolean;
  };
  process: {
    pid?: number;
    ppid?: number;
    name?: string;
    executable?: string;
    command_line?: string;
    parent_name?: string;
    parent_command_line?: string;
    hash_sha256?: string;
  };
  network: {
    protocol?: string;
    src_ip?: string;
    src_port?: number;
    dst_ip?: string;
    dst_port?: number;
    dns_query?: string;
  };
  file_or_registry: {
    target_path?: string;
    operation?: string;
    details?: string;
  };
  full_raw_payload: Record<string, any>;
}

interface LiveLogStreamProps {
  onSelectEvent: (event: UnifiedLogEvent) => void;
  selectedEventId?: string;
}

const SEVERITY_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  low: { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-800' },
  medium: { bg: 'bg-amber-950/80', text: 'text-amber-400', border: 'border-amber-800/60' },
  high: { bg: 'bg-orange-950/80', text: 'text-orange-400', border: 'border-orange-800/60' },
  critical: { bg: 'bg-rose-950/90', text: 'text-rose-400', border: 'border-rose-800/80' }
};

const CATEGORY_COLORS: Record<string, string> = {
  process: 'text-cyan-400 bg-cyan-950/50 border-cyan-800/40',
  network: 'text-emerald-400 bg-emerald-950/50 border-emerald-800/40',
  auth: 'text-purple-400 bg-purple-950/50 border-purple-800/40',
  file_or_registry: 'text-amber-400 bg-amber-950/50 border-amber-800/40',
  system: 'text-slate-300 bg-slate-800/50 border-slate-700/40'
};

export const LiveLogStream: React.FC<LiveLogStreamProps> = ({ onSelectEvent, selectedEventId }) => {
  const [events, setEvents] = useState<UnifiedLogEvent[]>([]);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [osFilter, setOsFilter] = useState<string>('all');
  const [wsConnected, setWsConnected] = useState<boolean>(false);

  const socketRef = useRef<WebSocket | null>(null);

  // Fetch initial logs
  useEffect(() => {
    fetchLogs();
    const interval = setInterval(() => {
      if (!isPaused && !wsConnected) {
        fetchLogs();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [isPaused, wsConnected, categoryFilter, severityFilter, osFilter]);

  // WebSocket Live Stream Connection
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/v1/ai/stream`;

    const connectWS = () => {
      try {
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          if (isPaused) return;
          try {
            const newEvent: UnifiedLogEvent = JSON.parse(event.data);
            setEvents(prev => [newEvent, ...prev.slice(0, 199)]);
          } catch (e) {
            console.error('Failed parsing stream event', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Retry connection after 3s
          setTimeout(connectWS, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        setWsConnected(false);
      }
    };

    connectWS();

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [isPaused]);

  const fetchLogs = async () => {
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (categoryFilter !== 'all') params.append('category', categoryFilter);
      if (severityFilter !== 'all') params.append('severity', severityFilter);
      if (osFilter !== 'all') params.append('os_category', osFilter);
      if (searchTerm) params.append('query', searchTerm);

      const res = await fetch(`/api/v1/logs?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
      }
    } catch (e) {
      console.error('Failed to fetch logs', e);
    }
  };

  const filteredEvents = events.filter(ev => {
    if (searchTerm === '') return true;
    const term = searchTerm.toLowerCase();
    const actorUser = ev.actor?.user?.toLowerCase() || '';
    const procCmd = ev.process?.command_line?.toLowerCase() || '';
    const procName = ev.process?.name?.toLowerCase() || '';
    const srcIp = ev.network?.src_ip || '';
    const dstIp = ev.network?.dst_ip || '';
    const host = ev.agent?.hostname?.toLowerCase() || '';

    return actorUser.includes(term) ||
      procCmd.includes(term) ||
      procName.includes(term) ||
      srcIp.includes(term) ||
      dstIp.includes(term) ||
      host.includes(term);
  });

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-xl flex flex-col h-[750px]">
      {/* 1. Header Toolbar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
        <div className="flex items-center space-x-3">
          <h2 className="text-sm font-semibold text-slate-100 flex items-center font-mono">
            <span className={`w-2.5 h-2.5 rounded-full mr-2 ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
            SOC INGESTION STREAM
            <span className="ml-2 px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300">
              {filteredEvents.length} events
            </span>
          </h2>

          <div className="flex items-center space-x-1.5 text-xs font-mono">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className={`px-3 py-1 rounded-lg border text-xs font-medium transition-colors ${
                isPaused
                  ? 'bg-amber-950 text-amber-400 border-amber-800 hover:bg-amber-900'
                  : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
              }`}
            >
              {isPaused ? '▶ Resume Stream' : '⏸ Pause Stream'}
            </button>
            <button
              onClick={() => setEvents([])}
              className="px-2.5 py-1 rounded-lg border border-slate-800 text-slate-400 hover:text-slate-200 text-xs"
            >
              Clear
            </button>
          </div>
        </div>

        {/* 2. Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            placeholder="Search command, user, IP..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-48"
          />

          <select
            value={categoryFilter}
            onChange={e => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Categories</option>
            <option value="process">Process</option>
            <option value="network">Network</option>
            <option value="auth">Auth & Logon</option>
            <option value="file_or_registry">File / Registry</option>
            <option value="system">System</option>
          </select>

          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>

          <select
            value={osFilter}
            onChange={e => setOsFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All OS</option>
            <option value="windows_workstation">Windows Workstation</option>
            <option value="windows_server">Windows Server</option>
            <option value="ubuntu_server">Ubuntu Server</option>
            <option value="linux_endpoint">Linux Endpoint</option>
          </select>
        </div>
      </div>

      {/* 3. Log Table */}
      <div className="overflow-y-auto flex-1">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-950/90 text-slate-400 sticky top-0 border-b border-slate-800 z-10">
            <tr>
              <th className="py-2.5 px-3">TIMESTAMP</th>
              <th className="py-2.5 px-3">HOST & OS</th>
              <th className="py-2.5 px-3">CATEGORY / ACTION</th>
              <th className="py-2.5 px-3">ACTOR</th>
              <th className="py-2.5 px-3">TELEMETRY DETAILS (CMD / IP / PATH)</th>
              <th className="py-2.5 px-3">SEVERITY</th>
              <th className="py-2.5 px-3 text-right">ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-16 text-center text-slate-500 font-sans">
                  No telemetry events match current filters.
                </td>
              </tr>
            ) : (
              filteredEvents.map(ev => {
                const isSelected = selectedEventId === ev.event_id;
                const sev = ev.event?.severity_hint?.toLowerCase() || 'low';
                const sevStyle = SEVERITY_BADGES[sev] || SEVERITY_BADGES.low;
                const catClass = CATEGORY_COLORS[ev.event?.category] || CATEGORY_COLORS.system;

                let detailsText = '';
                if (ev.process?.command_line) {
                  detailsText = ev.process.command_line;
                } else if (ev.network?.src_ip || ev.network?.dst_ip) {
                  detailsText = `${ev.network.protocol?.toUpperCase() || 'IP'} ${ev.network.src_ip || '*'}:${ev.network.src_port || '*'} -> ${ev.network.dst_ip || '*'}:${ev.network.dst_port || '*'}`;
                } else if (ev.file_or_registry?.target_path) {
                  detailsText = `${ev.file_or_registry.operation || ''} ${ev.file_or_registry.target_path}`;
                } else {
                  detailsText = ev.event?.action || 'system telemetry';
                }

                return (
                  <tr
                    key={ev.event_id}
                    onClick={() => onSelectEvent(ev)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/40 border-l-2 border-cyan-400 text-slate-100'
                        : 'hover:bg-slate-800/40 text-slate-300'
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                      {ev.event_timestamp ? new Date(ev.event_timestamp).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="font-semibold text-slate-200">{ev.agent?.hostname || 'UNKNOWN'}</span>
                      <span className="ml-1.5 text-[10px] text-slate-500">
                        {ev.agent?.os_category === 'windows_server' ? 'WinSrv' : ev.agent?.os_category === 'ubuntu_server' ? 'Ubuntu' : ev.agent?.os_category}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${catClass}`}>
                        {ev.event?.category} : {ev.event?.action}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="text-slate-200 font-medium">
                        {ev.actor?.user || '-'}
                      </span>
                      {ev.actor?.elevated && (
                        <span className="ml-1 text-[9px] px-1 py-0.2 rounded bg-amber-950 text-amber-400 border border-amber-800">
                          ELEVATED
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 max-w-md truncate text-slate-300 text-[11px]" title={detailsText}>
                      {detailsText}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${sevStyle.bg} ${sevStyle.text} ${sevStyle.border}`}>
                        {sev}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev);
                        }}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-cyan-900/60 text-cyan-400 hover:text-cyan-200 text-[11px] border border-slate-700"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
