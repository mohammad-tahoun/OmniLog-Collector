import React, { useState } from 'react';

export interface DeviceItem {
  agent_id: string;
  hostname: string;
  os_category: string;
  os_name: string;
  os_version: string;
  ip_address: string;
  mac_address: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  cpu_percent: number;
  ram_percent: number;
  queue_depth: number;
  events_sent_total: number;
  enrolled_at: string;
  last_seen_at: string;
}

export interface FleetCategoryGroup {
  category: string;
  display_name: string;
  total_devices: number;
  online_count: number;
  degraded_count: number;
  offline_count: number;
  devices: DeviceItem[];
}

export interface FleetSummary {
  total_agents: number;
  online_agents: number;
  degraded_agents: number;
  offline_agents: number;
  categories: Record<string, FleetCategoryGroup>;
}

interface FleetOverviewProps {
  fleet: FleetSummary | null;
  onSelectAgent?: (agentId: string) => void;
  onOpenEnrollModal: () => void;
}

const OS_ICONS: Record<string, string> = {
  windows_workstation: '🪟',
  windows_server: '🏢',
  ubuntu_server: '🐧',
  linux_endpoint: '💻'
};

export const FleetOverview: React.FC<FleetOverviewProps> = ({ fleet, onOpenEnrollModal }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  if (!fleet) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400 mr-3"></div>
        Connecting to Force-Fields Fleet Manager...
      </div>
    );
  }

  const allDevices: DeviceItem[] = Object.values(fleet.categories).flatMap(c => c.devices);

  const filteredDevices = allDevices.filter(d => {
    const matchesCat = selectedCategory === 'all' || d.os_category === selectedCategory;
    const matchesSearch = searchTerm === '' ||
      d.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.ip_address.includes(searchTerm) ||
      d.agent_id.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCat && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* 1. OS Category Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(fleet.categories).map(([catKey, cat]) => {
          const isSelected = selectedCategory === catKey;
          return (
            <div
              key={catKey}
              onClick={() => setSelectedCategory(isSelected ? 'all' : catKey)}
              className={`p-5 rounded-xl border cursor-pointer transition-all duration-200 ${
                isSelected
                  ? 'bg-slate-800/90 border-cyan-500 shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500'
                  : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-2xl">{OS_ICONS[catKey] || '🖥️'}</span>
                <div className="flex items-center space-x-1.5 text-xs font-mono">
                  <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/50">
                    {cat.online_count} online
                  </span>
                  {cat.offline_count > 0 && (
                    <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-400 border border-rose-800/50">
                      {cat.offline_count} off
                    </span>
                  )}
                </div>
              </div>
              <h3 className="font-semibold text-slate-100 text-sm tracking-wide">{cat.display_name}</h3>
              <div className="mt-2 flex items-baseline justify-between">
                <span className="text-2xl font-bold font-mono text-cyan-400">{cat.total_devices}</span>
                <span className="text-xs text-slate-400 font-mono">
                  {cat.online_count === cat.total_devices && cat.total_devices > 0
                    ? '100% HEALTHY'
                    : `${cat.online_count}/${cat.total_devices} active`}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* 2. Device Roster Header & Search */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <h2 className="text-base font-semibold text-slate-100 flex items-center">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 mr-2 shadow-sm shadow-cyan-400"></span>
              Dedicated Endpoint Fleet
              <span className="ml-2 px-2 py-0.5 rounded-full text-xs font-mono bg-slate-800 text-slate-300">
                {filteredDevices.length} endpoints
              </span>
            </h2>
            {selectedCategory !== 'all' && (
              <button
                onClick={() => setSelectedCategory('all')}
                className="text-xs text-cyan-400 hover:underline font-mono"
              >
                (Clear category filter)
              </button>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <input
              type="text"
              placeholder="Search hostname, IP, agent ID..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-64"
            />
            <button
              onClick={onOpenEnrollModal}
              className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium px-3.5 py-1.5 rounded-lg shadow-sm shadow-cyan-900/50 transition-all flex items-center"
            >
              <span className="mr-1.5 font-bold">+</span> Enroll New Agent
            </button>
          </div>
        </div>

        {/* 3. Device Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 font-mono border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">STATUS</th>
                <th className="py-3 px-4">HOST & AGENT ID</th>
                <th className="py-3 px-4">OS PLATFORM</th>
                <th className="py-3 px-4">IP / MAC</th>
                <th className="py-3 px-4">CPU & RAM LOAD</th>
                <th className="py-3 px-4">QUEUE DEPTH</th>
                <th className="py-3 px-4">EVENTS SENT</th>
                <th className="py-3 px-4">LAST SEEN</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    No active agents match the selected criteria.
                    <br />
                    <button
                      onClick={onOpenEnrollModal}
                      className="mt-3 text-cyan-400 underline font-mono text-xs"
                    >
                      Enroll your first agent now
                    </button>
                  </td>
                </tr>
              ) : (
                filteredDevices.map(device => {
                  const isOnline = device.status === 'ONLINE';
                  const isDegraded = device.status === 'DEGRADED';

                  return (
                    <tr key={device.agent_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="relative flex h-2.5 w-2.5">
                            {isOnline && (
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            )}
                            <span
                              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                                isOnline
                                  ? 'bg-emerald-500'
                                  : isDegraded
                                  ? 'bg-amber-500'
                                  : 'bg-rose-500'
                              }`}
                            ></span>
                          </span>
                          <span
                            className={`text-[11px] font-semibold ${
                              isOnline
                                ? 'text-emerald-400'
                                : isDegraded
                                ? 'text-amber-400'
                                : 'text-rose-400'
                            }`}
                          >
                            {device.status}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-100">{device.hostname}</div>
                        <div className="text-[10px] text-slate-500">{device.agent_id}</div>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="text-slate-300 flex items-center">
                          <span className="mr-1.5">{OS_ICONS[device.os_category] || '🖥️'}</span>
                          {device.os_version || device.os_name}
                        </div>
                        <div className="text-[10px] text-cyan-400/80">{device.os_category}</div>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        <div>{device.ip_address}</div>
                        <div className="text-[10px] text-slate-500">{device.mac_address}</div>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="space-y-1 w-32">
                          <div className="flex justify-between text-[10px] text-slate-400">
                            <span>CPU {device.cpu_percent.toFixed(1)}%</span>
                            <span>RAM {device.ram_percent.toFixed(0)}%</span>
                          </div>
                          <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden flex">
                            <div
                              className="bg-cyan-500 h-1.5"
                              style={{ width: `${Math.min(device.cpu_percent, 100)}%` }}
                            ></div>
                            <div
                              className="bg-indigo-500 h-1.5"
                              style={{ width: `${Math.min(device.ram_percent, 100)}%` }}
                            ></div>
                          </div>
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] ${
                            device.queue_depth > 50
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'text-slate-400'
                          }`}
                        >
                          {device.queue_depth} msgs
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300 font-semibold">
                        {device.events_sent_total.toLocaleString()}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {device.last_seen_at
                          ? new Date(device.last_seen_at).toLocaleTimeString()
                          : 'Never'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
