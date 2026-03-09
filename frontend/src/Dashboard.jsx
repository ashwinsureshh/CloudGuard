import React, { useState, useMemo, useEffect } from 'react';

// ── Helpers ───────────────────────────────────────────────────────────────────
const PORT_NAMES = { 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 3389: 'RDP', 8080: 'HTTP-Alt' };
const formatPort  = (p) => PORT_NAMES[p] ? `${p} (${PORT_NAMES[p]})` : String(p);
const formatId    = (id) => `ALRT-${String(id).padStart(5, '0')}`;

const getSeverity = (alert) => {
  if (!alert.is_attack)          return { label: 'Benign',   bg: 'bg-emerald-500', row: '' };
  if (alert.confidence >= 0.95)  return { label: 'Critical', bg: 'bg-rose-600',    row: 'bg-rose-50/40 dark:bg-rose-900/10' };
  if (alert.severity === 'HIGH') return { label: 'High',     bg: 'bg-orange-500',  row: 'bg-orange-50/20 dark:bg-orange-900/5' };
  return                                { label: 'Medium',   bg: 'bg-yellow-500',  row: '' };
};

const attackBadgeStyle = (type) => ({
  BENIGN:       'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400',
  DDoS:         'bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400',
  BruteForce:   'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400',
  Infiltration: 'bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400',
  PortScan:     'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400',
}[type] || 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400');

const confBarColor = (alert) => {
  if (!alert.is_attack)          return 'bg-emerald-500';
  if (alert.confidence >= 0.95)  return 'bg-rose-600';
  if (alert.severity === 'HIGH') return 'bg-orange-500';
  return 'bg-yellow-500';
};

const SEV_MAP = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Benign' };
const ITEMS_PER_PAGE = 10;

const exportCSV = (alerts) => {
  const headers = ['ID','Timestamp','Source IP','Dst Port','Attack Type','Confidence','Severity'];
  const rows = alerts.map(a => [
    formatId(a.id), a.timestamp, a.src_ip, a.dst_port,
    a.attack_type, `${Math.round(a.confidence * 100)}%`, getSeverity(a).label
  ]);
  const csv  = [headers, ...rows].map(r => r.join(',')).join('\n');
  const url  = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  const el   = Object.assign(document.createElement('a'), { href: url, download: 'cloudguard_alerts.csv' });
  el.click();
  URL.revokeObjectURL(url);
};

// ── Stat Card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, icon, valueClass, borderClass, trendIcon, trendClass, trendLabel }) {
  return (
    <div className={`flex flex-col gap-2 rounded-xl p-5 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm ${borderClass}`}>
      <div className="flex justify-between items-start">
        <p className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">{label}</p>
        <span className={`material-symbols-outlined text-xl ${valueClass}`}>{icon}</span>
      </div>
      <p className={`text-3xl font-bold ${valueClass}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      <div className="flex items-center gap-1.5 mt-1">
        <span className={`material-symbols-outlined text-sm ${trendClass}`}>{trendIcon}</span>
        <p className={`text-xs font-semibold ${trendClass}`}>{trendLabel}</p>
      </div>
    </div>
  );
}

// ── Bar Chart ─────────────────────────────────────────────────────────────────
const BAR_H = 192; // px — max bar height

function AttackBarChart({ breakdown }) {
  const entries = Object.entries(breakdown || {});
  const maxVal  = Math.max(...entries.map(([, v]) => v), 1);
  if (!entries.length) return (
    <div className="flex items-center justify-center text-slate-400 text-sm" style={{ height: BAR_H + 32 }}>
      Waiting for attack data…
    </div>
  );
  return (
    <div className="flex items-end gap-4 px-4" style={{ height: BAR_H + 32 }}>
      {entries.map(([name, count]) => {
        const barPx = Math.max(Math.round((count / maxVal) * BAR_H), 6);
        return (
          <div key={name} className="flex-1 flex flex-col items-center gap-2">
            <div className="relative group w-full rounded-t-lg bg-rose-500/80 transition-all"
                 style={{ height: barPx }}>
              <div className="opacity-0 group-hover:opacity-100 absolute -top-7 left-1/2 -translate-x-1/2 bg-slate-800 text-white text-[10px] px-2 py-1 rounded whitespace-nowrap z-10">
                {count.toLocaleString()}
              </div>
            </div>
            <span className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wide">
              {name.length > 9 ? name.slice(0, 8) + '.' : name}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Donut Chart ───────────────────────────────────────────────────────────────
function DonutChart({ benign, attacks, total }) {
  const bPct = total > 0 ? Math.round((benign  / total) * 100) : 0;
  const aPct = total > 0 ? Math.round((attacks / total) * 100) : 0;
  return (
    <div className="flex flex-col items-center justify-center space-y-6 h-64">
      <div className="relative size-36">
        <svg className="size-full -rotate-90" viewBox="0 0 36 36">
          <circle cx="18" cy="18" r="16" fill="none" className="stroke-slate-200 dark:stroke-slate-700" strokeWidth="4" />
          {total > 0 && <>
            <circle cx="18" cy="18" r="16" fill="none" className="stroke-emerald-500" strokeWidth="4"
              strokeDasharray={`${bPct} 100`} />
            <circle cx="18" cy="18" r="16" fill="none" className="stroke-rose-500" strokeWidth="4"
              strokeDasharray={`${aPct} 100`} strokeDashoffset={`-${bPct}`} />
          </>}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold text-slate-900 dark:text-white">100%</span>
          <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest">Monitored</span>
        </div>
      </div>
      <div className="flex justify-center gap-6 w-full px-4">
        {[{ color: 'bg-emerald-500', label: 'Benign', pct: bPct },
          { color: 'bg-rose-500',    label: 'Malicious', pct: aPct }].map(({ color, label, pct }) => (
          <div key={label} className="flex items-center gap-2">
            <div className={`size-3 rounded-full ${color}`} />
            <div className="flex flex-col">
              <span className="text-xs font-bold uppercase text-slate-900 dark:text-white">{label}</span>
              <span className="text-[10px] text-slate-500">{pct}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
export default function Dashboard({ stats, alerts, connected, onAlertClick }) {
  const [showFilters, setShowFilters] = useState(true);
  const [page, setPage]               = useState(1);
  const [filters, setFilters]         = useState({ srcIp:'', threatId:'', dstPort:'', attackType:'', severity:'' });
  const [activeNav, setActiveNav]     = useState('dashboard'); // 'dashboard' | 'threats' | 'reports'
  const [showBell, setShowBell]       = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  const setFilter = (k, v) => setFilters(f => ({ ...f, [k]: v }));
  useEffect(() => setPage(1), [filters]);

  // Nav actions
  const goNav = (nav) => {
    setActiveNav(nav);
    setShowBell(false);
    setShowSettings(false);
    if (nav === 'threats') {
      setFilters(f => ({ ...f, severity: 'critical' }));
      setShowFilters(true);
    } else if (nav === 'dashboard') {
      setFilters({ srcIp:'', threatId:'', dstPort:'', attackType:'', severity:'' });
    }
  };

  // Recent critical/high alerts for bell dropdown
  const recentCritical = useMemo(() =>
    alerts.filter(a => a.is_attack && a.confidence >= 0.85).slice(0, 5),
  [alerts]);

  const filtered = useMemo(() => alerts.filter(a => {
    if (filters.srcIp      && !a.src_ip.includes(filters.srcIp))                                return false;
    if (filters.threatId   && !formatId(a.id).toLowerCase().includes(filters.threatId.toLowerCase())) return false;
    if (filters.dstPort    && a.dst_port !== parseInt(filters.dstPort))                          return false;
    if (filters.attackType && a.attack_type !== filters.attackType)                              return false;
    if (filters.severity   && getSeverity(a).label !== SEV_MAP[filters.severity])                return false;
    return true;
  }), [alerts, filters]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / ITEMS_PER_PAGE));
  const paged      = filtered.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);
  const detRate    = stats.total_flows > 0
    ? ((stats.attacks_detected / stats.total_flows) * 100).toFixed(1) + '%' : '0.0%';

  const pageNums = Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
    return Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
  }).filter(n => n <= totalPages);

  return (
    <div className="relative flex min-h-screen w-full flex-col bg-background-light dark:bg-background-dark font-display antialiased"
      onClick={e => {
        if (!e.target.closest('[data-dropdown]')) { setShowBell(false); setShowSettings(false); }
      }}>

      {/* ── Header ── */}
      <header className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-background-dark px-6 py-3 sticky top-0 z-40">
        <div className="flex items-center gap-4">
          <span className="material-symbols-outlined text-primary text-3xl">shield_with_heart</span>
          <div>
            <h2 className="text-slate-900 dark:text-white text-lg font-bold leading-tight tracking-tight">CloudGuard</h2>
            <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">Network Security Operations Center</span>
          </div>
        </div>
        <nav className="hidden md:flex items-center gap-6 ml-10">
          {[
            { key: 'dashboard', icon: 'dashboard',  label: 'Dashboard' },
            { key: 'threats',   icon: 'security',   label: 'Threats'   },
            { key: 'reports',   icon: 'analytics',  label: 'Reports'   },
          ].map(({ key, icon, label }) => (
            <button key={key} onClick={() => goNav(key)}
              className={`text-sm font-semibold flex items-center gap-1.5 pb-1 transition-colors ${
                activeNav === key
                  ? 'text-primary border-b-2 border-primary'
                  : 'text-slate-500 dark:text-slate-400 hover:text-primary border-b-2 border-transparent'
              }`}>
              <span className="material-symbols-outlined text-sm">{icon}</span> {label}
            </button>
          ))}
        </nav>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full ${connected ? 'bg-emerald-500/10' : 'bg-rose-500/10'}`}>
            <span className="relative flex h-2 w-2">
              {connected && <span className="animate-ping absolute inset-0 rounded-full bg-emerald-400 opacity-75" />}
              <span className={`relative inline-flex rounded-full h-2 w-2 ${connected ? 'bg-emerald-500' : 'bg-rose-500'}`} />
            </span>
            <span className={`text-xs font-bold uppercase tracking-wider ${connected ? 'text-emerald-500' : 'text-rose-500'}`}>
              {connected ? 'Live' : 'Offline'}
            </span>
          </div>

          {/* Bell */}
          <div className="relative" data-dropdown>
            <button onClick={() => { setShowBell(b => !b); setShowSettings(false); }}
              className={`p-2 rounded-lg transition-colors relative ${showBell ? 'bg-primary/10 text-primary' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'}`}>
              <span className="material-symbols-outlined text-[20px]">notifications</span>
              {recentCritical.length > 0 && (
                <span className="absolute -top-0.5 -right-0.5 size-4 flex items-center justify-center rounded-full bg-rose-500 text-white text-[9px] font-black">
                  {recentCritical.length}
                </span>
              )}
            </button>
            {showBell && (
              <div className="absolute right-0 top-12 w-80 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#161f2c] shadow-2xl z-50 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
                  <p className="text-sm font-bold text-slate-900 dark:text-white">Recent Threats</p>
                  <span className="text-[10px] text-slate-500">High confidence only</span>
                </div>
                {recentCritical.length === 0 ? (
                  <p className="px-4 py-6 text-sm text-slate-500 text-center">No high-confidence threats yet</p>
                ) : (
                  <ul className="divide-y divide-slate-100 dark:divide-slate-800 max-h-72 overflow-y-auto">
                    {recentCritical.map(a => (
                      <li key={a.id} className="px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                        onClick={() => { onAlertClick(a); setShowBell(false); }}>
                        <div className="flex justify-between items-start">
                          <div>
                            <p className="text-xs font-bold text-primary">{formatId(a.id)}</p>
                            <p className="text-xs text-slate-700 dark:text-slate-300 mt-0.5">{a.attack_type} from {a.src_ip}</p>
                          </div>
                          <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-500 uppercase">{Math.round(a.confidence*100)}%</span>
                        </div>
                        <p className="text-[10px] text-slate-400 mt-1">{a.timestamp}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          {/* Settings */}
          <div className="relative" data-dropdown>
            <button onClick={() => { setShowSettings(s => !s); setShowBell(false); }}
              className={`p-2 rounded-lg transition-colors ${showSettings ? 'bg-primary/10 text-primary' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'}`}>
              <span className="material-symbols-outlined text-[20px]">settings</span>
            </button>
            {showSettings && (
              <div className="absolute right-0 top-12 w-64 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#161f2c] shadow-2xl z-50 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800">
                  <p className="text-sm font-bold text-slate-900 dark:text-white">Settings</p>
                </div>
                <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                  {[
                    { icon: 'wifi', label: 'Backend URL', sub: 'localhost:5001' },
                    { icon: 'history', label: 'Alert buffer', sub: '200 events' },
                    { icon: 'bar_chart', label: 'Chart refresh', sub: 'Real-time (WS)' },
                    { icon: 'download', label: 'Export format', sub: 'CSV' },
                  ].map(({ icon, label, sub }) => (
                    <li key={label} className="flex items-center gap-3 px-4 py-3">
                      <span className="material-symbols-outlined text-slate-400 text-sm">{icon}</span>
                      <div>
                        <p className="text-xs font-semibold text-slate-900 dark:text-white">{label}</p>
                        <p className="text-[10px] text-slate-500">{sub}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="p-6 max-w-[1600px] mx-auto w-full space-y-6">

        {/* ── Stat Cards ── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard label="Total Flows"      value={stats.total_flows}       icon="dynamic_feed"  valueClass="text-primary"                    borderClass="" trendIcon="trending_up" trendClass="text-emerald-500" trendLabel="Monitoring active" />
          <StatCard label="Attacks Detected" value={stats.attacks_detected}  icon="gpp_maybe"     valueClass="text-rose-500 dark:text-rose-400" borderClass="border-l-4 border-l-rose-500"    trendIcon="trending_up" trendClass="text-rose-500"    trendLabel="Elevated risk" />
          <StatCard label="Benign Traffic"   value={stats.benign_count}      icon="verified_user" valueClass="text-emerald-600 dark:text-emerald-500" borderClass="border-l-4 border-l-emerald-500" trendIcon="trending_flat" trendClass="text-slate-400"  trendLabel="Within baseline" />
          <StatCard label="Detection Rate"   value={detRate}                 icon="target"        valueClass="text-slate-900 dark:text-white"   borderClass="border-l-4 border-l-primary"     trendIcon="check_circle" trendClass="text-emerald-500" trendLabel="Model active" />
        </div>

        {/* ── Charts ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Attack Type Counts</h3>
                <p className="text-sm text-slate-500">Real-time breakdown of detected threats</p>
              </div>
              <span className="material-symbols-outlined text-slate-400">bar_chart</span>
            </div>
            <AttackBarChart breakdown={stats.attack_breakdown} />
          </div>
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Traffic Distribution</h3>
              <span className="material-symbols-outlined text-slate-400">pie_chart</span>
            </div>
            <DonutChart benign={stats.benign_count} attacks={stats.attacks_detected} total={stats.total_flows} />
          </div>
        </div>

        {/* ── Reports Panel (shown when activeNav === 'reports') ── */}
        {activeNav === 'reports' && (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm p-6">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Session Report</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {[
                { label: 'Total Events',   value: stats.total_flows.toLocaleString(),      color: 'text-primary' },
                { label: 'Threats Found',  value: stats.attacks_detected.toLocaleString(),  color: 'text-rose-500' },
                { label: 'Benign Events',  value: stats.benign_count.toLocaleString(),       color: 'text-emerald-500' },
                { label: 'Detection Rate', value: detRate,                                    color: 'text-slate-900 dark:text-white' },
              ].map(({ label, value, color }) => (
                <div key={label} className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                  <p className="text-[10px] font-bold uppercase text-slate-500 mb-1">{label}</p>
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
            <p className="text-sm font-bold text-slate-900 dark:text-white mb-3">Attack Type Breakdown</p>
            <div className="space-y-2">
              {Object.entries(stats.attack_breakdown || {}).map(([type, count]) => {
                const pct = stats.attacks_detected > 0 ? Math.round((count / stats.attacks_detected) * 100) : 0;
                return (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 w-24">{type}</span>
                    <div className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-rose-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-xs font-bold text-slate-500 w-16 text-right">{count.toLocaleString()} ({pct}%)</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Alert Feed ── */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">

          {/* Feed Header */}
          <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50/50 dark:bg-slate-800/50">
            <div className="flex items-center gap-3">
              <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                {activeNav === 'threats' ? 'Threat Feed' : 'Live Alert Feed'}
              </h3>
              <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-500 text-[10px] font-bold uppercase tracking-widest border border-rose-500/20">
                {activeNav === 'threats' ? 'Critical Only' : 'Active Threats'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setShowFilters(s => !s)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                <span className="material-symbols-outlined text-sm">filter_alt</span>
                {showFilters ? 'Hide' : 'Filter'}
              </button>
              <button onClick={() => exportCSV(filtered)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary text-white text-xs font-bold hover:brightness-110 transition-all">
                <span className="material-symbols-outlined text-sm">download</span> Export CSV
              </button>
            </div>
          </div>

          {/* Filters */}
          {showFilters && (
            <div className="px-6 py-4 bg-slate-50/30 dark:bg-slate-800/20 border-b border-slate-200 dark:border-slate-800">
              <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
                {/* Source IP */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-bold uppercase text-slate-500 dark:text-slate-400">Source IP</label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-2 top-1/2 -translate-y-1/2 text-sm text-slate-400">search</span>
                    <input value={filters.srcIp} onChange={e => setFilter('srcIp', e.target.value)}
                      className="w-full pl-8 pr-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:ring-1 focus:ring-primary"
                      placeholder="e.g. 192.168.1.1" />
                  </div>
                </div>
                {/* Threat ID */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-bold uppercase text-slate-500 dark:text-slate-400">Threat ID</label>
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-2 top-1/2 -translate-y-1/2 text-sm text-slate-400">search</span>
                    <input value={filters.threatId} onChange={e => setFilter('threatId', e.target.value)}
                      className="w-full pl-8 pr-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:ring-1 focus:ring-primary"
                      placeholder="e.g. ALRT-00042" />
                  </div>
                </div>
                {/* Dest Port */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-bold uppercase text-slate-500 dark:text-slate-400">Dest Port</label>
                  <input value={filters.dstPort} onChange={e => setFilter('dstPort', e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:ring-1 focus:ring-primary"
                    placeholder="Any" type="number" />
                </div>
                {/* Attack Type */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-bold uppercase text-slate-500 dark:text-slate-400">Attack Type</label>
                  <select value={filters.attackType} onChange={e => setFilter('attackType', e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:ring-1 focus:ring-primary">
                    <option value="">All Types</option>
                    <option value="DDoS">DDoS</option>
                    <option value="PortScan">PortScan</option>
                    <option value="BruteForce">BruteForce</option>
                    <option value="Infiltration">Infiltration</option>
                    <option value="BENIGN">Benign</option>
                  </select>
                </div>
                {/* Severity */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-bold uppercase text-slate-500 dark:text-slate-400">Severity</label>
                  <select value={filters.severity} onChange={e => setFilter('severity', e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:ring-1 focus:ring-primary">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Benign</option>
                  </select>
                </div>
                {/* Clear */}
                <div className="flex flex-col gap-1.5 justify-end">
                  <button onClick={() => setFilters({ srcIp:'', threatId:'', dstPort:'', attackType:'', severity:'' })}
                    className="w-full px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                    Clear All
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 dark:bg-slate-800/30">
                  {['Threat ID','Timestamp','Source IP','Dest Port','Attack Type','Confidence','Severity'].map(h => (
                    <th key={h} className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {paged.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-6 py-14 text-center text-slate-400 text-sm">
                      {alerts.length === 0 ? 'Waiting for traffic events…' : 'No alerts match the current filters.'}
                    </td>
                  </tr>
                ) : paged.map(alert => {
                  const sev  = getSeverity(alert);
                  const conf = Math.round(alert.confidence * 100);
                  return (
                    <tr key={alert.id} onClick={() => onAlertClick(alert)}
                      className={`${sev.row} hover:bg-primary/5 dark:hover:bg-primary/10 cursor-pointer transition-[background-color] duration-150`}>
                      <td className="px-6 py-3.5 text-xs font-mono font-semibold text-primary">{formatId(alert.id)}</td>
                      <td className="px-6 py-3.5 text-xs font-mono text-slate-500 dark:text-slate-400">{alert.timestamp}</td>
                      <td className="px-6 py-3.5 text-sm font-medium text-slate-900 dark:text-white">{alert.src_ip}</td>
                      <td className="px-6 py-3.5 text-sm text-slate-600 dark:text-slate-300">{formatPort(alert.dst_port)}</td>
                      <td className="px-6 py-3.5">
                        <span className={`px-2 py-1 rounded text-[11px] font-bold ${attackBadgeStyle(alert.attack_type)}`}>
                          {alert.attack_type}
                        </span>
                      </td>
                      <td className="px-6 py-3.5">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${confBarColor(alert)}`} style={{ width: `${conf}%` }} />
                          </div>
                          <span className="text-xs font-bold text-slate-700 dark:text-slate-300">{conf}%</span>
                        </div>
                      </td>
                      <td className="px-6 py-3.5">
                        <span className={`inline-flex px-2.5 py-1 rounded-full text-white text-[10px] font-black uppercase ${sev.bg}`}>
                          {sev.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 flex justify-between items-center text-xs text-slate-500">
            <p>Showing {filtered.length === 0 ? 0 : (page-1)*ITEMS_PER_PAGE+1}–{Math.min(page*ITEMS_PER_PAGE, filtered.length)} of {filtered.length.toLocaleString()} alerts</p>
            <div className="flex gap-1.5">
              <button onClick={() => setPage(p => Math.max(1,p-1))} disabled={page===1}
                className="px-2.5 py-1 rounded border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors">Previous</button>
              {pageNums.map(n => (
                <button key={n} onClick={() => setPage(n)}
                  className={`px-2.5 py-1 rounded font-medium transition-colors ${n===page ? 'bg-primary text-white' : 'border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800'}`}>
                  {n}
                </button>
              ))}
              <button onClick={() => setPage(p => Math.min(totalPages,p+1))} disabled={page===totalPages}
                className="px-2.5 py-1 rounded border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 transition-colors">Next</button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
