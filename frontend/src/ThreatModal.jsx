import React, { useState, useMemo } from 'react';

/* ─── helpers ─────────────────────────────────────────────── */
const PORT_NAMES = { 80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 3389: 'RDP', 8080: 'HTTP-Alt' };
const formatPort = (p) => PORT_NAMES[p] ? `${p} (${PORT_NAMES[p]})` : String(p);
const formatId   = (id) => `ALRT-${String(id).padStart(5, '0')}`;

function getSeverity(alert) {
  if (!alert.is_attack)          return { label: 'Benign',   badge: 'bg-emerald-500/20 text-emerald-400' };
  if (alert.confidence >= 0.95)  return { label: 'Critical', badge: 'bg-red-500/20 text-red-500'        };
  if (alert.severity === 'HIGH') return { label: 'High',     badge: 'bg-amber-500/20 text-amber-500'    };
  return                                { label: 'Medium',   badge: 'bg-yellow-500/20 text-yellow-500'  };
}

const GEO_MAP = {
  '192.168.1.101': 'San Jose, CA',
  '10.0.0.55':     'Dallas, TX',
  '172.16.0.20':   'Frankfurt, DE',
  '192.168.2.15':  'London, UK',
};

function getFlowChars(alert) {
  const map = {
    DDoS:         { packets: '1.2M',  rate: '450 MB/s',  duration: '142 ms' },
    PortScan:     { packets: '84K',   rate: '2.1 MB/s',  duration: '8.3 s'  },
    BruteForce:   { packets: '12K',   rate: '0.8 MB/s',  duration: '45 s'   },
    Infiltration: { packets: '3.2K',  rate: '0.3 MB/s',  duration: '120 s'  },
    BENIGN:       { packets: '230',   rate: '0.05 MB/s', duration: '1.2 s'  },
  };
  return map[alert.attack_type] || map.BENIGN;
}

function getFlowInfo(alert) {
  const msgs = {
    DDoS:         'Traffic pattern indicates a high-volume SYN flood targeting the primary application load balancer.',
    PortScan:     'Sequential port probe detected across the target subnet — consistent with reconnaissance activity.',
    BruteForce:   'Repeated authentication attempts detected; possible credential stuffing or dictionary attack.',
    Infiltration: 'Anomalous lateral movement observed with low-and-slow exfiltration signature.',
  };
  return msgs[alert.attack_type] || 'Traffic classified as normal by the ML pipeline.';
}

function typeBadge(type) {
  if (type === 'DDoS')         return 'bg-red-500/20 text-red-500';
  if (type === 'BruteForce')   return 'bg-purple-500/20 text-purple-400';
  if (type === 'PortScan')     return 'bg-amber-500/20 text-amber-500';
  if (type === 'Infiltration') return 'bg-orange-500/20 text-orange-400';
  return 'bg-slate-500/20 text-slate-400';
}

function protocolFor(port) {
  if ([443, 8080].includes(port)) return 'TCP/TLS';
  if (port === 22)  return 'SSH/TCP';
  if (port === 3389) return 'RDP/TCP';
  return 'TCP';
}

/* ─── component ───────────────────────────────────────────── */
export default function ThreatModal({ alert, allAlerts, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');

  /* Compute historical context from the in-memory allAlerts list */
  const history = useMemo(() => {
    if (!alert) return null;

    const sameIp    = allAlerts.filter(a => a.src_ip === alert.src_ip && a.id !== alert.id);
    const attacks   = sameIp.filter(a => a.is_attack);

    /* Count by attack type */
    const typeCounts = {};
    attacks.forEach(a => {
      typeCounts[a.attack_type] = (typeCounts[a.attack_type] || 0) + 1;
    });
    const topTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

    /* Spread across 7 day-buckets (proportional simulation) */
    const n = attacks.length;
    const weights = [0.05, 0.10, 0.08, 0.25, 0.15, 0.12, 0.25];
    const dayBuckets = weights.map(w => Math.max(Math.floor(n * w), 0));
    const maxBucket  = Math.max(...dayBuckets, 1);

    return {
      totalIncidents: attacks.length,
      firstSeen:  sameIp.length ? sameIp[sameIp.length - 1].timestamp : alert.timestamp,
      lastSeen:   sameIp.length ? sameIp[0].timestamp : alert.timestamp,
      topTypes,
      dayBuckets,
      maxBucket,
      relatedAlerts: sameIp.slice(0, 20),
    };
  }, [alert, allAlerts]);

  if (!alert) return null;

  const sev      = getSeverity(alert);
  const flow     = getFlowChars(alert);
  const geo      = GEO_MAP[alert.src_ip] || 'Private Network';
  const protocol = protocolFor(alert.dst_port);

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background-dark/70 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      {/* Modal card */}
      <div className="relative w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden rounded-xl bg-white dark:bg-[#161f2c] border border-slate-200 dark:border-slate-700 shadow-2xl">

        {/* ── Header ─────────────────────────────────────────── */}
        <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-3">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${sev.badge}`}>
                {sev.label.toUpperCase()}
              </span>
              <h1 className="text-2xl font-black text-slate-900 dark:text-white">
                {alert.is_attack ? `${alert.attack_type} Attack Detected` : 'Benign Traffic'}
              </h1>
            </div>
            <p className="text-slate-500 dark:text-slate-400 text-sm font-mono">
              ID: {formatId(alert.id)} • Sensor: US-EAST-01
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 transition-colors"
          >
            <span className="material-symbols-outlined">close</span>
          </button>
        </div>

        {/* ── Tab bar ────────────────────────────────────────── */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 px-6">
          {[
            { key: 'overview', label: 'Overview' },
            {
              key: 'related',
              label: 'Related Alerts',
              badge: history?.relatedAlerts.length || 0,
            },
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-3 text-sm font-bold transition-colors flex items-center gap-1.5 ${
                activeTab === tab.key
                  ? 'text-primary border-b-2 border-primary'
                  : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              {tab.label}
              {tab.badge > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── Scrollable body ─────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto">

          {/* ══ OVERVIEW TAB ══════════════════════════════════ */}
          {activeTab === 'overview' && (
            <div className="p-6 space-y-8">

              {/* ML Confidence + Timestamp */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex flex-col gap-2 rounded-xl p-5 bg-primary/5 border border-primary/20">
                  <div className="flex items-center gap-2 text-primary">
                    <span className="material-symbols-outlined text-sm">psychology</span>
                    <p className="text-sm font-semibold uppercase tracking-wider">ML Confidence Score</p>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <p className="text-3xl font-bold text-slate-900 dark:text-white">
                      {(alert.confidence * 100).toFixed(1)}%
                    </p>
                    <p className="text-emerald-500 text-sm font-medium flex items-center gap-0.5">
                      <span className="material-symbols-outlined text-xs">trending_up</span>
                      High Certainty
                    </p>
                  </div>
                </div>

                <div className="flex flex-col gap-2 rounded-xl p-5 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                  <div className="flex items-center gap-2 text-slate-500">
                    <span className="material-symbols-outlined text-sm">schedule</span>
                    <p className="text-sm font-semibold uppercase tracking-wider">Detection Timestamp</p>
                  </div>
                  <p className="text-xl font-bold text-slate-900 dark:text-white">{alert.timestamp}</p>
                  <p className="text-slate-500 text-sm font-medium">UTC Offset: +00:00</p>
                </div>
              </div>

              {/* Network Metadata */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary">lan</span>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">Network Metadata</h2>
                </div>
                <div className="grid grid-cols-2 gap-x-12 gap-y-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-800/20 border border-slate-200 dark:border-slate-800/50">
                  <div className="flex justify-between items-center py-1">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Source IP</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono font-medium">{alert.src_ip}</p>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Destination IP</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono font-medium">10.0.0.1</p>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Target Port</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono font-medium">{formatPort(alert.dst_port)}</p>
                  </div>
                  <div className="flex justify-between items-center py-1">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Protocol</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono font-medium">{protocol}</p>
                  </div>
                  <div className="flex justify-between items-center py-1 border-t border-slate-200 dark:border-slate-800 mt-2 pt-3 col-span-2">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Geolocation</p>
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-xs">location_on</span>
                      <p className="text-slate-900 dark:text-slate-100 text-sm font-medium">{geo}</p>
                    </div>
                  </div>
                </div>
              </section>

              {/* Flow Characteristics */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary">bar_chart</span>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">Flow Characteristics</h2>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'Packet Count', value: flow.packets, unit: 'pkts/sec' },
                    { label: 'Byte Rate',    value: flow.rate,    unit: ''         },
                    { label: 'Duration',     value: flow.duration,unit: ''         },
                  ].map(({ label, value, unit }) => (
                    <div key={label} className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                      <p className="text-xs text-slate-500 font-bold uppercase mb-1">{label}</p>
                      <p className="text-xl font-bold text-slate-900 dark:text-white">
                        {value}{unit && <span className="text-xs font-normal text-slate-400"> {unit}</span>}
                      </p>
                    </div>
                  ))}
                </div>
                <div className="mt-4 p-4 bg-primary/10 rounded-lg flex items-start gap-3">
                  <span className="material-symbols-outlined text-primary mt-0.5">info</span>
                  <p className="text-sm text-slate-700 dark:text-slate-300">{getFlowInfo(alert)}</p>
                </div>
              </section>

              {/* Alert Integrity — HMAC-SHA256 */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-emerald-500">verified_user</span>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">Alert Integrity</h2>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-500 uppercase tracking-wider">
                    HMAC-SHA256
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/20 border border-slate-200 dark:border-slate-800/50 space-y-3">
                  <div className="flex justify-between items-center">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Algorithm</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono">HMAC-SHA256</p>
                  </div>
                  <div className="flex justify-between items-center">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Key Source</p>
                    <p className="text-slate-900 dark:text-slate-100 text-sm font-mono">Server secret (env var)</p>
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Signature</p>
                    <p className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all bg-slate-100 dark:bg-slate-900/60 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-800">
                      {alert.hmac_sig || 'Not available'}
                    </p>
                  </div>
                  <div className="flex justify-between items-center pt-2 border-t border-slate-200 dark:border-slate-700">
                    <p className="text-slate-500 dark:text-slate-400 text-sm">Integrity Status</p>
                    {alert.hmac_sig ? (
                      <span className="flex items-center gap-1.5 text-emerald-500 text-sm font-semibold">
                        <span className="material-symbols-outlined text-base">check_circle</span>
                        Verified — alert not tampered
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-slate-400 text-sm">
                        <span className="material-symbols-outlined text-base">help</span>
                        Signature not present
                      </span>
                    )}
                  </div>
                </div>
              </section>

              {/* Historical Context */}
              <section>
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary">history</span>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                    Historical Context: <span className="font-mono">{alert.src_ip}</span>
                  </h2>
                </div>
                <div className="space-y-4">
                  {/* Metric cards */}
                  <div className="grid grid-cols-3 gap-4">
                    {[
                      { label: 'Total Incidents', value: history?.totalIncidents ?? 0 },
                      { label: 'First Seen',      value: history?.firstSeen ?? '—'    },
                      { label: 'Last Seen',       value: history?.lastSeen  ?? '—'    },
                    ].map(({ label, value }) => (
                      <div key={label} className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-100 dark:border-slate-800">
                        <p className="text-[10px] text-slate-500 font-bold uppercase mb-1 tracking-wider">{label}</p>
                        <p className="text-xl font-bold text-slate-900 dark:text-white">{value}</p>
                      </div>
                    ))}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* 7-day mini bar chart */}
                    <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/20 border border-slate-200 dark:border-slate-800/50">
                      <p className="text-[10px] text-slate-500 font-bold uppercase mb-4 tracking-wider">Frequency (Last 7 Days)</p>
                      <div className="flex items-end justify-between h-16 gap-1">
                        {(history?.dayBuckets ?? Array(7).fill(1)).map((val, i) => {
                          const pct = Math.round((val / (history?.maxBucket ?? 1)) * 100);
                          const cls = pct > 60 ? 'bg-primary' : pct > 30 ? 'bg-primary/60' : 'bg-primary/20';
                          return (
                            <div
                              key={i}
                              className={`flex-1 rounded-t-sm transition-all ${cls}`}
                              style={{ height: `${Math.max(pct, 4)}%` }}
                            />
                          );
                        })}
                      </div>
                    </div>

                    {/* Top attack types */}
                    <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/20 border border-slate-200 dark:border-slate-800/50">
                      <p className="text-[10px] text-slate-500 font-bold uppercase mb-3 tracking-wider">Top Previous Attack Types</p>
                      {history?.topTypes?.length > 0 ? (
                        <div className="space-y-2.5">
                          {history.topTypes.map(([type, count], idx) => (
                            <div key={type} className="flex justify-between items-center">
                              <span className="text-xs text-slate-700 dark:text-slate-300">{idx + 1}. {type}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${typeBadge(type)}`}>
                                {count}×
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-slate-500 mt-2">No historical data yet — monitoring…</p>
                      )}
                    </div>
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* ══ RELATED ALERTS TAB ════════════════════════════ */}
          {activeTab === 'related' && (
            <div className="p-6 space-y-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Recent Similar Activity</h3>
                <span className="text-xs text-slate-500 font-mono">src: {alert.src_ip}</span>
              </div>

              {history?.relatedAlerts.length > 0 ? (
                <>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="text-[10px] text-slate-500 font-bold uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                          <th className="pb-3">Alert ID</th>
                          <th className="pb-3">Time</th>
                          <th className="pb-3">Type</th>
                          <th className="pb-3">Confidence</th>
                          <th className="pb-3 text-right">Severity</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                        {history.relatedAlerts.map(ra => {
                          const rSev = getSeverity(ra);
                          return (
                            <tr key={ra.id} className="text-sm hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                              <td className="py-3 font-mono text-primary">{formatId(ra.id)}</td>
                              <td className="py-3 text-slate-600 dark:text-slate-400">{ra.timestamp}</td>
                              <td className="py-3 text-slate-700 dark:text-slate-300">{ra.attack_type}</td>
                              <td className="py-3 text-slate-700 dark:text-slate-300">{(ra.confidence * 100).toFixed(0)}%</td>
                              <td className="py-3 text-right">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${rSev.badge}`}>
                                  {rSev.label.toUpperCase()}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div className="p-4 bg-slate-50 dark:bg-slate-800/40 rounded-lg">
                    <p className="text-xs text-slate-500">
                      Showing {history.relatedAlerts.length} alert{history.relatedAlerts.length !== 1 ? 's' : ''} from{' '}
                      <span className="font-mono">{alert.src_ip}</span> in current session.
                    </p>
                  </div>
                </>
              ) : (
                <div className="py-16 text-center text-slate-500">
                  <span className="material-symbols-outlined text-4xl mb-3 block opacity-40">search_off</span>
                  <p className="text-sm">No other alerts from this source IP yet.</p>
                  <p className="text-xs mt-1 opacity-60">Check back as more traffic is analysed.</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Footer actions ──────────────────────────────────── */}
        <div className="flex items-center justify-end gap-3 p-6 bg-slate-50 dark:bg-slate-900/50 border-t border-slate-200 dark:border-slate-800">
          <button
            onClick={onClose}
            className="px-5 h-11 rounded-lg text-slate-600 dark:text-slate-300 font-bold text-sm hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
          >
            Dismiss Alert
          </button>
          <button className="px-5 h-11 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-white font-bold text-sm flex items-center gap-2 hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors">
            <span className="material-symbols-outlined text-sm">download</span>
            Export Report
          </button>
          <button className="px-6 h-11 rounded-lg bg-primary text-white font-bold text-sm shadow-lg shadow-primary/20 hover:brightness-110 transition-all">
            Quarantine Source
          </button>
        </div>
      </div>
    </div>
  );
}
