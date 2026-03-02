import React from 'react';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
    ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';

const COLORS = ['#6366f1', '#f43f5e', '#f59e0b', '#10b981', '#3b82f6'];

const SEVERITY_COLOR = {
    HIGH: '#f43f5e',
    MEDIUM: '#f59e0b',
    NONE: '#10b981'
};

function StatCard({ label, value, highlight }) {
    return (
        <div style={{
            background: highlight ? 'linear-gradient(135deg,#f43f5e22,#f43f5e44)' : '#1e293b',
            border: `1px solid ${highlight ? '#f43f5e66' : '#334155'}`,
            borderRadius: 12,
            padding: '20px 24px',
            flex: 1,
            minWidth: 160
        }}>
            <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 6 }}>{label}</div>
            <div style={{
                fontSize: 32, fontWeight: 700,
                color: highlight ? '#f43f5e' : '#f1f5f9'
            }}>{value.toLocaleString()}</div>
        </div>
    );
}

function Dashboard({ stats, alerts, connected }) {
    const attackData = Object.entries(stats.attack_breakdown || {}).map(([name, value]) => ({ name, value }));

    const detectionRate = stats.total_flows > 0
        ? ((stats.attacks_detected / stats.total_flows) * 100).toFixed(1)
        : 0;

    return (
        <div style={{
            minHeight: '100vh',
            background: '#0f172a',
            color: '#f1f5f9',
            fontFamily: "'Inter', 'Segoe UI', sans-serif",
            padding: '24px 32px'
        }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 32 }}>
                <div>
                    <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, letterSpacing: '-0.5px' }}>
                        🛡️ CloudGuard
                    </h1>
                    <p style={{ margin: '4px 0 0', color: '#64748b', fontSize: 14 }}>
                        Real-time Network Intrusion Detection
                    </p>
                </div>
                <div style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    background: connected ? '#10b98122' : '#f43f5e22',
                    border: `1px solid ${connected ? '#10b98155' : '#f43f5e55'}`,
                    borderRadius: 20, padding: '6px 14px', fontSize: 13
                }}>
                    <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: connected ? '#10b981' : '#f43f5e',
                        boxShadow: connected ? '0 0 6px #10b981' : '0 0 6px #f43f5e'
                    }} />
                    {connected ? 'Live' : 'Disconnected'}
                </div>
            </div>

            {/* Stat Cards */}
            <div style={{ display: 'flex', gap: 16, marginBottom: 32, flexWrap: 'wrap' }}>
                <StatCard label="Total Flows" value={stats.total_flows} />
                <StatCard label="Attacks Detected" value={stats.attacks_detected} highlight />
                <StatCard label="Benign Traffic" value={stats.benign_count} />
                <StatCard label="Detection Rate (%)" value={Number(detectionRate)} />
            </div>

            {/* Charts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 32 }}>
                {/* Bar Chart */}
                <div style={{ background: '#1e293b', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
                    <h3 style={{ margin: '0 0 16px', fontSize: 15, color: '#94a3b8' }}>Attack Type Breakdown</h3>
                    <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={attackData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                            <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }} />
                            <Bar dataKey="value" fill="#6366f1" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Pie Chart */}
                <div style={{ background: '#1e293b', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
                    <h3 style={{ margin: '0 0 16px', fontSize: 15, color: '#94a3b8' }}>Traffic Distribution</h3>
                    <ResponsiveContainer width="100%" height={220}>
                        <PieChart>
                            <Pie
                                data={attackData.length > 0 ? attackData : [{ name: 'No Data', value: 1 }]}
                                cx="50%" cy="50%"
                                outerRadius={80}
                                dataKey="value"
                                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                                labelLine={false}
                            >
                                {attackData.map((_, i) => (
                                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                                ))}
                            </Pie>
                            <Legend wrapperStyle={{ color: '#94a3b8', fontSize: 12 }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Alerts Table */}
            <div style={{ background: '#1e293b', borderRadius: 12, padding: 20, border: '1px solid #334155' }}>
                <h3 style={{ margin: '0 0 16px', fontSize: 15, color: '#94a3b8' }}>
                    Live Alert Feed <span style={{ color: '#475569', fontWeight: 400 }}>({alerts.length} events)</span>
                </h3>
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid #334155', color: '#64748b' }}>
                                {['Time', 'Source IP', 'Dst Port', 'Attack Type', 'Confidence', 'Severity'].map(h => (
                                    <th key={h} style={{ textAlign: 'left', padding: '8px 12px', fontWeight: 600 }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {alerts.slice(0, 15).map((a) => (
                                <tr key={a.id} style={{
                                    borderBottom: '1px solid #1e293b',
                                    background: a.is_attack ? '#f43f5e0a' : 'transparent',
                                    transition: 'background 0.2s'
                                }}>
                                    <td style={{ padding: '8px 12px', color: '#64748b' }}>{a.timestamp}</td>
                                    <td style={{ padding: '8px 12px', fontFamily: 'monospace' }}>{a.src_ip}</td>
                                    <td style={{ padding: '8px 12px' }}>{a.dst_port}</td>
                                    <td style={{ padding: '8px 12px', fontWeight: 600, color: a.is_attack ? '#f43f5e' : '#10b981' }}>
                                        {a.attack_type}
                                    </td>
                                    <td style={{ padding: '8px 12px' }}>{(a.confidence * 100).toFixed(1)}%</td>
                                    <td style={{ padding: '8px 12px' }}>
                                        <span style={{
                                            background: `${SEVERITY_COLOR[a.severity]}22`,
                                            color: SEVERITY_COLOR[a.severity],
                                            border: `1px solid ${SEVERITY_COLOR[a.severity]}55`,
                                            borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600
                                        }}>
                                            {a.severity}
                                        </span>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {alerts.length === 0 && (
                        <div style={{ textAlign: 'center', padding: 40, color: '#475569' }}>Waiting for traffic events…</div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default Dashboard;
