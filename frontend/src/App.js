import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import Dashboard from './Dashboard';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

function App() {
    const [stats, setStats] = useState({
        total_flows: 0,
        attacks_detected: 0,
        benign_count: 0,
        attack_breakdown: {}
    });
    const [alerts, setAlerts] = useState([]);
    const [connected, setConnected] = useState(false);

    useEffect(() => {
        const socket = io(API_URL);

        socket.on('connect', () => {
            setConnected(true);
            console.log('[CloudGuard] Socket connected');
        });

        socket.on('disconnect', () => {
            setConnected(false);
        });

        socket.on('stats_update', (data) => {
            setStats(data);
        });

        socket.on('new_alert', (alert) => {
            setAlerts((prev) => [alert, ...prev].slice(0, 50));
        });

        return () => socket.disconnect();
    }, []);

    return <Dashboard stats={stats} alerts={alerts} connected={connected} />;
}

export default App;
