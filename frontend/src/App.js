import React, { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import Dashboard from './Dashboard';
import ThreatModal from './ThreatModal';
import Login from './Login';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

function App() {
    // Restore token from localStorage on page load
    const [token, setToken] = useState(() => localStorage.getItem('cg_token'));

    const [stats, setStats] = useState({
        total_flows: 0,
        attacks_detected: 0,
        benign_count: 0,
        attack_breakdown: {}
    });
    const [alerts, setAlerts]               = useState([]);
    const [connected, setConnected]         = useState(false);
    const [selectedAlert, setSelectedAlert] = useState(null);

    useEffect(() => {
        if (!token) return;  // don't connect until authenticated

        // Pass JWT in the socket.io handshake auth payload
        const socket = io(API_URL, { auth: { token } });

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
            setAlerts((prev) => [alert, ...prev].slice(0, 200));
        });

        // Force logout if server rejects the token
        socket.on('connect_error', (err) => {
            if (err.message === 'Invalid token') {
                handleLogout();
            }
        });

        return () => socket.disconnect();
    }, [token]);  // reconnect when token changes

    const handleLogin = (newToken) => {
        setToken(newToken);
    };

    const handleLogout = () => {
        localStorage.removeItem('cg_token');
        setToken(null);
        setAlerts([]);
        setConnected(false);
        setSelectedAlert(null);
    };

    // Show login screen if not authenticated
    if (!token) {
        return <Login onLogin={handleLogin} />;
    }

    return (
        <>
            <Dashboard
                stats={stats}
                alerts={alerts}
                connected={connected}
                onAlertClick={setSelectedAlert}
                onLogout={handleLogout}
            />
            {selectedAlert && (
                <ThreatModal
                    alert={selectedAlert}
                    allAlerts={alerts}
                    onClose={() => setSelectedAlert(null)}
                />
            )}
        </>
    );
}

export default App;
