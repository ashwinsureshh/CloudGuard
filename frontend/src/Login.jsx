import React, { useState } from 'react';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res  = await fetch(`${API_URL}/api/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || 'Login failed');
      } else {
        localStorage.setItem('cg_token', data.token);
        onLogin(data.token);
      }
    } catch {
      setError('Cannot connect to server — is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
      <div className="w-full max-w-md">

        {/* Logo */}
        <div className="flex items-center gap-3 justify-center mb-8">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <span className="material-symbols-outlined text-blue-400">security</span>
          </div>
          <div>
            <h1 className="text-xl font-black text-white">CloudGuard</h1>
            <p className="text-xs text-slate-500">Network Security Operations Center</p>
          </div>
        </div>

        {/* Card */}
        <div className="bg-[#161f2c] rounded-2xl border border-slate-800 p-8 shadow-2xl">
          <h2 className="text-xl font-bold text-white mb-1">Analyst Sign In</h2>
          <p className="text-slate-500 text-sm mb-6">Enter your credentials to access the dashboard</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
                className="w-full h-11 px-4 rounded-lg bg-slate-900 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full h-11 px-4 rounded-lg bg-slate-900 border border-slate-700 text-white text-sm placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                <span className="material-symbols-outlined text-base">error</span>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full h-11 rounded-lg bg-blue-600 text-white font-bold text-sm shadow-lg shadow-blue-500/20 hover:bg-blue-500 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mt-2"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-base" style={{ animation: 'spin 1s linear infinite' }}>
                    progress_activity
                  </span>
                  Authenticating…
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-base">lock_open</span>
                  Sign In
                </>
              )}
            </button>
          </form>

          {/* Crypto info badge */}
          <div className="mt-6 p-3 rounded-lg bg-slate-800/60 border border-slate-700 space-y-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="material-symbols-outlined text-sm text-emerald-500">verified_user</span>
              <span className="font-mono">Auth: JWT HS256 · Passwords: SHA-256</span>
            </div>
            <p className="text-xs text-slate-600 font-mono pl-6">
              Demo → admin / admin123 &nbsp;|&nbsp; analyst / analyst123
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-slate-700 mt-6">
          Protected by JWT Authentication + HMAC-SHA256 Alert Integrity
        </p>
      </div>
    </div>
  );
}
