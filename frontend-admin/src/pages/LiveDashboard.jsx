import React, { useState, useEffect, useCallback } from 'react';
import Plot from 'react-plotly.js';
import { fetchStats, fetchRecentEvents } from '../api';

const ACTION_COLORS = {
  BLOCKED: '#ef4444',
  REDACTED: '#f97316',
  FLAGGED: '#eab308',
  PASSED: '#22c55e',
  ALLOWED: '#22c55e',
  HONEYPOT: '#a855f7',
};

function StatCard({ label, value, change, color }) {
  return (
    <div
      className="flex-1 p-5"
      style={{
        background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '8px',
        borderLeft: `3px solid ${color}`,
      }}
    >
      <div className="flex items-baseline gap-3">
        <span className="font-bold text-white" style={{ fontSize: '32px' }}>
          {typeof value === 'number' ? (value >= 1000 ? (value / 1000).toFixed(1) + 'k' : value) : value}
        </span>
        {change !== undefined && (
          <span
            style={{
              fontSize: '12px',
              color: change >= 0 ? '#22c55e' : '#ef4444',
              fontFamily: "'JetBrains Mono'",
            }}
          >
            {change >= 0 ? '↑' : '↓'}{Math.abs(change)}%
          </span>
        )}
      </div>
      <div style={{ color: '#9ca3af', fontSize: '13px', marginTop: '4px' }}>{label}</div>
    </div>
  );
}

function LayerBadge({ layer }) {
  return (
    <div
      className="flex items-center justify-center flex-shrink-0"
      style={{
        width: '28px',
        height: '28px',
        borderRadius: '50%',
        background: '#1a1a1a',
        border: '1px solid rgba(255,255,255,0.12)',
        fontFamily: "'JetBrains Mono'",
        fontSize: '11px',
        color: '#9ca3af',
      }}
    >
      L{layer}
    </div>
  );
}

function ActionBadge({ action }) {
  const bg = ACTION_COLORS[action] || '#6b7280';
  return (
    <span
      className="inline-block px-2 py-0.5 uppercase font-semibold"
      style={{
        background: bg,
        color: '#fff',
        borderRadius: '6px',
        fontSize: '11px',
        letterSpacing: '0.03em',
      }}
    >
      {action}
    </span>
  );
}

function EventCard({ event }) {
  const sessionShort = (event.session_id || '').slice(0, 8);
  const reason = event.reason || '';
  const ts = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    : '';

  return (
    <div
      className="flex items-start gap-3 p-4"
      style={{
        background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '8px',
      }}
    >
      <LayerBadge layer={event.layer || 0} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span style={{ fontFamily: "'JetBrains Mono'", fontSize: '12px', color: '#9ca3af' }}>
            ID: ...{sessionShort}
          </span>
          <span style={{ color: '#6b7280', fontSize: '12px' }}>{ts}</span>
        </div>
        <p className="text-white text-sm mt-1 truncate">{reason}</p>
        <div className="flex items-center gap-2 mt-2">
          <ActionBadge action={event.action || 'PASSED'} />
          {event.owasp_tag && event.owasp_tag !== 'NONE' && (
            <span
              className="px-2 py-0.5"
              style={{
                background: '#374151',
                borderRadius: '4px',
                fontFamily: "'JetBrains Mono'",
                fontSize: '11px',
                color: '#9ca3af',
              }}
            >
              {event.owasp_tag}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export default function LiveDashboard({ events }) {
  const [stats, setStats] = useState({
    active_sessions: 0,
    blocked_today: 0,
    honeypot_active: 0,
    total_events_today: 0,
  });

  const loadStats = useCallback(async () => {
    try {
      const data = await fetchStats();
      setStats(data);
    } catch {
      // Stats unavailable — keep previous values
    }
  }, []);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 10000);
    return () => clearInterval(interval);
  }, [loadStats]);

  // Build drift map data from events
  const safePoints = events.filter((e) => e.action === 'PASSED' || e.action === 'ALLOWED');
  const driftPoints = events.filter((e) => e.action === 'FLAGGED' || e.action === 'HONEYPOT');
  const injectionPoints = events.filter((e) => e.action === 'BLOCKED');

  const makePlotData = (points, color, name) => ({
    x: points.map((p) => p.x_coord || Math.random() * 10),
    y: points.map((p) => p.y_coord || Math.random() * 10),
    mode: 'markers',
    type: 'scatter',
    name,
    marker: { color, size: 8, opacity: 0.8 },
    text: points.map((p) => `${p.session_id?.slice(0, 8) || '?'}: ${p.reason?.slice(0, 40) || ''}`),
    hoverinfo: 'text',
  });

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-white font-bold text-2xl">Live Threat Monitoring</h1>
          <p style={{ color: '#9ca3af', fontSize: '14px', marginTop: '4px' }}>
            Real-time semantic analysis and session tracking
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div
            className="flex items-center gap-2 px-4 py-2"
            style={{
              background: '#1a1a1a',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '8px',
              color: '#9ca3af',
              fontSize: '13px',
            }}
          >
            📅 Last 24 Hours ▾
          </div>
          <button
            className="px-4 py-2 text-white text-sm font-medium"
            style={{ background: '#ef4444', borderRadius: '8px', border: 'none', cursor: 'pointer' }}
          >
            Export Report
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-4 mb-8">
        <StatCard label="Active Sessions" value={stats.active_sessions} change={12} color="#3b82f6" />
        <StatCard label="Blocked Today" value={stats.blocked_today} change={-5} color="#ef4444" />
        <StatCard label="Honeypot Active" value={stats.honeypot_active} change={0} color="#f97316" />
        <StatCard label="Total Events" value={stats.total_events_today} change={24} color="#6b7280" />
      </div>

      {/* Two-column: Drift Map + Live Feed */}
      <div className="flex gap-6">
        {/* Drift Map */}
        <div
          className="flex-[3] p-5"
          style={{
            background: '#111111',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '8px',
          }}
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-white font-semibold text-base">Semantic Drift Map</h2>
              <p style={{ color: '#9ca3af', fontSize: '12px' }}>
                Real-time session trajectory risk analysis
              </p>
            </div>
            <div className="flex items-center gap-4">
              {[
                { color: '#22c55e', label: 'SAFE' },
                { color: '#eab308', label: 'DRIFT' },
                { color: '#ef4444', label: 'INJECTION' },
              ].map((l) => (
                <div key={l.label} className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background: l.color }} />
                  <span style={{ fontSize: '11px', color: '#9ca3af' }}>{l.label}</span>
                </div>
              ))}
            </div>
          </div>
          <Plot
            data={[
              makePlotData(safePoints, '#22c55e', 'Safe'),
              makePlotData(driftPoints, '#eab308', 'Drift'),
              makePlotData(injectionPoints, '#ef4444', 'Injection'),
            ]}
            layout={{
              autosize: true,
              height: 360,
              margin: { t: 10, b: 40, l: 50, r: 20 },
              paper_bgcolor: 'transparent',
              plot_bgcolor: 'transparent',
              xaxis: {
                title: { text: 'Semantic Complexity >', font: { color: '#6b7280', size: 11 } },
                gridcolor: 'rgba(255,255,255,0.05)',
                zerolinecolor: 'rgba(255,255,255,0.05)',
                tickfont: { color: '#6b7280', size: 10 },
              },
              yaxis: {
                title: { text: 'Drift Magnitude', font: { color: '#6b7280', size: 11 } },
                gridcolor: 'rgba(255,255,255,0.05)',
                zerolinecolor: 'rgba(255,255,255,0.05)',
                tickfont: { color: '#6b7280', size: 10 },
              },
              showlegend: false,
              font: { family: "'DM Sans'" },
            }}
            config={{ displayModeBar: false, responsive: true }}
            style={{ width: '100%' }}
          />
        </div>

        {/* Live Event Feed */}
        <div
          className="flex-[2] flex flex-col"
          style={{
            background: '#111111',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '8px',
            maxHeight: '500px',
          }}
        >
          <div className="flex items-center justify-between p-5 pb-3">
            <div>
              <h2 className="text-white font-semibold text-base">Live Event Feed</h2>
              <p style={{ color: '#9ca3af', fontSize: '12px' }}>Incoming requests & actions</p>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto px-4 pb-4 flex flex-col gap-2">
            {events.length === 0 ? (
              <div className="text-center py-8" style={{ color: '#6b7280', fontSize: '13px' }}>
                Waiting for events...
              </div>
            ) : (
              events.slice(0, 20).map((event, i) => <EventCard key={i} event={event} />)
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
