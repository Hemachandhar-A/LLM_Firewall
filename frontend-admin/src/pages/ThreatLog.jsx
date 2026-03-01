import React, { useState, useEffect, useCallback } from 'react';
import { fetchThreatLog, fetchSessionDetail } from '../api';

const ACTION_COLORS = {
  BLOCKED: '#ef4444',
  REDACTED: '#f97316',
  FLAGGED: '#eab308',
  PASSED: '#22c55e',
  ALLOWED: '#22c55e',
  QUARANTINED: '#a855f7',
};

const ACTIONS = ['All Actions', 'BLOCKED', 'REDACTED', 'FLAGGED', 'ALLOWED', 'QUARANTINED'];
const LAYERS = ['All Layers', 'Prompt Injection', 'PII Leakage', 'Toxic Language', 'Data Exfiltration', 'Memory Audit', 'Tool Scanner'];
const OWASP_TAGS = ['Any Tag', 'LLM01', 'LLM02', 'LLM06', 'LLM07', 'LLM09'];

const LAYER_NAMES = {
  1: 'Prompt Injection',
  2: 'RAG/Tool Scanner',
  3: 'Memory Audit',
  4: 'Drift Detection',
  5: 'Output Guard',
  6: 'Honeypot',
  7: 'Cross-Agent',
  8: 'Adaptive Engine',
  9: 'Observability',
};

function Dropdown({ label, options, value, onChange }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label
        style={{
          color: '#6b7280',
          fontSize: '11px',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          background: '#1a1a1a',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '8px',
          color: '#ffffff',
          fontSize: '13px',
          padding: '8px 32px 8px 12px',
          appearance: 'none',
          cursor: 'pointer',
          fontFamily: "'DM Sans'",
          backgroundImage: `url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23ef4444' stroke-width='2'%3e%3cpath d='M6 9l6 6 6-6'/%3e%3c/svg%3e")`,
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 8px center',
          backgroundSize: '16px',
        }}
      >
        {options.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>
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
      }}
    >
      {action}
    </span>
  );
}

function RiskBar({ score }) {
  const pct = Math.round((score || 0) * 100);
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f97316' : '#22c55e';
  return (
    <div className="flex items-center gap-2">
      <div
        className="flex-1"
        style={{
          height: '6px',
          background: '#1a1a1a',
          borderRadius: '3px',
          width: '120px',
          overflow: 'hidden',
        }}
      >
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: '3px' }} />
      </div>
      <span className="font-semibold" style={{ fontSize: '12px', color, minWidth: '32px', textAlign: 'right' }}>
        {pct}%
      </span>
    </div>
  );
}

function ExpandedRow({ event }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await fetchSessionDetail(event.session_id);
        if (!cancelled) setDetail(data);
      } catch {
        // Couldn't load detail
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [event.session_id]);

  if (loading) {
    return (
      <tr>
        <td colSpan="7">
          <div className="p-6" style={{ background: '#0d0d0d', borderLeft: '3px solid #ef4444' }}>
            <span style={{ color: '#9ca3af', fontSize: '13px' }}>Loading conversation history...</span>
          </div>
        </td>
      </tr>
    );
  }

  const conversation = detail?.conversation || [];
  const events = detail?.events || [];

  return (
    <tr>
      <td colSpan="7" style={{ padding: 0 }}>
        <div style={{ background: '#0d0d0d', borderLeft: '3px solid #ef4444' }} className="p-6">
          {/* Header */}
          <div className="flex items-center gap-2 mb-5">
            <span style={{ color: '#ef4444', fontSize: '16px' }}>📋</span>
            <h3 className="text-white font-semibold text-sm">Full Conversation History</h3>
          </div>

          {/* Turns */}
          {conversation.length > 0 ? (
            conversation.map((turn, i) => {
              const isUser = turn.role === 'user';
              const turnEvents = events.filter((e) => e.turn === i + 1);
              const highestScore = Math.max(0, ...turnEvents.map((e) => e.threat_score || 0));
              const riskLevel = highestScore >= 0.7 ? 'HIGH' : highestScore >= 0.4 ? 'MED' : 'LOW';
              const riskColor = highestScore >= 0.7 ? '#ef4444' : highestScore >= 0.4 ? '#f97316' : '#22c55e';
              const detectedKeywords = turnEvents
                .filter((e) => e.action === 'BLOCKED')
                .map((e) => e.reason)
                .join('; ');

              return (
                <div key={i} className="mb-5">
                  {/* Turn header */}
                  <div className="flex items-center gap-3 mb-2">
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0"
                      style={{
                        background: isUser ? '#3b82f6' : 'rgba(239,68,68,0.2)',
                        color: isUser ? '#fff' : '#ef4444',
                        border: isUser ? 'none' : '1px solid rgba(239,68,68,0.4)',
                      }}
                    >
                      {isUser ? 'U' : '🛡'}
                    </div>
                    <span className="font-semibold text-sm" style={{ color: isUser ? '#fff' : '#ef4444' }}>
                      {isUser ? 'User' : 'NISHUN Guard'}
                    </span>
                    <span style={{ fontFamily: "'JetBrains Mono'", fontSize: '11px', color: '#9ca3af' }}>
                      {turn.timestamp || ''}
                    </span>
                  </div>

                  {/* Message bubble */}
                  {isUser ? (
                    <div
                      className="p-4 ml-11 text-sm"
                      style={{
                        background: '#1a1a1a',
                        border: '1px solid rgba(255,255,255,0.08)',
                        borderRadius: '8px',
                        color: '#fff',
                      }}
                    >
                      {turn.content}
                    </div>
                  ) : (
                    <div
                      className="p-4 ml-11"
                      style={{
                        background: 'rgba(239,68,68,0.08)',
                        border: '1px solid rgba(239,68,68,0.3)',
                        borderRadius: '8px',
                      }}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <span style={{ color: '#ef4444', fontSize: '14px' }}>⊘</span>
                        <span className="font-semibold text-sm" style={{ color: '#ef4444' }}>
                          Response Blocked
                        </span>
                      </div>
                      <p className="text-white text-sm">{turn.content}</p>
                    </div>
                  )}

                  {/* Risk badge for user turns */}
                  {isUser && turnEvents.length > 0 && (
                    <div className="flex items-center gap-2 ml-11 mt-2">
                      <span
                        className="px-2 py-0.5 text-xs font-semibold uppercase"
                        style={{
                          background: riskColor + '22',
                          color: riskColor,
                          borderRadius: '4px',
                        }}
                      >
                        RISK: {riskLevel}
                      </span>
                      {detectedKeywords && (
                        <span style={{ color: '#9ca3af', fontSize: '12px' }}>
                          Detected Keywords: "{detectedKeywords.slice(0, 80)}"
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <p style={{ color: '#6b7280', fontSize: '13px' }}>No conversation turns found for this session.</p>
          )}

          {/* Bottom action bar */}
          <div className="flex items-center justify-end gap-3 mt-4 pt-4" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
            <button
              style={{
                background: 'none',
                border: 'none',
                color: '#9ca3af',
                fontSize: '13px',
                cursor: 'pointer',
              }}
            >
              View Raw JSON
            </button>
            <button
              style={{
                background: '#ef4444',
                border: 'none',
                borderRadius: '6px',
                color: '#fff',
                fontSize: '13px',
                padding: '6px 16px',
                cursor: 'pointer',
              }}
            >
              Add to Blacklist
            </button>
          </div>
        </div>
      </td>
    </tr>
  );
}

export default function ThreatLog() {
  const [filterAction, setFilterAction] = useState('All Actions');
  const [filterLayer, setFilterLayer] = useState('All Layers');
  const [filterOwasp, setFilterOwasp] = useState('Any Tag');
  const [page, setPage] = useState(1);
  const [data, setData] = useState({ events: [], total: 0, page: 1, page_size: 20 });
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchThreatLog({
        action: filterAction,
        layer: filterLayer,
        owasp_tag: filterOwasp,
        page,
        page_size: 20,
      });
      setData(result);
    } catch {
      // Keep previous data on error
    } finally {
      setLoading(false);
    }
  }, [filterAction, filterLayer, filterOwasp, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleApply = () => {
    setPage(1);
    loadData();
  };

  const handleClear = () => {
    setFilterAction('All Actions');
    setFilterLayer('All Layers');
    setFilterOwasp('Any Tag');
    setPage(1);
  };

  const events = data.events || [];
  const totalPages = Math.max(1, Math.ceil((data.total || 0) / 20));

  const formatTimestamp = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) +
      ', ' +
      d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  };

  const exportCSV = () => {
    if (events.length === 0) return;
    const headers = ['Timestamp', 'Session ID', 'Layer', 'Action', 'Reason', 'OWASP Tag', 'Risk Score'];
    const rows = events.map((e) => [
      formatTimestamp(e.timestamp),
      e.session_id || '',
      LAYER_NAMES[e.layer] || e.layer,
      e.action || '',
      (e.reason || '').replace(/,/g, ';'),
      e.owasp_tag || '',
      Math.round((e.threat_score || 0) * 100) + '%',
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_log_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-white font-bold text-2xl">Threat Log Archive</h1>
          <p style={{ color: '#9ca3af', fontSize: '14px', marginTop: '4px' }}>
            Audit and analyze AI interactions flagged by security protocols.
          </p>
        </div>
        <button
          onClick={exportCSV}
          className="flex items-center gap-2 px-4 py-2 text-sm"
          style={{
            background: '#1a1a1a',
            border: '1px solid rgba(255,255,255,0.12)',
            borderRadius: '8px',
            color: '#fff',
            cursor: 'pointer',
          }}
        >
          ⬇ Export CSV
        </button>
      </div>

      {/* Filter bar */}
      <div
        className="flex items-end gap-4 p-4 mb-6"
        style={{
          background: '#111111',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '8px',
        }}
      >
        <Dropdown label="ACTION TAKEN" options={ACTIONS} value={filterAction} onChange={setFilterAction} />
        <Dropdown label="SECURITY LAYER" options={LAYERS} value={filterLayer} onChange={setFilterLayer} />
        <Dropdown label="OWASP TAG" options={OWASP_TAGS} value={filterOwasp} onChange={setFilterOwasp} />
        <button
          onClick={handleApply}
          className="px-6 py-2 text-sm font-medium"
          style={{
            background: '#ef4444',
            border: 'none',
            borderRadius: '8px',
            color: '#fff',
            cursor: 'pointer',
            height: '38px',
          }}
        >
          Apply
        </button>
        <button
          onClick={handleClear}
          className="px-4 py-2 text-sm"
          style={{
            background: 'none',
            border: 'none',
            color: '#9ca3af',
            cursor: 'pointer',
            height: '38px',
          }}
        >
          Clear
        </button>
      </div>

      {/* Table */}
      <div
        style={{
          background: '#111111',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: '8px',
          overflow: 'hidden',
        }}
      >
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: '#0f0f0f' }}>
              {['TIMESTAMP', 'SESSION ID', 'LAYER', 'ACTION', 'REASON', 'OWASP TAG', 'RISK SCORE'].map((h) => (
                <th
                  key={h}
                  style={{
                    textAlign: 'left',
                    padding: '12px 16px',
                    fontSize: '11px',
                    letterSpacing: '0.08em',
                    color: '#6b7280',
                    textTransform: 'uppercase',
                    fontWeight: 500,
                    borderBottom: '1px solid rgba(255,255,255,0.05)',
                  }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center py-12" style={{ color: '#6b7280', fontSize: '13px' }}>
                  {loading ? 'Loading...' : 'No threat events found.'}
                </td>
              </tr>
            ) : (
              events.map((event, i) => {
                const isExpanded = expandedId === i;
                return (
                  <React.Fragment key={i}>
                    <tr
                      onClick={() => setExpandedId(isExpanded ? null : i)}
                      style={{
                        height: '56px',
                        borderBottom: '1px solid rgba(255,255,255,0.05)',
                        cursor: 'pointer',
                        background: isExpanded ? 'rgba(255,255,255,0.02)' : 'transparent',
                      }}
                      onMouseEnter={(e) => {
                        if (!isExpanded) e.currentTarget.style.background = 'rgba(255,255,255,0.03)';
                      }}
                      onMouseLeave={(e) => {
                        if (!isExpanded) e.currentTarget.style.background = 'transparent';
                      }}
                    >
                      <td style={{ padding: '0 16px', fontFamily: "'JetBrains Mono'", fontSize: '13px', color: '#9ca3af' }}>
                        <span style={{ color: '#6b7280', marginRight: '8px' }}>{isExpanded ? '∧' : '∨'}</span>
                        {formatTimestamp(event.timestamp)}
                      </td>
                      <td style={{ padding: '0 16px', fontFamily: "'JetBrains Mono'", fontSize: '13px', color: '#9ca3af' }}>
                        {(event.session_id || '').slice(0, 10)}...
                      </td>
                      <td style={{ padding: '0 16px', fontSize: '13px', color: '#fff' }}>
                        {LAYER_NAMES[event.layer] || `Layer ${event.layer}`}
                      </td>
                      <td style={{ padding: '0 16px' }}>
                        <ActionBadge action={event.action || 'PASSED'} />
                      </td>
                      <td
                        style={{
                          padding: '0 16px',
                          fontSize: '13px',
                          color: '#9ca3af',
                          maxWidth: '200px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {event.reason || ''}
                      </td>
                      <td style={{ padding: '0 16px' }}>
                        {event.owasp_tag && event.owasp_tag !== 'NONE' ? (
                          <span
                            className="px-2 py-0.5"
                            style={{
                              background: '#1f2937',
                              borderRadius: '4px',
                              fontFamily: "'JetBrains Mono'",
                              fontSize: '11px',
                              color: '#9ca3af',
                            }}
                          >
                            {event.owasp_tag}
                          </span>
                        ) : (
                          <span style={{ color: '#6b7280' }}>-</span>
                        )}
                      </td>
                      <td style={{ padding: '0 16px' }}>
                        <RiskBar score={event.threat_score} />
                      </td>
                    </tr>
                    {isExpanded && <ExpandedRow event={event} />}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-4 mt-6">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 text-sm"
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: '6px',
              color: page === 1 ? '#6b7280' : '#fff',
              cursor: page === 1 ? 'not-allowed' : 'pointer',
            }}
          >
            Previous
          </button>
          <span style={{ color: '#9ca3af', fontSize: '13px' }}>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-4 py-2 text-sm"
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: '6px',
              color: page === totalPages ? '#6b7280' : '#fff',
              cursor: page === totalPages ? 'not-allowed' : 'pointer',
            }}
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
