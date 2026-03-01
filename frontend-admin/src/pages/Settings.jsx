import React, { useState, useEffect } from 'react';
import { fetchStats } from '../api';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

function Section({ title, children }) {
  return (
    <div
      className="p-6 mb-6"
      style={{
        background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '8px',
      }}
    >
      <h2 className="text-white font-semibold text-base mb-5">{title}</h2>
      {children}
    </div>
  );
}

function ThresholdSlider({ label, value }) {
  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-white text-sm">{label}</span>
        <span style={{ fontFamily: "'JetBrains Mono'", fontSize: '13px', color: '#ef4444' }}>
          {value}
        </span>
      </div>
      <div style={{ position: 'relative', height: '6px', background: '#1a1a1a', borderRadius: '3px' }}>
        <div
          style={{
            width: `${value * 100}%`,
            height: '100%',
            background: '#ef4444',
            borderRadius: '3px',
          }}
        />
        <div
          style={{
            position: 'absolute',
            top: '-5px',
            left: `${value * 100}%`,
            width: '16px',
            height: '16px',
            borderRadius: '50%',
            background: '#ef4444',
            border: '2px solid #0a0a0a',
            transform: 'translateX(-50%)',
          }}
        />
      </div>
    </div>
  );
}

function Toggle({ label, enabled, disabled: isDisabled }) {
  return (
    <div className="flex items-center justify-between py-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
      <span className="text-white text-sm">{label}</span>
      <div className="flex items-center gap-2">
        {isDisabled && (
          <span style={{ color: '#6b7280', fontSize: '11px' }}>Coming Soon</span>
        )}
        <div
          style={{
            width: '40px',
            height: '22px',
            borderRadius: '11px',
            background: enabled ? '#ef4444' : '#374151',
            position: 'relative',
            opacity: isDisabled ? 0.4 : 1,
            cursor: isDisabled ? 'not-allowed' : 'default',
          }}
        >
          <div
            style={{
              width: '18px',
              height: '18px',
              borderRadius: '50%',
              background: '#fff',
              position: 'absolute',
              top: '2px',
              left: enabled ? '20px' : '2px',
              transition: 'left 0.2s',
            }}
          />
        </div>
      </div>
    </div>
  );
}

export default function Settings({ wsConnected }) {
  const [lastEvent, setLastEvent] = useState('Never');

  useEffect(() => {
    (async () => {
      try {
        await fetchStats();
        setLastEvent(new Date().toISOString());
      } catch {
        setLastEvent('Unable to reach backend');
      }
    })();
  }, []);

  return (
    <div className="p-8 max-w-3xl">
      <h1 className="text-white font-bold text-2xl mb-1">Settings</h1>
      <p style={{ color: '#9ca3af', fontSize: '14px', marginBottom: '24px' }}>
        System configuration and security policy management.
      </p>

      <Section title="Role Policy Thresholds">
        <p style={{ color: '#6b7280', fontSize: '12px', marginBottom: '16px' }}>
          Configured in backend — read-only view.
        </p>
        <ThresholdSlider label="Guest" value={0.5} />
        <ThresholdSlider label="User" value={0.65} />
        <ThresholdSlider label="Admin" value={0.85} />
      </Section>

      <Section title="Layer Toggles">
        <Toggle label="Layer 1 — Indic Threat Classifier" enabled={true} />
        <Toggle label="Layer 2 — RAG / Tool Scanner" enabled={true} />
        <Toggle label="Layer 3 — Memory Integrity Auditor" enabled={true} />
        <Toggle label="Layer 4 — Semantic Drift Engine" enabled={true} />
        <Toggle label="Layer 5 — Output Guard (PII / Leakage)" enabled={true} />
        <Toggle label="Layer 6 — Adversarial Honeypot Tarpit" enabled={true} />
        <Toggle label="Layer 7 — Cross-Agent Zero-Trust" enabled={true} />
        <Toggle label="Layer 8 — Adaptive Rule Engine" enabled={true} />
        <Toggle label="Layer 9 — Observability Dashboard" enabled={true} />
      </Section>

      <Section title="Threat Intel Feed">
        <Toggle label="Shared Threat Intelligence Feed" enabled={false} disabled={true} />
      </Section>

      <Section title="System Info">
        <div className="flex flex-col gap-3">
          {[
            { label: 'Backend URL', value: BACKEND_URL },
            { label: 'WebSocket URL', value: WS_URL + '/ws/admin' },
            { label: 'WebSocket Status', value: wsConnected ? 'Connected' : 'Disconnected' },
            { label: 'Last Event Timestamp', value: lastEvent },
          ].map((item) => (
            <div key={item.label} className="flex items-center justify-between py-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
              <span style={{ color: '#9ca3af', fontSize: '13px' }}>{item.label}</span>
              <span style={{ fontFamily: "'JetBrains Mono'", fontSize: '12px', color: '#fff' }}>
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}
