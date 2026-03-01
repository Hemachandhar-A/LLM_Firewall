import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';

const NAV_ITEMS = [
  { path: '/', label: 'Live Dashboard', icon: '⊞' },
  { path: '/threat-log', label: 'Threat Log', icon: '⚠' },
  { path: '#', label: 'Policy Management', icon: '◈', disabled: true },
  { path: '#', label: 'Integrations', icon: '⚙', disabled: true },
  { path: '/settings', label: 'Settings', icon: '⚙' },
];

export default function AdminLayout({ wsConnected }) {
  return (
    <div className="flex h-screen" style={{ background: '#0a0a0a' }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col justify-between flex-shrink-0"
        style={{
          width: '240px',
          background: '#0f0f0f',
          borderRight: '1px solid rgba(255,255,255,0.08)',
        }}
      >
        {/* Logo */}
        <div>
          <div className="flex items-center gap-3 px-5 py-5">
            <div
              className="w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-sm"
              style={{
                background: 'linear-gradient(135deg, #c2410c, #ea580c)',
              }}
            >
              A
            </div>
            <div className="flex flex-col">
              <span className="text-white font-bold text-sm tracking-wide">AgentShield</span>
              <span style={{ color: '#9ca3af', fontSize: '12px' }}>AI Security Admin</span>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="mt-2 px-3 flex flex-col gap-1">
            {NAV_ITEMS.map((item) => {
              if (item.disabled) {
                return (
                  <div
                    key={item.label}
                    className="flex items-center gap-3 px-4 rounded-lg"
                    style={{
                      height: '48px',
                      color: '#6b7280',
                      fontSize: '14px',
                      cursor: 'default',
                    }}
                  >
                    <span style={{ fontSize: '16px', width: '20px', textAlign: 'center' }}>
                      {item.icon}
                    </span>
                    {item.label}
                  </div>
                );
              }
              return (
                <NavLink
                  key={item.label}
                  to={item.path}
                  end={item.path === '/'}
                  className="no-underline"
                  style={({ isActive }) => ({
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px',
                    padding: '0 16px',
                    height: '48px',
                    borderRadius: '8px',
                    fontSize: '14px',
                    color: isActive ? '#ffffff' : '#9ca3af',
                    background: isActive ? 'rgba(239,68,68,0.1)' : 'transparent',
                    borderLeft: isActive ? '3px solid #ef4444' : '3px solid transparent',
                    transition: 'all 0.15s ease',
                  })}
                >
                  <span style={{ fontSize: '16px', width: '20px', textAlign: 'center' }}>
                    {item.icon}
                  </span>
                  {item.label}
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Bottom status */}
        <div className="px-5 pb-5">
          <div style={{ color: '#9ca3af', fontSize: '11px', marginBottom: '4px' }}>
            System Status
          </div>
          <div className="flex items-center gap-2">
            <div
              className="w-2 h-2 rounded-full"
              style={{ background: wsConnected ? '#22c55e' : '#ef4444' }}
            />
            <span className="text-white text-sm">
              {wsConnected ? 'Operational' : 'Disconnected'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto" style={{ background: '#0a0a0a' }}>
        <Outlet />
      </main>
    </div>
  );
}
