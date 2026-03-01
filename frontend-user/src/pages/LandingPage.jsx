import React from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldIcon,
  StackIcon,
  LanguageIcon,
  ChipIcon,
  TwitterIcon,
  GithubIcon,
} from '../components/Icons';

function Navbar() {
  return (
    <nav
      className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4"
      style={{
        background: '#0a0a0a',
        borderBottom: '1px solid rgba(255,255,255,0.08)',
      }}
    >
      <div className="flex items-center gap-2">
        <ShieldIcon size={20} />
        <span
          className="text-white font-semibold tracking-wider"
          style={{ fontFamily: "'DM Sans', sans-serif", letterSpacing: '0.05em' }}
        >
          NISHUN
        </span>
      </div>
      <div className="flex items-center gap-8">
        <div className="hidden md:flex items-center gap-6">
          {['Platform', 'Solutions', 'Documentation'].map((item) => (
            <a
              key={item}
              href="#"
              className="text-sm transition-colors"
              style={{ color: '#9ca3af' }}
              onMouseEnter={(e) => (e.target.style.color = '#fff')}
              onMouseLeave={(e) => (e.target.style.color = '#9ca3af')}
            >
              {item}
            </a>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <button
            className="px-5 py-2 text-sm font-medium text-white rounded-md border transition-colors"
            style={{
              borderColor: 'rgba(255,255,255,0.3)',
              background: 'transparent',
              borderRadius: '6px',
            }}
          >
            Sign In
          </button>
          <Link
            to="/chat"
            className="px-5 py-2 text-sm font-medium text-white rounded-md transition-colors no-underline"
            style={{ background: '#ef4444', borderRadius: '6px' }}
            onMouseEnter={(e) => (e.target.style.background = '#dc2626')}
            onMouseLeave={(e) => (e.target.style.background = '#ef4444')}
          >
            Try Demo
          </Link>
        </div>
      </div>
    </nav>
  );
}

function TerminalBlock() {
  return (
    <div
      className="w-full max-w-2xl mx-auto mt-12"
      style={{
        background: '#111111',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: '6px',
        overflow: 'hidden',
      }}
    >
      {/* Window chrome */}
      <div className="flex items-center gap-2 px-4 py-3" style={{ background: '#0d0d0d' }}>
        <div className="w-3 h-3 rounded-full" style={{ background: '#ef4444' }} />
        <div className="w-3 h-3 rounded-full" style={{ background: '#eab308' }} />
        <div className="w-3 h-3 rounded-full" style={{ background: '#22c55e' }} />
        <span className="ml-auto text-xs" style={{ fontFamily: "'JetBrains Mono'", color: '#6b7280' }}>
          nishun-core v2.4.8 — root@nishun-srv-01
        </span>
      </div>
      {/* Terminal content */}
      <div className="p-5" style={{ fontFamily: "'JetBrains Mono'", fontSize: '13px', lineHeight: '1.8' }}>
        <div style={{ color: '#ef4444' }}>→ Initializing NISHUN Enterprise Security Core...</div>
        <div className="flex items-center gap-2">
          <span style={{ color: '#22c55e' }}>✓</span>
          <span style={{ color: '#22c55e' }}>Memory Integrity Guard:</span>
          <span className="font-semibold" style={{ color: '#22c55e' }}>Active</span>
        </div>
        <div className="flex items-center gap-2">
          <span style={{ color: '#22c55e' }}>✓</span>
          <span style={{ color: '#22c55e' }}>Indic Language Model:</span>
          <span className="font-semibold" style={{ color: '#22c55e' }}>
            Loaded (<span style={{ color: '#f97316' }}>Hindi, Tamil, Telugu, Bengali</span>)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span style={{ color: '#22c55e' }}>✓</span>
          <span style={{ color: '#22c55e' }}>Deep Packet Inspection:</span>
          <span className="font-semibold" style={{ color: '#22c55e' }}>Enabled</span>
        </div>
        <div className="mt-3" style={{ color: '#eab308' }}>
          ! WARNING: Anomalous vector embedding detected in agent memory.
        </div>
        <div className="pl-6" style={{ color: '#9ca3af' }}>
          Source: External API Call
        </div>
        <div className="pl-6" style={{ color: '#9ca3af' }}>
          Signature: PROMPT_INJECTION_TYPE_3
        </div>
        <div className="pl-6" style={{ color: '#9ca3af' }}>
          Action: <span className="font-semibold" style={{ color: '#ef4444' }}>BLOCKED</span> &amp; IP Flagged
        </div>
        <div className="mt-2" style={{ color: '#ef4444' }}>
          → <span className="cursor-blink">_</span>
        </div>
      </div>
    </div>
  );
}

const features = [
  {
    icon: <StackIcon size={24} />,
    title: '9 Security Layers',
    description:
      'A robust multi-layered defense system protecting against prompt injection, jailbreaking, PII leakage, and data exfiltration at every stage of the pipeline.',
  },
  {
    icon: <LanguageIcon size={24} />,
    title: 'Indic Language Detection',
    description:
      'Native, transformer-based support for detecting malicious inputs in major Indic languages, ensuring localized security for global deployments across diverse regions.',
  },
  {
    icon: <ChipIcon size={24} />,
    title: 'Memory Integrity Guard',
    description:
      'Real-time monitoring of vector databases and agent memory states to prevent unauthorized access, memory pollution, and long-term corruption of agent behavior.',
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen" style={{ background: '#0a0a0a' }}>
      <Navbar />

      {/* Hero Section */}
      <section
        className="flex flex-col items-center justify-center text-center px-4 pt-32 pb-24"
        style={{
          minHeight: '100vh',
          background: 'radial-gradient(ellipse at top center, rgba(239,68,68,0.08) 0%, #0a0a0a 60%)',
        }}
      >
        {/* Pill badge */}
        <div
          className="inline-flex items-center gap-2 px-4 py-1.5 mb-8"
          style={{
            background: 'rgba(239,68,68,0.15)',
            border: '1px solid rgba(239,68,68,0.4)',
            borderRadius: '100px',
          }}
        >
          <div className="w-2 h-2 rounded-full" style={{ background: '#ef4444' }} />
          <span style={{ fontSize: '11px', letterSpacing: '0.1em', color: '#ef4444', textTransform: 'uppercase' }}>
            Enterprise Security
          </span>
        </div>

        {/* Headline */}
        <h1
          className="font-bold"
          style={{
            fontFamily: "'DM Sans', sans-serif",
            fontSize: 'clamp(36px, 5vw, 72px)',
            lineHeight: 1.1,
            color: '#ffffff',
          }}
        >
          The Security Layer Built
          <br />
          for the{' '}
          <span style={{ color: '#ef4444' }}>Agentic AI Era</span>
        </h1>

        {/* Subtext */}
        <p
          className="mt-6 max-w-xl mx-auto"
          style={{ fontSize: '16px', color: '#9ca3af', lineHeight: 1.7 }}
        >
          Protect your LLMs and agentic workflows with NISHUN. The first enterprise-grade security
          platform designed to safeguard memory integrity and detect threats in real-time.
        </p>

        {/* CTA Buttons */}
        <div className="flex items-center gap-4 mt-8">
          <Link
            to="/chat"
            className="flex items-center gap-2 px-6 text-white font-medium text-sm no-underline transition-colors"
            style={{ background: '#ef4444', height: '48px', borderRadius: '6px' }}
            onMouseEnter={(e) => (e.target.style.background = '#dc2626')}
            onMouseLeave={(e) => (e.target.style.background = '#ef4444')}
          >
            Try the Demo →
          </Link>
          <a
            href="#"
            className="flex items-center px-6 text-white font-medium text-sm no-underline transition-colors"
            style={{
              height: '48px',
              borderRadius: '6px',
              border: '1px solid rgba(255,255,255,0.3)',
              background: 'transparent',
            }}
          >
            Read the Whitepaper
          </a>
        </div>

        <TerminalBlock />
      </section>

      {/* Features Section */}
      <section className="px-8 py-24 max-w-6xl mx-auto text-center">
        <h2 className="font-bold text-3xl md:text-4xl" style={{ fontFamily: "'DM Sans'" }}>
          Enterprise-Grade Protection for
          <br />
          <span style={{ color: '#ef4444' }}>Mission Critical AI</span>
        </h2>
        <p className="mt-4 max-w-xl mx-auto" style={{ color: '#9ca3af', fontSize: '16px' }}>
          Comprehensive security infrastructure designed for the complexities of modern agentic AI
          systems and LLM deployments.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12">
          {features.map((f) => (
            <div
              key={f.title}
              className="text-left p-6"
              style={{
                background: '#111111',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: '8px',
              }}
            >
              <div
                className="inline-flex items-center justify-center w-10 h-10 mb-4"
                style={{ background: 'rgba(239,68,68,0.15)', borderRadius: '8px' }}
              >
                {f.icon}
              </div>
              <h3 className="font-semibold text-white mb-2" style={{ fontSize: '16px' }}>
                {f.title}
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '14px', lineHeight: 1.6 }}>{f.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA Section */}
      <section className="px-8 py-24 text-center">
        <h2 className="font-bold text-3xl md:text-4xl text-white" style={{ fontFamily: "'DM Sans'" }}>
          Secure your AI
          <br />
          Infrastructure
        </h2>
        <p className="mt-4 max-w-lg mx-auto" style={{ color: '#9ca3af', fontSize: '16px' }}>
          Join the leading enterprises building safe, reliable, and compliant agentic AI systems
          today.
        </p>
        <div className="mt-8">
          <Link
            to="/chat"
            className="inline-flex items-center px-8 text-white font-medium text-sm no-underline transition-colors"
            style={{ background: '#ef4444', height: '48px', borderRadius: '100px' }}
            onMouseEnter={(e) => (e.target.style.background = '#dc2626')}
            onMouseLeave={(e) => (e.target.style.background = '#ef4444')}
          >
            Get Started Now
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer
        className="flex items-center justify-between px-8 py-6"
        style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}
      >
        <div className="flex items-center gap-2">
          <ShieldIcon size={16} />
          <span className="text-white font-semibold text-sm tracking-wide">NISHUN</span>
        </div>
        <span style={{ color: '#6b7280', fontSize: '12px' }}>Built for AMD Slingshot 2026</span>
        <div className="flex items-center gap-4">
          <a href="#" style={{ color: '#9ca3af' }} onMouseEnter={(e) => (e.target.style.color = '#fff')} onMouseLeave={(e) => (e.target.style.color = '#9ca3af')}>
            <TwitterIcon size={18} />
          </a>
          <a href="#" style={{ color: '#9ca3af' }} onMouseEnter={(e) => (e.target.style.color = '#fff')} onMouseLeave={(e) => (e.target.style.color = '#9ca3af')}>
            <GithubIcon size={18} />
          </a>
        </div>
      </footer>
    </div>
  );
}
