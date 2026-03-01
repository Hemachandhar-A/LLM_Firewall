/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0a0a0a',
        'bg-surface': '#111111',
        'bg-surface-2': '#1a1a1a',
        'bg-surface-3': '#222222',
        'accent-red': '#ef4444',
        'accent-red-hover': '#dc2626',
        'accent-red-muted': 'rgba(239,68,68,0.15)',
        'text-primary': '#ffffff',
        'text-secondary': '#9ca3af',
        'text-tertiary': '#6b7280',
        'border-subtle': 'rgba(255,255,255,0.08)',
        'border-red': 'rgba(239,68,68,0.5)',
      },
      fontFamily: {
        sans: ["'DM Sans'", 'sans-serif'],
        mono: ["'JetBrains Mono'", 'monospace'],
      },
      borderRadius: {
        DEFAULT: '8px',
      },
    },
  },
  plugins: [],
}
