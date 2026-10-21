/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        space: {
          900: '#0B0F19',
          800: '#0F1424',
          700: '#161C2E',
          600: '#1E2638',
          500: '#2A3346'
        },
        neon: {
          cyan: '#06B6D4',
          indigo: '#6366F1'
        },
        state: {
          ok: '#10B981',
          warn: '#F59E0B',
          caution: '#F97316',
          alert: '#EF4444'
        },
        ink: {
          100: '#E5E7EB',
          300: '#9CA3AF',
          500: '#6B7280'
        }
      },
      keyframes: {
        'ag-pulse': { '0%': { transform: 'scale(0.6)', opacity: '0.7' }, '100%': { transform: 'scale(1.7)', opacity: '0' } },
        'ag-float': { '0%, 100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-8px)' } },
        'ag-rise': { from: { opacity: '0', transform: 'translateY(18px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        'ag-flow': { from: { strokeDashoffset: '24' }, to: { strokeDashoffset: '0' } },
        'ag-glow': { '0%, 100%': { opacity: '0.35' }, '50%': { opacity: '0.7' } },
        'ag-spin-slow': { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } },
        'ag-scan': { '0%': { transform: 'translateY(-100%)' }, '100%': { transform: 'translateY(100%)' } },
        'ag-blink': { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0.25' } },
        'ag-shimmer': { from: { backgroundPosition: '-200% 0' }, to: { backgroundPosition: '200% 0' } }
      },
      animation: {
        'ag-pulse': 'ag-pulse 3.6s ease-out infinite',
        'ag-float': 'ag-float 5s ease-in-out infinite',
        'ag-rise': 'ag-rise 0.8s ease-out both',
        'ag-flow': 'ag-flow 1.2s linear infinite',
        'ag-glow': 'ag-glow 6s ease-in-out infinite',
        'ag-spin-slow': 'ag-spin-slow 20s linear infinite',
        'ag-scan': 'ag-scan 4s linear infinite',
        'ag-blink': 'ag-blink 1.4s ease-in-out infinite',
        'ag-shimmer': 'ag-shimmer 2.5s linear infinite'
      }
    }
  },
  plugins: []
};
