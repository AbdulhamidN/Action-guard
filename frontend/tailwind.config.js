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
          950: '#0B1327',
          900: '#101C38', // Refined deep navy main background
          850: '#122345',
          800: '#15294D', // Refined secondary navy surface
          750: '#19335E',
          700: '#1B3B6B',
          600: '#234C87',
          500: '#2B5FA3'
        },
        brand: {
          deep: '#101C38',
          navy: '#15294D',
          surface: '#18325B',
          blue: '#174A91',      // Deep gradient blue
          luminous: '#258DEB',  // Luminous sapphire blue
          cyan: '#35C5E8',      // Vibrant cyan highlight
          glow: 'rgba(37, 141, 235, 0.25)'
        },
        neon: {
          cyan: '#35C5E8',      // Updated to refined vibrant cyan
          indigo: '#258DEB'     // Updated to luminous sapphire blue
        },
        state: {
          ok: '#10B981',
          warn: '#F59E0B',
          caution: '#F97316',
          alert: '#EF4444'
        },
        ink: {
          50: '#FFFFFF',
          100: '#F8FAFC',
          200: '#E2E8F0',
          300: '#94A3B8',
          400: '#64748B',
          500: '#475569'
        }
      },
      keyframes: {
        'ag-pulse': { '0%': { transform: 'scale(0.6)', opacity: '0.7' }, '100%': { transform: 'scale(1.7)', opacity: '0' } },
        'ag-float': { '0%, 100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-10px)' } },
        'ag-float-reverse': { '0%, 100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(10px)' } },
        'ag-rise': { from: { opacity: '0', transform: 'translateY(18px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
        'ag-flow': { from: { strokeDashoffset: '24' }, to: { strokeDashoffset: '0' } },
        'ag-glow': { '0%, 100%': { opacity: '0.4', transform: 'scale(1)' }, '50%': { opacity: '0.8', transform: 'scale(1.08)' } },
        'ag-spin-slow': { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } },
        'ag-scan': { '0%': { transform: 'translateY(-100%)' }, '100%': { transform: 'translateY(100%)' } },
        'ag-blink': { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0.25' } },
        'ag-shimmer': { from: { backgroundPosition: '-200% 0' }, to: { backgroundPosition: '200% 0' } },
        'ag-aurora': {
          '0%, 100%': { transform: 'translate(0, 0) scale(1)' },
          '33%': { transform: 'translate(30px, -20px) scale(1.12)' },
          '66%': { transform: 'translate(-25px, 25px) scale(0.94)' }
        },
        'ag-wave': {
          '0%': { transform: 'translateX(0)' },
          '50%': { transform: 'translateX(-25%)' },
          '100%': { transform: 'translateX(0)' }
        }
      },
      animation: {
        'ag-pulse': 'ag-pulse 3.6s ease-out infinite',
        'ag-float': 'ag-float 6s ease-in-out infinite',
        'ag-float-reverse': 'ag-float-reverse 7s ease-in-out infinite',
        'ag-rise': 'ag-rise 0.8s ease-out both',
        'ag-flow': 'ag-flow 1.2s linear infinite',
        'ag-glow': 'ag-glow 6s ease-in-out infinite',
        'ag-spin-slow': 'ag-spin-slow 20s linear infinite',
        'ag-scan': 'ag-scan 4s linear infinite',
        'ag-blink': 'ag-blink 1.4s ease-in-out infinite',
        'ag-shimmer': 'ag-shimmer 2.5s linear infinite',
        'ag-aurora': 'ag-aurora 14s ease-in-out infinite',
        'ag-wave': 'ag-wave 12s ease-in-out infinite'
      }
    }
  },
  plugins: []
};