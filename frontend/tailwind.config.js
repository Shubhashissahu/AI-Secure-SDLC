/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        slate: {
          50: '#fafafa',  // Crisp White
          100: '#f4f4f5',
          200: '#e4e4e7', 
          300: '#d4d4d8',
          400: '#a1a1aa', // Ash Grey
          500: '#71717a',
          600: '#52525b',
          700: '#3f3f46', 
          800: '#27272a', 
          900: '#18181b', // Jet Black
          950: '#09090b', // Deep Obsidian
        },
        blue: {
          400: '#22d3ee',
          500: '#06b6d4', 
          600: '#0891b2', // Electric Cyan
          700: '#0e7490', 
        },
        critical: "#dc2626",
        high: "#ea580c",
        medium: "#ca8a04",
        low: "#16a34a"
      },
      animation: {
        'float': 'float 6s ease-in-out infinite',
        'glow-pulse': 'glow 3s ease-in-out infinite alternate',
        'slide-up': 'slideUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 15px rgba(6, 182, 212, 0.1)' },
          '100%': { boxShadow: '0 0 30px rgba(6, 182, 212, 0.4)' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        }
      }
    }
  },
  plugins: []
};
