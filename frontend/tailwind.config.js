/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        slate: {
          50: '#ffffff',
          100: '#F0EDE5', // Sand Dune (Primary Text)
          200: '#e4dfd1', 
          300: '#c8c1ae',
          400: '#a79d85', // Muted Text
          500: '#006c64',
          600: '#005852',
          700: '#004643', // Cyprus (Borders/Accents)
          800: '#003331', // Cyprus (Cards)
          900: '#002221', // Cyprus (Dark Cards)
          950: '#001a19', // Cyprus (Deep Background)
        },
        blue: {
          400: '#ffffff',
          500: '#ffffff', 
          600: '#F0EDE5', // Sand Dune (Buttons)
          700: '#e4dfd1', 
        },
        critical: "#dc2626",
        high: "#ea580c",
        medium: "#ca8a04",
        low: "#16a34a"
      }
    }
  },
  plugins: []
};
