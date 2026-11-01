/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          primary: '#5125A5',
          deep: '#24104D',
          deeper: '#180B33',
          yellow: '#FFE52E',
          yellowHover: '#F5DC20',
          lavender: '#A98BEF',
          lavenderLight: '#CBB7F7',
          lavenderDark: '#7042C9',
          cream: '#FFF7E8',
          creamLight: '#FFFBF3',
          creamCard: '#FAF3E3',
          darkText: '#211747',
          secRed: '#EF4444',
          secGreen: '#22C55E',
        }
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'glow-purple': '0 0 50px -10px rgba(169, 139, 239, 0.35)',
        'glow-yellow': '0 0 35px -5px rgba(255, 229, 46, 0.45)',
        'glass': '0 8px 32px 0 rgba(31, 14, 66, 0.37)',
        'card': '0 10px 30px -5px rgba(33, 23, 71, 0.08)',
      },
      backdropBlur: {
        xs: '2px',
      }
    },
  },
  plugins: [],
}
