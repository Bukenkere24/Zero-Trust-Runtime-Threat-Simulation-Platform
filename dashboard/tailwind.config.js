/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        attack: { DEFAULT: '#ef4444', light: '#fef2f2' },
        defense: { DEFAULT: '#3b82f6', light: '#eff6ff' },
      },
    },
  },
  plugins: [],
}
