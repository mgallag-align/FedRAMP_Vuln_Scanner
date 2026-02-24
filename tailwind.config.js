/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/**/*.{js,jsx}', './public/index.html'],
  theme: {
    extend: {
      colors: {
        fedramp: {
          blue: '#003366',
          red: '#C8102E',
          gray: '#6B7280',
          light: '#F3F4F6',
        },
      },
    },
  },
  plugins: [],
};
