/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/**/*.{js,jsx}', './public/index.html'],
  safelist: [
    'bg-blue-500', 'bg-purple-500', 'bg-red-500', 'bg-amber-500',
    'bg-green-500', 'bg-orange-500', 'bg-gray-500',
  ],
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
