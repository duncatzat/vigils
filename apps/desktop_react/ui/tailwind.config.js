/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        vigils: {
          "bg-deep": "var(--vigils-bg-deep)",
          "bg-panel": "var(--vigils-bg-panel)",
          "bg-tertiary": "var(--vigils-bg-tertiary)",
          "bg-surface": "var(--vigils-bg-surface)",
          cyan: "var(--vigils-cyan)",
          green: "var(--vigils-green)",
          red: "var(--vigils-red)",
          purple: "var(--vigils-purple)",
          yellow: "var(--vigils-yellow)",
          "text-primary": "var(--vigils-text-primary)",
          "text-secondary": "var(--vigils-text-secondary)",
          "text-muted": "var(--vigils-text-muted)",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Courier New"', "monospace"],
      },
      animation: {
        "fade-in-up": "fadeInUp 0.5s ease-out",
        "pulse-glow": "pulseGlow 1.5s ease-in-out infinite",
      },
      keyframes: {
        fadeInUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseGlow: {
          "0%, 100%": { boxShadow: "0 0 12px rgba(5,217,232,0.15)" },
          "50%": { boxShadow: "0 0 24px rgba(5,217,232,0.3)" },
        },
      },
    },
  },
  plugins: [],
};
