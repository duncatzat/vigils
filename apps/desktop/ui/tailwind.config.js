/** @type {import('tailwindcss').Config} */
export default {
  // Tailwind 与 Naive UI 共存:Tailwind 作 utility 层,Naive UI 管组件内部样式。
  // **不启** Tailwind preflight 的强制 base reset,避免覆盖 Naive UI 默认样式。
  content: ["./index.html", "./src/**/*.{vue,ts,tsx}"],
  // 禁 base preflight,留给 Naive UI 的 `n-global-style`
  corePlugins: {
    preflight: false,
  },
  theme: {
    extend: {
      // Vigils Desktop 原型图设计系统(深色安全控制台)
      colors: {
        vigils: {
          cyan: "var(--vigils-cyan)",
          "cyan-light": "var(--vigils-cyan-light)",
          green: "var(--vigils-green)",
          purple: "var(--vigils-purple)",
          red: "var(--vigils-red)",
          yellow: "var(--vigils-yellow)",
          "bg-deep": "var(--vigils-bg-deep)",
          "bg-page": "var(--vigils-bg-page)",
          "bg-panel": "var(--vigils-bg-panel)",
          "bg-tertiary": "var(--vigils-bg-tertiary)",
          "bg-surface": "var(--vigils-bg-surface)",
          "border": "var(--vigils-border)",
          "input": "var(--vigils-input)",
          "text-primary": "var(--vigils-text-primary)",
          "text-secondary": "var(--vigils-text-secondary)",
          "text-muted": "var(--vigils-text-muted)",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "PingFang SC",
          "Microsoft YaHei",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
      boxShadow: {
        "glow-cyan": "0 0 20px rgba(5,217,232,.3), 0 0 60px rgba(5,217,232,.1)",
        "glow-green": "0 0 16px rgba(0,255,157,.2)",
        "glow-red": "0 0 20px rgba(255,42,109,.3), 0 0 60px rgba(255,42,109,.1)",
        card: "0 8px 32px rgba(0,0,0,.4)",
        "card-hover": "0 12px 40px rgba(5,217,232,.08)",
        terminal: "0 24px 64px rgba(0,0,0,.5)",
      },
      animation: {
        "fade-in": "fadeIn 0.4s ease forwards",
        "fade-in-up": "fadeInUp 0.6s ease forwards",
        "pulse-glow": "pulseGlow 3s ease-in-out infinite",
        "breathe-title": "breatheTitle 4s ease-in-out infinite",
        "card-float": "cardFloat 4s ease-in-out infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        fadeInUp: {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseGlow: {
          "0%, 100%": { boxShadow: "0 0 16px rgba(5,217,232,.2)" },
          "50%": { boxShadow: "0 0 32px rgba(5,217,232,.5)" },
        },
        breatheTitle: {
          "0%, 100%": {
            textShadow:
              "0 0 40px rgba(5,217,232,.2), 0 0 80px rgba(5,217,232,.1)",
          },
          "50%": {
            textShadow:
              "0 0 60px rgba(5,217,232,.35), 0 0 120px rgba(5,217,232,.15)",
          },
        },
        cardFloat: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
      },
      letterSpacing: {
        wider: "0.05em",
      },
    },
  },
  plugins: [],
};
