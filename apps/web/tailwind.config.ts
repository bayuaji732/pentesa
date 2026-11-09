import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "#090d16",
        surface: {
          base: "#0f172a",
          elevated: "#1e293b",
          overlay: "#334155",
        },
        border: {
          subtle: "#1e293b",
          default: "#334155",
          focused: "#64748b",
        },
        sev: {
          critical: "#ef4444",
          "critical-bg": "#450a0a",
          high: "#f97316",
          "high-bg": "#431407",
          medium: "#f59e0b",
          "medium-bg": "#451a03",
          low: "#3b82f6",
          "low-bg": "#172554",
          info: "#64748b",
          "info-bg": "#0f172a",
        },
        state: {
          passed: "#10b981",
          failed: "#ef4444",
          running: "#06b6d4",
          review: "#a855f7",
          blocked: "#f43f5e",
          na: "#475569",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
        mono: ["JetBrains Mono", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;

