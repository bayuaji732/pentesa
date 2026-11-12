import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "var(--bg-canvas)",
        surface: {
          base: "var(--bg-surface-base)",
          elevated: "var(--bg-surface-elevated)",
          overlay: "var(--bg-surface-overlay)",
        },
        border: {
          subtle: "var(--border-subtle)",
          default: "var(--border-default)",
          focused: "var(--border-focused)",
        },
        brand: {
          primary: "var(--brand-primary)",
          "primary-hover": "var(--brand-primary-hover)",
          accent: "var(--brand-accent)",
        },
        sev: {
          critical: "var(--sev-critical)",
          "critical-bg": "var(--sev-critical-bg)",
          "critical-border": "var(--sev-critical-border)",
          high: "var(--sev-high)",
          "high-bg": "var(--sev-high-bg)",
          "high-border": "var(--sev-high-border)",
          medium: "var(--sev-medium)",
          "medium-bg": "var(--sev-medium-bg)",
          "medium-border": "var(--sev-medium-border)",
          low: "var(--sev-low)",
          "low-bg": "var(--sev-low-bg)",
          "low-border": "var(--sev-low-border)",
          info: "var(--sev-info)",
          "info-bg": "var(--sev-info-bg)",
          "info-border": "var(--sev-info-border)",
        },
        state: {
          passed: "#10b981",
          failed: "#ef4444",
          running: "#0284c7",
          review: "#8b5cf6",
          blocked: "#f43f5e",
          na: "#64748b",
        },
      },
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
      boxShadow: {
        xs: "0 1px 2px 0 rgba(0, 0, 0, 0.05)",
      },
    },
  },
  plugins: [],
};

export default config;
