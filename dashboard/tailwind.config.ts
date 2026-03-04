import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{astro,html,tsx,ts}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        tokamak: {
          bg: "#0f1117",
          card: "#1a1d2e",
          border: "#2a2d3e",
          accent: "#6366f1",
          green: "#22c55e",
          yellow: "#eab308",
          red: "#ef4444",
        },
        sentinel: {
          bg: "#101622",
          card: "#161d2a",
          surface: "#1a2234",
          border: "#232f48",
          "border-light": "#2d3a54",
          primary: "#135bec",
          critical: "#ff4d4d",
          high: "#ffa500",
          medium: "#eab308",
          low: "#135bec",
          connected: "#0bda5e",
          text: "#e5e7eb",
          "text-muted": "#9ca3af",
        },
      },
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
      },
    },
  },
  plugins: [],
};

export default config;
