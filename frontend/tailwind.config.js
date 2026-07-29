/** Tailwind config — tokens derive from frontend/design-system/MASTER.md
 * (Svetovid = Dark Data-Dense Dashboard, JetBrains Mono, dark navy + green
 * accent + amber/red status). Every color is a CSS variable defined in
 * src/styles/tokens.css; Tailwind just maps semantic names to those vars so
 * theme changes happen in one place. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Semantic surface colors backed by CSS vars (see tokens.css)
        background: "var(--color-background)",
        foreground: "var(--color-foreground)",
        muted: { DEFAULT: "var(--color-muted)", foreground: "var(--color-muted-fg)" },
        surface: { DEFAULT: "var(--color-surface)", foreground: "var(--color-surface-fg)" },
        border: "var(--color-border)",
        primary: { DEFAULT: "var(--color-primary)", foreground: "var(--color-on-primary)" },
        secondary: { DEFAULT: "var(--color-secondary)", foreground: "var(--color-on-secondary)" },
        accent: { DEFAULT: "var(--color-accent)", foreground: "var(--color-on-accent)" },
        destructive: { DEFAULT: "var(--color-destructive)", foreground: "var(--color-on-destructive)" },
        // Status semantics for tool calls / nodes
        status: {
          pending: "var(--color-status-pending)",
          running: "var(--color-status-running)",
          done: "var(--color-status-done)",
          failed: "var(--color-status-failed)",
          skipped: "var(--color-status-skipped)",
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        // Type scale per MASTER.md, monospace-tuned
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
        xs: ["0.75rem", { lineHeight: "1.125rem" }],
        sm: ["0.8125rem", { lineHeight: "1.1875rem" }],
        base: ["0.875rem", { lineHeight: "1.3125rem" }],
        lg: ["1rem", { lineHeight: "1.5rem" }],
        xl: ["1.25rem", { lineHeight: "1.75rem" }],
        "2xl": ["1.5rem", { lineHeight: "2rem" }],
        "3xl": ["2rem", { lineHeight: "2.5rem" }],
      },
      spacing: {
        // Density 8/10 — dense dashboard scale
        xs: "0.125rem",
        sm: "0.25rem",
        md: "0.5rem",
        lg: "0.75rem",
        xl: "1rem",
        "2xl": "1.5rem",
        "3xl": "2rem",
      },
      borderRadius: {
        none: "0",
        sm: "0.125rem",
        DEFAULT: "0.1875rem",
        md: "0.25rem",
        lg: "0.375rem",
      },
      boxShadow: {
        sm: "0 1px 2px rgba(0,0,0,0.25)",
        md: "0 4px 6px rgba(0,0,0,0.35)",
        lg: "0 10px 15px rgba(0,0,0,0.45)",
      },
      transitionDuration: {
        // Motion 5/10 — 150-300ms micro-interactions only
        DEFAULT: "200ms",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "slide-up": { from: { opacity: "0", transform: "translateY(8px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        "pulse-soft": { "0%, 100%": { opacity: "1" }, "50%": { opacity: "0.5" } },
      },
      animation: {
        "fade-in": "fade-in 200ms ease-out",
        "slide-up": "slide-up 200ms ease-out",
        "pulse-soft": "pulse-soft 1.6s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
