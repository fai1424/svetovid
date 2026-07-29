// Minimal themed primitives — Button, Card, Badge, StatusDot, Spinner.
// Styled entirely from tokens; no external shadcn install needed for v1.
// Each component is forwardRef + accessible (aria where needed).

import { forwardRef } from "react";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";
import type { NodeStatus } from "@/lib/types";

type ButtonVariant = "primary" | "secondary" | "ghost" | "destructive" | "outline";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-accent text-on-accent hover:brightness-110",
  secondary: "bg-secondary text-on-secondary hover:bg-secondary/80",
  ghost: "bg-transparent text-foreground hover:bg-muted",
  outline: "bg-transparent border border-border text-foreground hover:bg-muted",
  destructive: "bg-destructive text-on-destructive hover:brightness-110",
};
const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-7 px-2 text-xs gap-1 rounded-md",
  md: "h-9 px-3 text-sm gap-2 rounded-md",
  lg: "h-11 px-4 text-base gap-2 rounded-md",
  icon: "h-7 w-7 rounded-md",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, className, children, disabled, ...rest },
  ref
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center font-medium transition-all cursor-pointer",
        "focus-visible:outline-2 focus-visible:outline-[var(--color-ring)] focus-visible:outline-offset-2",
        "disabled:opacity-40 disabled:cursor-not-allowed",
        buttonVariants[variant],
        buttonSizes[size],
        className
      )}
      {...rest}
    >
      {loading && <Spinner className="h-3.5 w-3.5" />}
      {children}
    </button>
  );
});

export function Card({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("bg-surface text-surface-fg border border-border rounded-md shadow-sm", className)}
      {...rest}
    />
  );
}

export function CardHeader({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-lg py-md border-b border-border", className)} {...rest} />;
}

export function CardBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-lg py-md", className)} {...rest} />;
}

type BadgeTone = "default" | "accent" | "warning" | "danger" | "muted";

const badgeTones: Record<BadgeTone, string> = {
  default: "bg-secondary text-on-secondary",
  accent: "bg-accent/15 text-accent border border-accent/40",
  warning: "bg-status-pending/15 text-status-pending border border-status-pending/40",
  danger: "bg-destructive/15 text-destructive border border-destructive/40",
  muted: "bg-muted text-muted-fg",
};

export function Badge({ tone = "default", className, children }: { tone?: BadgeTone; className?: string; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 text-2xs uppercase tracking-wider rounded-sm",
        badgeTones[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

const statusColor: Record<NodeStatus, string> = {
  pending: "bg-status-pending",
  running: "bg-status-running animate-pulse-soft",
  done: "bg-status-done",
  failed: "bg-status-failed",
  skipped: "bg-status-skipped",
};

export function StatusDot({ status, className }: { status: NodeStatus; className?: string }) {
  return (
    <span
      role="img"
      aria-label={status}
      className={cn("inline-block h-2 w-2 rounded-full", statusColor[status], className)}
    />
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn("animate-spin", className)}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M22 12a10 10 0 0 1-10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Input({ className, ...rest }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "w-full h-9 px-md bg-background text-foreground placeholder:text-muted-fg/60",
        "border border-border rounded-md font-mono text-sm",
        "focus-visible:outline-2 focus-visible:outline-[var(--color-ring)] focus-visible:outline-offset-1",
        "transition-colors",
        className
      )}
      {...rest}
    />
  );
}

export function Label({ className, ...rest }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={cn("block text-xs uppercase tracking-wider text-muted-fg mb-1", className)}
      {...rest}
    />
  );
}
