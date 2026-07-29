// RatingPrompt — dismissible toast that surfaces after an investigation ends.
//
// Watches the event store for an investigation transitioning to a terminal
// state (investigation.end fired by the backend) and invites the user to rate
// the result on a 1-5 scale with optional free-text feedback. Submits to
// POST /api/telemetry/rate. Auto-dismisses after 5s; user can also close it
// manually or by submitting. The component itself is a no-op until an
// investigation actually ends, so it can sit in the App tree permanently.
//
// Privacy: only the investigation_id, rating, and feedback text travel to the
// server. No evidence content, paths, or prompts are attached.

import { useEffect, useRef, useState } from "react";
import { Star, X, CheckCircle2, Send } from "lucide-react";
import { cn } from "@/lib/cn";
import { useEvents } from "@/lib/events";
import { api } from "@/lib/api";

const AUTO_DISMISS_MS = 5000;

interface PromptState {
  investigationId: string;
  goalLabel: string;
}

export function RatingPrompt() {
  const investigations = useEvents((s) => s.investigations);
  const activeId = useEvents((s) => s.activeInvestigationId);

  const [prompt, setPrompt] = useState<PromptState | null>(null);
  // remember which investigations we've already prompted for so a status
  // re-render doesn't re-trigger the toast.
  const seenRef = useRef<Set<string>>(new Set());

  // Watch the active investigation for a terminal transition.
  useEffect(() => {
    if (!activeId) return;
    const inv = investigations[activeId];
    if (!inv) return;
    const terminal = inv.status === "done" || inv.status === "failed" || inv.status === "cancelled";
    if (terminal && !seenRef.current.has(activeId)) {
      seenRef.current.add(activeId);
      setPrompt({ investigationId: activeId, goalLabel: inv.goal_label || inv.goal_id });
    }
  }, [activeId, investigations]);

  if (!prompt) return null;

  return (
    <RatingToast
      key={prompt.investigationId}
      prompt={prompt}
      onDone={() => setPrompt(null)}
    />
  );
}

function RatingToast({ prompt, onDone }: { prompt: PromptState; onDone: () => void }) {
  const [rating, setRating] = useState(0);
  const [hover, setHover] = useState(0);
  const [feedback, setFeedback] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-dismiss countdown. Pauses while submitting, and stops the moment the
  // user picks a rating (interaction implies intent to stay).
  useEffect(() => {
    if (submitting || rating > 0) return;
    const id = setTimeout(onDone, AUTO_DISMISS_MS);
    return () => clearTimeout(id);
  }, [onDone, submitting, rating]);

  async function submit() {
    if (rating < 1 || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.rateInvestigation(prompt.investigationId, rating, feedback);
      setSubmitted(true);
      // brief success beat, then dismiss
      setTimeout(onDone, 900);
    } catch (e) {
      setError(e instanceof Error ? e.message : "submit failed");
      setSubmitting(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-label="Rate this investigation"
      className="fixed bottom-xl right-xl z-50 w-80 animate-slide-up"
    >
      <div className="bg-surface text-surface-fg border border-border rounded-md shadow-lg overflow-hidden">
        {/* header */}
        <div className="flex items-center justify-between px-lg py-md border-b border-border">
          <div className="min-w-0">
            <div className="text-xs font-semibold uppercase tracking-wider">How was it?</div>
            <div className="text-2xs text-muted-fg font-mono truncate">
              {prompt.goalLabel}
            </div>
          </div>
          <button
            type="button"
            onClick={onDone}
            aria-label="Dismiss"
            className="text-muted-fg hover:text-foreground transition-colors cursor-pointer"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* body */}
        {submitted ? (
          <div className="px-lg py-2xl flex flex-col items-center gap-md text-center">
            <CheckCircle2 className="h-6 w-6 text-status-done" />
            <p className="text-xs text-muted-fg">Thanks — your rating was recorded.</p>
          </div>
        ) : (
          <div className="px-lg py-md space-y-md">
            {/* stars */}
            <div className="flex items-center justify-center gap-sm">
              {[1, 2, 3, 4, 5].map((n) => {
                const active = (hover || rating) >= n;
                return (
                  <button
                    key={n}
                    type="button"
                    aria-label={`${n} star${n > 1 ? "s" : ""}`}
                    onMouseEnter={() => setHover(n)}
                    onMouseLeave={() => setHover(0)}
                    onClick={() => setRating(n)}
                    className="p-xs rounded-sm transition-colors cursor-pointer hover:bg-muted"
                  >
                    <Star
                      className={cn(
                        "h-5 w-5 transition-colors",
                        active ? "text-accent" : "text-muted-fg/50"
                      )}
                      fill={active ? "currentColor" : "none"}
                      strokeWidth={active ? 1.5 : 2}
                    />
                  </button>
                );
              })}
            </div>

            {/* feedback */}
            <textarea
              className="w-full h-16 px-md py-sm bg-background border border-border rounded-md text-xs font-mono text-foreground placeholder:text-muted-fg/60 focus-visible:outline-2 focus-visible:outline-[var(--color-ring)] focus-visible:outline-offset-1 resize-none"
              placeholder="optional feedback (no case details)…"
              value={feedback}
              onChange={(e) => setFeedback(e.target.value)}
              maxLength={1000}
            />

            {error && (
              <p className="text-2xs text-destructive font-mono">{error}</p>
            )}

            <div className="flex items-center justify-between gap-sm">
              <span className="text-2xs text-muted-fg">
                anonymous · no case data sent
              </span>
              <button
                type="button"
                onClick={submit}
                disabled={rating < 1 || submitting}
                className={cn(
                  "inline-flex items-center gap-xs h-7 px-md rounded-md text-xs font-medium transition-all cursor-pointer",
                  "disabled:opacity-40 disabled:cursor-not-allowed",
                  rating >= 1
                    ? "bg-accent text-on-accent hover:brightness-110"
                    : "bg-secondary text-on-secondary"
                )}
              >
                <Send className="h-3 w-3" />
                Submit
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
