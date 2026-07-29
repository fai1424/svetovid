// Screen 4 — Investigation. The heart of the app.
//
// Three panes:
//   LEFT   — AgentTrace: streaming ReAct loop rendered as evidence-tape motif
//   MIDDLE — StepProgress: vertical stepper, live node status, sub-progress
//   RIGHT  — LiveReport: report assembles itself in real time + tabs
//
// Top bar: Stop / Pause / Approve (HITL) buttons + timer + token counter
// Bottom bar: provenance ticker (chain-of-custody heartbeat)

import { memo, useEffect, useRef, useState } from "react";
import {
  Pause,
  Play,
  Square,
  CheckCircle2,
  XCircle,
  ShieldQuestion,
  Activity,
  FileText,
  ListTree,
  ScrollText,
  Download,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { api } from "@/lib/api";
import { Badge, Button, Card, CardBody, CardHeader, StatusDot } from "@/components/ui/primitives";
import { useActiveInvestigation, useEvents } from "@/lib/events";
import type { Investigation as Inv, TraceRow } from "@/lib/types";
import ReactMarkdown from "react-markdown";
import { TimelineView } from "@/components/TimelineView";
import { AttackHeatmap } from "@/components/AttackHeatmap";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export function Investigation() {
  const inv = useActiveInvestigation();
  const [elapsed, setElapsed] = useState(0);
  // Q3 — tracks in-flight HITL submission so the buttons disable while the
  // POST is in flight (prevents double-submit racing the Future resolution).
  const [hitlBusy, setHitlBusy] = useState(false);

  // tick the elapsed timer
  useEffect(() => {
    if (!inv || inv.status !== "running") return;
    const t0 = Date.parse(inv.started_at);
    const id = setInterval(() => setElapsed(Date.now() - t0), 250);
    return () => clearInterval(id);
  }, [inv?.id, inv?.status, inv?.started_at]);

  if (!inv) {
    return <EmptyInvestigation onStart={() => {}} />;
  }

  const hitlPending = inv.status === "paused";
  const running = inv.status === "running";

  // Q3 — POST the human's decision to the HITL gate endpoint. The backend
  // resolves the asyncio.Future the goal coroutine is awaiting, which either
  // releases the report for finalization (approve) or cancels it (reject).
  const submitHitl = async (approved: boolean) => {
    if (!inv || hitlBusy) return;
    setHitlBusy(true);
    try {
      await api.hitlResponse(inv.id, approved);
      // The backend emits hitl.response / investigation.end over the WS;
      // the events reducer flips the status, so no local state update needed.
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error("HITL submission failed", e);
    } finally {
      setHitlBusy(false);
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Top bar: status + controls */}
      <header className="flex-none px-2xl py-md border-b border-border flex items-center gap-lg">
        <div className="flex items-center gap-md">
          <StatusDot status={statusToNode(inv.status)} />
          <h1 className="text-sm font-semibold tracking-tight">{inv.goal_label}</h1>
          <Badge tone="muted">{inv.goal_id}</Badge>
        </div>
        <div className="ml-auto flex items-center gap-md text-xs text-muted-fg">
          <span className="font-mono tabular-nums">{formatElapsed(elapsed)}</span>
          <Sep />
          <span>{inv.trace.length} events</span>
          <Sep />
          <span>{Object.keys(inv.tool_calls).length} tool calls</span>
          <Sep />
          <span>{inv.provenance_count} provenance</span>
        </div>
        <div className="flex items-center gap-sm pl-lg border-l border-border">
          <ExportMenu invId={inv.id} />
          {hitlPending ? (
            <>
              <Button
                variant="primary"
                loading={hitlBusy}
                onClick={() => submitHitl(true)}
              >
                <CheckCircle2 className="h-3.5 w-3.5" /> Approve
              </Button>
              <Button
                variant="destructive"
                loading={hitlBusy}
                onClick={() => submitHitl(false)}
              >
                <XCircle className="h-3.5 w-3.5" /> Reject
              </Button>
            </>
          ) : running ? (
            <>
              <Button variant="ghost" onClick={() => {}}>
                <Pause className="h-3.5 w-3.5" /> Pause
              </Button>
              <Button variant="destructive" onClick={() => {}}>
                <Square className="h-3.5 w-3.5" /> Stop
              </Button>
            </>
          ) : (
            <Button variant="ghost" disabled>
              <Play className="h-3.5 w-3.5" /> Resume
            </Button>
          )}
        </div>
      </header>

      {/* Three-pane layout */}
      <div className="flex-1 grid grid-cols-12 gap-md overflow-hidden p-md">
        <Pane className="col-span-3" title="Agent trace" icon={ScrollText}>
          <ErrorBoundary>
            <AgentTrace trace={inv.trace} />
          </ErrorBoundary>
        </Pane>
        <Pane className="col-span-4" title="Progress" icon={ListTree}>
          <ErrorBoundary>
            <StepProgress inv={inv} />
          </ErrorBoundary>
        </Pane>
        <Pane className="col-span-5" title="Live report" icon={FileText}>
          <ErrorBoundary>
            <LiveReport inv={inv} />
          </ErrorBoundary>
        </Pane>
      </div>

      {/* Provenance ticker */}
      <footer className="flex-none border-t border-border px-2xl py-sm flex items-center gap-md text-2xs text-muted-fg">
        <ShieldQuestion className="h-3 w-3" aria-hidden />
        <span>chain of custody</span>
        <Sep />
        {inv.last_provenance ? (
          <span className="font-mono truncate">
            {(inv.last_provenance as Record<string, unknown>).tool as string}
            {" · "}
            {(inv.last_provenance as Record<string, unknown>).output_hash as string || "—"}
            {" · "}
            {(inv.last_provenance as Record<string, unknown>).ts as string}
          </span>
        ) : (
          <span className="italic">no tool calls recorded yet</span>
        )}
      </footer>
    </div>
  );
}

function statusToNode(s: Inv["status"]) {
  switch (s) {
    case "running": return "running" as const;
    case "done": return "done" as const;
    case "failed": return "failed" as const;
    case "cancelled": return "failed" as const;
    case "paused": return "pending" as const;
  }
}

function Pane({
  title,
  icon: Icon,
  className,
  children,
}: {
  title: string;
  icon: typeof Activity;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <Card className={cn("flex flex-col overflow-hidden", className)}>
      <CardHeader className="flex-none flex items-center gap-md py-sm">
        <Icon className="h-3.5 w-3.5 text-muted-fg" aria-hidden />
        <h2 className="text-xs font-semibold uppercase tracking-wider">{title}</h2>
      </CardHeader>
      <div className="flex-1 overflow-auto">{children}</div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// LEFT: AgentTrace — evidence-tape motif
// ---------------------------------------------------------------------------

const TRACE_STYLE: Record<TraceRow["kind"], { color: string; prefix: string; icon?: string }> = {
  thought:     { color: "text-muted-fg",  prefix: "»" },
  action:      { color: "text-accent",    prefix: "→" },
  observation: { color: "text-foreground", prefix: "←" },
  error:       { color: "text-destructive", prefix: "!" },
  hitl:        { color: "text-status-pending", prefix: "⏸" },
  checkpoint:  { color: "text-status-running", prefix: "▶" },
  tool:        { color: "text-foreground", prefix: "⚙" },
};

function AgentTraceImpl({ trace }: { trace: TraceRow[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // jump-to-latest: stick to bottom unless user has scrolled up
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (atBottom) el.scrollTop = el.scrollHeight;
  }, [trace.length]);

  if (trace.length === 0) {
    return <EmptyPane>Waiting for the agent's first thought…</EmptyPane>;
  }

  return (
    <div ref={scrollRef} className="evidence-tape pl-md">
      <ul className="py-md pr-md space-y-xs">
        {trace.map((row) => {
          const style = TRACE_STYLE[row.kind];
          return (
            <li key={row.id} className="text-xs leading-relaxed animate-fade-in">
              <div className={cn("flex gap-sm", style.color)}>
                <span className="select-none">{style.prefix}</span>
                <div className="flex-1">
                  <div className="flex items-baseline justify-between gap-md">
                    <span className={cn(row.kind === "thought" && "italic", row.kind === "error" && "font-medium")}>
                      {row.text}
                    </span>
                    <time className="text-2xs text-muted-fg/70 font-mono shrink-0">
                      {formatTime(row.ts)}
                    </time>
                  </div>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// Q9: memoize so the trace pane only re-renders when its `trace` prop reference
// changes, not on every unrelated investigation update (e.g. report/ioc events
// that don't touch the trace).
const AgentTrace = memo(AgentTraceImpl);

// ---------------------------------------------------------------------------
// MIDDLE: StepProgress
// ---------------------------------------------------------------------------

function StepProgressImpl({ inv }: { inv: Inv }) {
  if (inv.nodes.length === 0) {
    return <EmptyPane>Investigation graph will appear here once the goal loads.</EmptyPane>;
  }

  // overall progress: count of done nodes
  const done = inv.nodes.filter((n) => n.status === "done").length;
  const total = inv.nodes.length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const runningToolCall = Object.values(inv.tool_calls).find((t) => t.status === "running");

  return (
    <div className="p-md">
      {/* overall progress bar */}
      <div className="mb-md">
        <div className="flex justify-between text-2xs text-muted-fg uppercase tracking-wider mb-xs">
          <span>{inv.status}</span>
          <span className="tabular-nums">{pct}% · {done}/{total}</span>
        </div>
        <div className="h-1 rounded-full bg-muted overflow-hidden">
          <div
            className="h-full bg-accent transition-all duration-300"
            style={{ width: `${pct}%` }}
            role="progressbar"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
      </div>

      {/* active tool call sub-progress */}
      {runningToolCall && (
        <Card className="mb-md border-status-running/40 bg-status-running/5">
          <CardBody className="p-md text-xs">
            <div className="flex items-center gap-md">
              <Activity className="h-3 w-3 text-status-running animate-pulse-soft" />
              <span className="font-mono">{runningToolCall.tool}</span>
              {runningToolCall.sandboxed && <Badge tone="muted">sandbox</Badge>}
            </div>
            <div className="mt-xs font-mono text-2xs text-muted-fg space-y-0.5 max-h-24 overflow-auto">
              {runningToolCall.stdout.slice(-4).map((l, i) => (
                <div key={i} className="truncate">{l}</div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}

      {/* stepper */}
      <ol className="space-y-0">
        {inv.nodes.map((n, i) => (
          <li key={n.id} className="relative pl-xl py-sm">
            {/* connector line */}
            {i < inv.nodes.length - 1 && (
              <span
                className={cn(
                  "absolute left-1 top-7 bottom-0 w-px",
                  n.status === "done" ? "bg-status-done/40" : "bg-border"
                )}
                aria-hidden
              />
            )}
            {/* status bullet */}
            <span className="absolute left-0 top-2">
              <StatusDot status={n.status} />
            </span>
            <div className="flex items-baseline justify-between">
              <span className={cn(
                "text-sm",
                n.status === "pending" ? "text-muted-fg" : "text-foreground",
                n.status === "running" && "font-medium"
              )}>
                {n.label}
              </span>
              <span className="text-2xs text-muted-fg uppercase tracking-wider font-mono">{n.id}</span>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

// Q9: memoize — the progress pane depends on node status + the running tool
// call only. Without memo it re-renders on every report/trace event too.
const StepProgress = memo(StepProgressImpl);

// ---------------------------------------------------------------------------
// RIGHT: LiveReport
// ---------------------------------------------------------------------------

function LiveReportImpl({ inv }: { inv: Inv }) {
  const [tab, setTab] = useState<"report" | "tools" | "ioc" | "timeline" | "attack">("report");
  const [heatmapTechnique, setHeatmapTechnique] = useState<string | null>(null);
  const sorted = [...inv.report].sort((a, b) => a.order - b.order);
  const tabs = [
    { id: "report" as const, label: "Report", count: sorted.length },
    { id: "tools" as const, label: "Tools", count: Object.keys(inv.tool_calls).length },
    { id: "ioc" as const, label: "IoCs", count: inv.iocs.length },
    { id: "timeline" as const, label: "Timeline", count: inv.timeline.length },
    { id: "attack" as const, label: "ATT&CK", count: countDistinctTechniques(inv) },
  ];

  return (
    <div className="flex flex-col h-full">
      {/* tabs */}
      <div className="flex-none flex border-b border-border">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            aria-selected={tab === t.id}
            className={cn(
              "px-lg py-sm text-xs uppercase tracking-wider transition-colors cursor-pointer",
              tab === t.id
                ? "text-foreground border-b-2 border-accent -mb-px"
                : "text-muted-fg hover:text-foreground"
            )}
          >
            {t.label}
            {t.count > 0 && <span className="ml-xs text-2xs text-muted-fg">({t.count})</span>}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-hidden text-sm leading-relaxed">
        {tab === "report" && (
          <div className="h-full overflow-auto p-lg">
            {sorted.length === 0 ? (
              <EmptyPane>Report sections will appear here as the agent writes them.</EmptyPane>
            ) : (
              <div className="space-y-xl">
                {sorted.map((s) => (
                  <section key={s.section_id}>
                    <h3 className="text-xs uppercase tracking-wider text-muted-fg mb-xs">{s.title}</h3>
                    <div className="prose prose-invert max-w-none">
                      <ReactMarkdown>{s.markdown}</ReactMarkdown>
                    </div>
                  </section>
                ))}
              </div>
            )}
          </div>
        )}
        {tab === "tools" && (
          <div className="h-full overflow-auto p-lg">
            <ToolCallList inv={inv} />
          </div>
        )}
        {tab === "ioc" && (
          <div className="h-full overflow-auto p-lg">
            <IocTable iocs={inv.iocs} />
          </div>
        )}
        {tab === "timeline" && (
          <TimelineView
            entries={inv.timeline}
            techniqueFilter={heatmapTechnique}
            onClearTechniqueFilter={() => setHeatmapTechnique(null)}
          />
        )}
        {tab === "attack" && (
          <AttackHeatmap
            techniqueCounts={buildTechniqueCounts(inv)}
            selectedTechnique={heatmapTechnique}
            onSelectTechnique={(id) => {
              setHeatmapTechnique(id);
              if (id) setTab("timeline");
            }}
          />
        )}
      </div>
    </div>
  );
}

// Q9: memoize — the report pane is the heaviest renderer (ReactMarkdown +
// heatmap), so we only want to recompute it when its `inv` prop reference
// changes, which the reducer already swaps on every state update.
const LiveReport = memo(LiveReportImpl);

// Tally ATT&CK technique references across timeline entries + IOCs so the
// heatmap can shade cells by finding count.
function buildTechniqueCounts(inv: Inv): Record<string, number> {
  const counts: Record<string, number> = {};
  const bump = (id: string) => {
    counts[id] = (counts[id] || 0) + 1;
  };
  for (const e of inv.timeline) {
    for (const t of e.mitre_tags || []) bump(t);
  }
  for (const ioc of inv.iocs) {
    for (const t of ioc.mitre_tags || []) bump(t);
  }
  return counts;
}

function countDistinctTechniques(inv: Inv): number {
  return Object.keys(buildTechniqueCounts(inv)).length;
}

function IocTable({ iocs }: { iocs: Inv["iocs"] }) {
  if (iocs.length === 0) {
    return <EmptyPane>No indicators of compromise extracted yet.</EmptyPane>;
  }
  return (
    <div className="overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-2xs uppercase tracking-wider text-muted-fg border-b border-border">
            <th className="text-left font-medium py-xs px-sm">Type</th>
            <th className="text-left font-medium py-xs px-sm">Value</th>
            <th className="text-left font-medium py-xs px-sm">Description</th>
            <th className="text-left font-medium py-xs px-sm">ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={i} className="border-b border-border/50 hover:bg-muted/50">
              <td className="py-xs px-sm">
                <Badge tone="muted">{ioc.type}</Badge>
              </td>
              <td className="py-xs px-sm font-mono text-foreground break-all">{ioc.value}</td>
              <td className="py-xs px-sm text-muted-fg">{ioc.description || "—"}</td>
              <td className="py-xs px-sm">
                <div className="flex flex-wrap gap-xs">
                  {(ioc.mitre_tags || []).map((t) => (
                    <span key={t} className="font-mono text-2xs text-accent">
                      {t}
                    </span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Export menu — Markdown / STIX / CASE / JSON / PDF
// ---------------------------------------------------------------------------

const EXPORT_FORMATS: { id: string; label: string; mime: string }[] = [
  { id: "markdown", label: "Markdown (.md)", mime: "text/markdown" },
  { id: "json", label: "JSON (.json)", mime: "application/json" },
  { id: "stix", label: "STIX 2.1 (.json)", mime: "application/stix+json" },
  { id: "case", label: "CASE / UCO (.json)", mime: "application/ld+json" },
  { id: "pdf", label: "PDF report (.pdf)", mime: "application/pdf" },
];

function ExportMenu({ invId }: { invId: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  async function doExport(format: string, mime: string) {
    setBusy(format);
    try {
      const resp = await api.exportInvestigation(invId, format);
      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        console.error(`export ${format} failed: HTTP ${resp.status}`, text);
        return;
      }
      // Determine a filename + content type. Prefer the server's
      // Content-Disposition; otherwise synthesize one from the format.
      const disposition = resp.headers.get("Content-Disposition") || "";
      const filenameMatch = disposition.match(/filename="?([^"]+)"?/);
      const filename =
        filenameMatch?.[1] || `svetovid-${invId}.${format === "markdown" ? "md" : format === "pdf" ? "pdf" : "json"}`;
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      void mime; // mime kept for type clarity; server already sets it on the blob
    } catch (e) {
      console.error(`export ${format} error`, e);
    } finally {
      setBusy(null);
      setOpen(false);
    }
  }

  return (
    <div className="relative" ref={menuRef}>
      <Button
        variant="outline"
        size="sm"
        onClick={() => setOpen((o) => !o)}
        disabled={busy !== null}
      >
        <Download className="h-3.5 w-3.5" />
        Export
        <ChevronDown className="h-3 w-3" />
      </Button>
      {open && (
        <div className="absolute right-0 top-full mt-xs z-20 min-w-[12rem] bg-surface border border-border rounded-md shadow-lg py-xs animate-fade-in">
          {EXPORT_FORMATS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => doExport(f.id, f.mime)}
              disabled={busy !== null}
              className="w-full text-left px-md py-sm text-xs text-foreground hover:bg-muted disabled:opacity-50 cursor-pointer"
            >
              {busy === f.id ? "Exporting…" : f.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ToolCallList({ inv }: { inv: Inv }) {
  const calls = Object.values(inv.tool_calls);
  if (calls.length === 0) {
    return <EmptyPane>No tool calls yet.</EmptyPane>;
  }
  return (
    <ul className="space-y-md">
      {calls.map((c) => (
        <li key={c.call_id} className="border border-border rounded-md p-md">
          <div className="flex items-center justify-between mb-xs">
            <span className="font-mono text-xs text-accent">{c.tool}</span>
            <Badge tone={c.status === "ok" ? "accent" : c.status === "running" ? "warning" : "danger"}>
              {c.status}
            </Badge>
          </div>
          <pre className="text-2xs text-muted-fg font-mono whitespace-pre-wrap break-all">
            {JSON.stringify(c.args)}
          </pre>
          {c.duration_s !== undefined && (
            <div className="mt-xs text-2xs text-muted-fg flex gap-md">
              <span>{c.duration_s.toFixed(2)}s</span>
              {c.output_hash && <span className="font-mono truncate">{c.output_hash}</span>}
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

function EmptyPane({ children }: { children: React.ReactNode }) {
  return (
    <div className="h-full flex items-center justify-center text-center px-xl py-2xl text-xs text-muted-fg">
      {children}
    </div>
  );
}

function EmptyInvestigation({ onStart }: { onStart: () => void }) {
  const [goalId, setGoalId] = useState<string>("G01");
  const [path, setPath] = useState("");
  const setActive = useEvents((s) => s.setActive);

  async function start() {
    if (!path || !goalId) return;
    const r = await api.startInvestigation(goalId, path);
    setActive(r.investigation_id);
  }

  return (
    <div className="h-full flex items-center justify-center">
      <Card className="max-w-md">
        <CardBody className="text-center space-y-md">
          <Activity className="h-8 w-8 mx-auto text-muted-fg opacity-50" />
          <h2 className="text-sm font-semibold">No active investigation</h2>
          <p className="text-xs text-muted-fg">
            Pick a goal on the Goal screen, or kick one off directly here.
          </p>
          <div className="space-y-xs text-left">
            <input
              className="w-full h-9 px-md bg-background border border-border rounded-md font-mono text-xs"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/path/to/evidence"
            />
            <select
              className="w-full h-9 px-md bg-background border border-border rounded-md font-mono text-xs"
              value={goalId}
              onChange={(e) => setGoalId(e.target.value)}
            >
              <option value="G01">G01 — Windows attack timeline</option>
            </select>
            <Button variant="primary" className="w-full" onClick={start} disabled={!path}>
              Start G01
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function Sep() {
  return <span className="text-muted-fg/40">|</span>;
}

function formatElapsed(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  return `${m}:${String(sec).padStart(2, "0")}`;
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return "";
  }
}
