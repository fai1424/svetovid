// WebSocket event store — single source of truth for the Investigation screen.
//
// Connects to /ws, dispatches every AgentEvent through a reducer, and exposes
// per-investigation view-model state (nodes, trace rows, tool calls, report
// sections, provenance ticker) to the three Investigation panes.
//
// Design notes:
//   - One global WebSocket (the backend multiplexes all investigations on it).
//   - Investigations are keyed by investigation_id; the UI picks the active one.
//   - The reducer is deliberately explicit — every event type is its own case,
//     so the progress/status rules are auditable in one place.

import { create } from "zustand";
import type {
  AgentEvent,
  Investigation,
  GoalNode,
  NodeStatus,
  ReportSection,
  ToolCallRow,
  TraceRow,
  IOC,
  TimelineEntry,
} from "./types";

// In Vite dev (localhost:1420) the Vite proxy forwards /ws to the backend.
// In Tauri production the window origin is tauri://localhost, so we must
// hardcode the backend's loopback address (matching the CSP in tauri.conf.json).
function wsBaseUrl() {
  return window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? `ws://${window.location.host}/ws`
    : "ws://127.0.0.1:7421/ws";
}

// Auth token for the WS (same token the REST client uses).
let wsToken: string | null = null;
export async function setWsToken(t: string | null) {
  wsToken = t;
}

let socket: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let announcementLive: ((msg: string) => void) | null = null;

// Screen-reader live region hook (set from App.tsx so announcements work).
export function setAnnouncer(fn: (msg: string) => void) {
  announcementLive = fn;
}

function announce(msg: string) {
  if (announcementLive) announcementLive(msg);
}

interface EventStore {
  investigations: Record<string, Investigation>;
  activeInvestigationId: string | null;
  scan: {
    status: "idle" | "scanning" | "done" | "error";
    scanned: number;
    total: number | null;
    found: Record<string, number>;
  };
  connected: boolean;

  // actions
  connect: () => void;
  disconnect: () => void;
  setActive: (id: string | null) => void;
  ingest: (event: AgentEvent) => void;
  resetScan: () => void;
}

function newInvestigation(invId: string, goalId: string, goalLabel: string): Investigation {
  return {
    id: invId,
    goal_id: goalId,
    goal_label: goalLabel,
    status: "running",
    started_at: new Date().toISOString(),
    nodes: [],
    trace: [],
    tool_calls: {},
    report: [],
    iocs: [],
    timeline: [],
    provenance_count: 0,
  };
}

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

export const useEvents = create<EventStore>((set, get) => ({
  investigations: {},
  activeInvestigationId: null,
  scan: { status: "idle", scanned: 0, total: null, found: {} },
  connected: false,

  connect: () => {
    if (socket && socket.readyState <= 1) return; // CONNECTING or OPEN
    const url = wsToken ? `${wsBaseUrl()}?token=${wsToken}` : wsBaseUrl();
    socket = new WebSocket(url);
    socket.onopen = () => set({ connected: true });
    socket.onclose = () => {
      set({ connected: false });
      socket = null;
      // gentle reconnect backoff
      if (!reconnectTimer) reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        get().connect();
      }, 1500);
    };
    socket.onerror = () => {
      try { socket?.close(); } catch { /* noop */ }
    };
    socket.onmessage = (ev) => {
      try {
        const evt = JSON.parse(ev.data) as AgentEvent;
        get().ingest(evt);
      } catch {
        /* malformed — drop */
      }
    };
  },

  disconnect: () => {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
    try { socket?.close(); } catch { /* noop */ }
    socket = null;
    set({ connected: false });
  },

  setActive: (id) => set({ activeInvestigationId: id }),

  resetScan: () =>
    set({ scan: { status: "idle", scanned: 0, total: null, found: {} } }),

  ingest: (event) => {
    const invId = event.investigation_id;
    const data = event.data || {};

    // ---- scan events (not tied to an investigation) ----
    if (event.type === "scan.start") {
      set({ scan: { status: "scanning", scanned: 0, total: null, found: {} } });
      return;
    }
    if (event.type === "scan.progress") {
      const d = data as { scanned: number; total: number | null; found: Record<string, number> };
      set((s) => ({
        scan: { status: "scanning", scanned: d.scanned, total: d.total, found: d.found || {} },
      }));
      return;
    }
    if (event.type === "scan.complete") {
      set((s) => ({ scan: { ...s.scan, status: "done" } }));
      return;
    }
    if (event.type === "ping") return;

    // ---- error ----
    if (event.type === "error") {
      const d = data as { message: string; fatal: boolean };
      if (invId) {
        set((s) => updateInvestigation(s, invId, (inv) => ({
          ...inv,
          trace: [...inv.trace, {
            id: uid(), ts: event.ts, kind: "error", text: d.message,
          }],
        })));
      }
      announce(`Error: ${d.message}`);
      return;
    }

    if (!invId) return;
    // Ensure the investigation exists; if this is the start event, seed its nodes.
    set((s) => {
      if (s.investigations[invId]) return s;
      const goalId = (data as { goal_id?: string }).goal_id || "?";
      const label = GOAL_LABEL_FALLBACK[goalId] || goalId;
      return { investigations: { ...s.investigations, [invId]: newInvestigation(invId, goalId, label) } };
    });

    set((s) => updateInvestigation(s, invId, (inv) => reduceEvent(inv, event)));

    // Make the first investigation we see the active one.
    if (get().activeInvestigationId === null) {
      set({ activeInvestigationId: invId });
    }
  },
}));

function updateInvestigation(
  s: EventStore,
  invId: string,
  fn: (inv: Investigation) => Investigation
): Partial<EventStore> {
  const inv = s.investigations[invId];
  if (!inv) return {};
  return { investigations: { ...s.investigations, [invId]: fn(inv) } };
}

function reduceEvent(inv: Investigation, e: AgentEvent): Investigation {
  const d = e.data || {};
  switch (e.type) {
    case "investigation.start": {
      const nodes = ((d as { nodes?: string[] }).nodes || []).map((id) => ({
        id,
        label: id.replaceAll("_", " "),
        status: "pending" as NodeStatus,
      }));
      return { ...inv, nodes };
    }
    case "goal.graph_loaded": {
      const nodes: GoalNode[] = ((d as { nodes?: unknown[] }).nodes || []).map((n) => {
        const obj = n as { id: string; label: string; status?: NodeStatus };
        return { id: obj.id, label: obj.label, status: obj.status || "pending" };
      });
      return { ...inv, nodes };
    }
    case "node.state_change": {
      const status = (d as { status: NodeStatus }).status;
      const detail = (d as { detail?: string }).detail || "";
      const nodes = inv.nodes.map((n) =>
        n.id === e.node ? { ...n, status } : n
      );
      // When a node flips to running, drop a checkpoint in the trace.
      const trace =
        status === "running"
          ? [...inv.trace, {
              id: uid(), ts: e.ts, kind: "checkpoint" as const,
              text: `▶ ${e.node} — ${detail || ""}`.trim(),
            }]
          : inv.trace;
      return { ...inv, nodes, trace };
    }
    case "agent.thought": {
      const text = (d as { text: string }).text;
      return { ...inv, trace: [...inv.trace, { id: uid(), ts: e.ts, kind: "thought", text }] };
    }
    case "agent.action": {
      const tool = (d as { tool: string }).tool;
      const args = (d as { args?: Record<string, unknown> }).args || {};
      return {
        ...inv,
        trace: [...inv.trace, {
          id: uid(), ts: e.ts, kind: "action",
          text: `→ ${tool}(${Object.keys(args).join(", ")})`, tool,
        }],
      };
    }
    case "agent.observation": {
      const tool = (d as { tool: string }).tool;
      const summary = (d as { summary: string }).summary;
      return { ...inv, trace: [...inv.trace, { id: uid(), ts: e.ts, kind: "observation", text: `← ${tool}: ${summary}`, tool }] };
    }
    case "tool.start": {
      const call_id = (d as { call_id?: string }).call_id || uid();
      const tool = (d as { tool: string }).tool;
      const args = (d as { args?: Record<string, unknown> }).args || {};
      const sandboxed = (d as { sandboxed?: boolean }).sandboxed ?? false;
      const container_id = (d as { container_id?: string }).container_id || null;
      const row: ToolCallRow = {
        call_id, tool, args, sandboxed, container_id,
        status: "running", stdout: [], stderr: [], node: e.node,
      };
      return { ...inv, tool_calls: { ...inv.tool_calls, [call_id]: row } };
    }
    case "tool.stdout":
    case "tool.stderr": {
      const call_id = (d as { call_id: string }).call_id;
      const chunk = (d as { chunk: string }).chunk;
      const row = inv.tool_calls[call_id];
      if (!row) return inv;
      const key = e.type === "tool.stdout" ? "stdout" : "stderr";
      // Q9: cap the per-call line buffer so a chatty tool (e.g. a long
      // chainsaw scan) can't grow stdout/stderr unbounded and stall the
      // UI. Keep the most recent MAX_LINES, dropping oldest.
      const MAX_LINES = 200;
      const newLines = [...row[key], chunk];
      if (newLines.length > MAX_LINES) {
        newLines.splice(0, newLines.length - MAX_LINES);
      }
      return {
        ...inv,
        tool_calls: { ...inv.tool_calls, [call_id]: { ...row, [key]: newLines } },
      };
    }
    case "tool.progress": {
      // progress currently surfaces via tool_calls stdout; kept here for future UI hook
      return inv;
    }
    case "tool.end": {
      const call_id = (d as { call_id: string }).call_id;
      const exit_code = (d as { exit_code: number }).exit_code;
      const duration_s = (d as { duration_s: number }).duration_s;
      const output_hash = (d as { output_hash?: string }).output_hash;
      const ok = (d as { ok?: boolean }).ok ?? exit_code === 0;
      const row = inv.tool_calls[call_id];
      if (!row) return inv;
      return {
        ...inv,
        tool_calls: {
          ...inv.tool_calls,
          [call_id]: {
            ...row,
            status: ok ? "ok" : "error",
            exit_code, duration_s, output_hash,
          },
        },
      };
    }
    case "report.section_added": {
      const section_id = (d as { section_id: string }).section_id;
      const title = (d as { title: string }).title;
      const markdown = (d as { markdown: string }).markdown;
      const existingIdx = inv.report.findIndex((s) => s.section_id === section_id);
      const order = existingIdx >= 0 ? inv.report[existingIdx].order : inv.report.length;
      const section: ReportSection = { section_id, title, markdown, order };
      const report = existingIdx >= 0
        ? inv.report.map((s) => (s.section_id === section_id ? section : s))
        : [...inv.report, section];
      return { ...inv, report };
    }
    case "report.ioc": {
      // The agent emits a report.ioc event for every indicator it extracts.
      // Accumulate them onto the investigation for the IoC tab + STIX export.
      const ioc: IOC = {
        type: String((d as { type?: string }).type ?? "unknown"),
        value: String(
          (d as { value?: string }).value ??
          (d as { ioc?: string }).ioc ??
          (d as { indicator?: string }).indicator ?? "",
        ),
        description: (d as { description?: string }).description,
        mitre_tags: (d as { mitre_tags?: string[] }).mitre_tags,
        ts: e.ts,
        source: e.node ?? undefined,
      };
      return { ...inv, iocs: [...inv.iocs, ioc] };
    }
    case "report.timeline_entry": {
      // A timeline entry is one timestamped host/agent event. Kept in arrival
      // order; the TimelineView sorts by timestamp for display.
      const entry: TimelineEntry = {
        timestamp: String(
          (d as { timestamp?: string }).timestamp ??
          (d as { ts?: string }).ts ?? e.ts,
        ),
        source: String((d as { source?: string }).source ?? e.node ?? ""),
        actor: (d as { actor?: string }).actor,
        event: String(
          (d as { event?: string }).event ??
          (d as { description?: string }).description ?? "",
        ),
        description: (d as { description?: string }).description,
        mitre_tags: (d as { mitre_tags?: string[] }).mitre_tags,
        ts: e.ts,
      };
      return { ...inv, timeline: [...inv.timeline, entry] };
    }
    case "hitl.request": {
      const reason = (d as { reason: string }).reason;
      return {
        ...inv,
        status: "paused",
        trace: [...inv.trace, { id: uid(), ts: e.ts, kind: "hitl", text: `⏸ ${reason}` }],
      };
    }
    case "hitl.response": {
      // Q3 — the human's decision landed. Append an audit trace row and
      // clear the paused state immediately (the follow-up investigation.end
      // event then sets the final done/cancelled status).
      const approved = (d as { approved: boolean }).approved;
      const detail = (d as { detail?: string }).detail ?? "";
      const mark = approved ? "✓" : "✗";
      return {
        ...inv,
        status: "running",
        trace: [
          ...inv.trace,
          { id: uid(), ts: e.ts, kind: "hitl", text: `${mark} HITL ${detail || (approved ? "approved" : "rejected")}` },
        ],
      };
    }
    case "provenance.recorded": {
      const record = (d as { record: Record<string, unknown> }).record;
      return {
        ...inv,
        provenance_count: inv.provenance_count + 1,
        last_provenance: record,
      };
    }
    case "investigation.end": {
      const status = (d as { status: string }).status as Investigation["status"];
      announce(`Investigation ${status}`);
      return { ...inv, status, ended_at: new Date().toISOString() };
    }
    case "investigation.paused":
      return { ...inv, status: "paused" };
    case "investigation.resumed":
      return { ...inv, status: "running" };
    case "investigation.cancelled":
      return { ...inv, status: "cancelled", ended_at: new Date().toISOString() };
    default:
      return inv;
  }
}

// Goal labels for the fallback when the start event arrives before the goal list.
// Updated as we wire more goals.
const GOAL_LABEL_FALLBACK: Record<string, string> = {
  G01: "Windows attack timeline",
};

// Convenience selector hooks
export function useActiveInvestigation(): Investigation | null {
  return useEvents((s) => {
    const id = s.activeInvestigationId;
    return id ? s.investigations[id] || null : null;
  });
}
