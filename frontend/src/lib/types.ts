// Shared types — mirror of backend pydantic models. Hand-maintained so changes
// are visible in review (codegen would couple too tightly for v1).

export type ProviderId = "ollama" | "glm" | "kimi";

export interface Provider {
  id: ProviderId;
  label: string;
  base_url: string;
  api_key: string; // empty = not set; "***" = set (never returned in cleartext from server)
  model: string;
  temperature: number;
  max_tokens: number | null;
}

export interface Settings {
  providers: Record<ProviderId, Provider>;
  active_provider: ProviderId | null;
  sandbox_mode: "docker" | "host_subprocess" | "disabled";
  docker_image_prefix: string;
  hitl_evidence_collection: "required" | "advisory" | "off";
  hitl_report_release: "required" | "advisory" | "off";
  hitl_tool_execution: "required" | "advisory" | "off";
  attack_version: string;
  sigma_rules_path: string;
  telemetry_enabled: boolean;
  telemetry_endpoint: string;
}

export interface TestConnectionResult {
  ok: boolean;
  status:
    | "connected"
    | "connected_model_missing"
    | "auth_failed"
    | "unreachable"
    | "timeout"
    | "http_error"
    | "bad_json"
    | "misconfigured"
    | "error"
    | "no_active";
  detail: string;
  models: string[];
}

export interface TelemetryStatus {
  enabled: boolean;
  endpoint: string;
  queued_count: number;
}

export interface Artifact {
  artifact_id: string;        // B-family research id
  family: string;
  kind: string;               // detector name (evtx, pcap, memory, ...)
  path: string;
  size_bytes: number;
  extra: Record<string, unknown>;
  goals: string[];            // G-ids this artifact feeds
}

export interface GoalNode {
  id: string;
  label: string;
  status: NodeStatus;
}

export type NodeStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface GoalManifest {
  id: string;
  cluster: string;
  label: string;
  description: string;
  input_artifacts: string[];
  tools: string[];
  icon: string;
  nodes: { id: string; label: string }[];
}

// ---------------------------------------------------------------------------
// Streaming events (mirror of backend agent/events.py)
// ---------------------------------------------------------------------------

export interface AgentEvent<T = Record<string, unknown>> {
  type: string;
  ts: string;
  case_id?: string | null;
  investigation_id?: string | null;
  node?: string | null;
  data: T;
}

export interface ToolCallRow {
  call_id: string;
  tool: string;
  args: Record<string, unknown>;
  sandboxed: boolean;
  container_id: string | null;
  status: "running" | "ok" | "error" | "timeout" | "cancelled";
  exit_code?: number;
  duration_s?: number;
  output_hash?: string | null;
  stdout: string[];   // accumulated stdout chunks
  stderr: string[];
  node?: string | null;
}

export interface TraceRow {
  id: string;
  ts: string;
  kind: "thought" | "action" | "observation" | "error" | "hitl" | "checkpoint" | "tool";
  text: string;
  tool?: string;
  call_id?: string;
}

export interface ReportSection {
  section_id: string;
  title: string;
  markdown: string;
  order: number;
}

// An indicator of compromise surfaced by the agent. The shape mirrors the
// ``report.ioc`` event payload: a free-form type (ipv4 / sha256 / url / ...)
// plus a value and optional context. mitre_tags link the IOC to ATT&CK.
export interface IOC {
  type: string;
  value: string;
  description?: string;
  mitre_tags?: string[];
  ts?: string;
  source?: string;
}

// One entry on the investigation timeline. Either an actual timestamped
// host event (from Chainsaw/Hayabusa/Volatility) or an agent-synthesized
// correlation point. mitre_tags carry the ATT&CK technique badge(s).
export interface TimelineEntry {
  timestamp: string;
  source: string;
  actor?: string;
  event: string;
  description?: string;
  mitre_tags?: string[];
  ts?: string;
}

export interface Investigation {
  id: string;
  goal_id: string;
  goal_label: string;
  status: "running" | "done" | "failed" | "cancelled" | "paused";
  started_at: string;
  ended_at?: string;
  nodes: GoalNode[];
  trace: TraceRow[];
  tool_calls: Record<string, ToolCallRow>;
  report: ReportSection[];
  iocs: IOC[];
  timeline: TimelineEntry[];
  provenance_count: number;
  last_provenance?: Record<string, unknown>;
}
