// REST client. In Vite dev, requests proxy through :1420 → :7421.
// In Tauri production, the window origin is tauri://localhost (not the backend),
// so we target the backend's loopback address directly.

import type { Artifact, GoalManifest, Settings, TestConnectionResult, ProviderId, TelemetryStatus } from "./types";

const base =
  window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? ""  // same-origin → Vite proxy handles it
    : "http://127.0.0.1:7421";  // Tauri production → direct to backend

// Auth token — fetched once from /api/auth-token (localhost-only exchange).
let authToken: string | null = null;

export async function fetchAuthToken(): Promise<string | null> {
  if (authToken) return authToken;
  try {
    const resp = await fetch(base + "/api/auth-token");
    if (resp.ok) {
      authToken = (await resp.json()).token;
    }
  } catch {
    // Dev without backend — auth will fail gracefully
  }
  return authToken;
}

async function getToken(): Promise<string | null> {
  return fetchAuthToken();
}

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getToken();
  const resp = await fetch(base + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
  });
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = await resp.json();
      detail = body.detail || detail;
    } catch {
      /* swallow */
    }
    throw new Error(detail);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  health: () => jsonFetch<{ ok: boolean; version: string; active_provider: string | null }>(
    "/health"
  ),

  getSettings: () => jsonFetch<Settings>("/api/settings"),

  saveSettings: (s: Partial<Settings>) =>
    jsonFetch<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(s) }),

  resetSettings: () => jsonFetch<Settings>("/api/settings/reset", { method: "POST" }),

  testProvider: (id: ProviderId) =>
    jsonFetch<TestConnectionResult>(`/api/providers/${id}/test`, { method: "POST" }),

  scan: (path: string) =>
    jsonFetch<{ artifacts: Artifact[] }>("/api/scan", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),

  listGoals: () => jsonFetch<{ goals: GoalManifest[] }>("/api/goals"),

  startInvestigation: (goal_id: string, evidence_path: string, user_prompt = "") =>
    jsonFetch<{ investigation_id: string; goal_id: string }>("/api/investigations", {
      method: "POST",
      body: JSON.stringify({ goal_id, evidence_path, user_prompt }),
    }),

  planInvestigation: (request: string, evidence_path: string) =>
    jsonFetch<{
      goal_id: string;
      goal_label: string;
      goal_description: string;
      user_prompt: string;
      confidence: number;
      reasoning: string;
      suggested_tools: string[];
      evidence_found: number;
    }>("/api/investigations/plan", {
      method: "POST",
      body: JSON.stringify({ request, evidence_path }),
    }),

  smartInvestigation: (request: string, evidence_path: string) =>
    jsonFetch<{ investigation_id: string; goal_id: string; confidence: number }>(
      "/api/investigations/smart",
      { method: "POST", body: JSON.stringify({ request, evidence_path }) },
    ),

  // Q3 — Human-in-the-loop approval gate. The Approve button POSTs
  // {"approved": true}, the Reject button POSTs {"approved": false}. The
  // backend resolves the pending Future the goal coroutine is awaiting.
  hitlResponse: (investigation_id: string, approved: boolean) =>
    jsonFetch<{ investigation_id: string; resolved: boolean; approved: boolean }>(
      `/api/investigations/${investigation_id}/hitl`,
      { method: "POST", body: JSON.stringify({ approved }) },
    ),

  rateInvestigation: (investigation_id: string, rating: number, feedback = "") =>
    jsonFetch<{ ok: boolean }>("/api/telemetry/rate", {
      method: "POST",
      body: JSON.stringify({ investigation_id, rating, feedback }),
    }),

  telemetryStatus: () => jsonFetch<TelemetryStatus>("/api/telemetry/status"),

  // Report export — returns the raw Response so the caller can read it as
  // text (markdown/json/stix/case) or a blob (pdf). Auth header attached.
  exportInvestigation: async (invId: string, format: string): Promise<Response> => {
    const token = await getToken();
    return fetch(base + `/api/investigations/${invId}/export?format=${format}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  },
};
