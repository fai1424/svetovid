// Screen — Settings.
// Sandbox mode + HITL policy + knowledge-base versions + telemetry. Mirrors backend settings.

import { useEffect, useState } from "react";
import { Card, CardBody, CardHeader, Button, Badge } from "@/components/ui/primitives";
import { cn } from "@/lib/cn";
import { api } from "@/lib/api";
import { Screen } from "./ApiKeySetup";
import type { Settings as SettingsT, TelemetryStatus } from "@/lib/types";

export function Settings() {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [dirty, setDirty] = useState(false);
  const [telemetryStatus, setTelemetryStatus] = useState<TelemetryStatus | null>(null);

  useEffect(() => {
    api.getSettings().then(setSettings);
    api.telemetryStatus().then(setTelemetryStatus).catch(() => { /* optional */ });
  }, []);
  if (!settings) return <Screen title="Settings"><div className="text-muted-fg">Loading…</div></Screen>;

  function update<K extends keyof SettingsT>(key: K, value: SettingsT[K]) {
    setSettings({ ...settings!, [key]: value });
    setDirty(true);
  }

  async function save() {
    const s = await api.saveSettings(settings!);
    setSettings(s);
    setDirty(false);
  }

  async function reset() {
    if (!confirm("Reset all settings and provider keys?")) return;
    const s = await api.resetSettings();
    setSettings(s);
  }

  return (
    <Screen title="Settings" subtitle="Sandbox mode, HITL policy, knowledge-base versions.">
      <div className="max-w-3xl space-y-md">
        <Card>
          <CardHeader><h2 className="text-sm font-semibold uppercase tracking-wider">Sandbox</h2></CardHeader>
          <CardBody className="space-y-md">
            <Field label="Sandbox mode">
              <select
                className="h-9 px-md bg-background border border-border rounded-md text-sm font-mono"
                value={settings.sandbox_mode}
                onChange={(e) => update("sandbox_mode", e.target.value as SettingsT["sandbox_mode"])}
              >
                <option value="docker">docker — per-call container, evidence :ro</option>
                <option value="host_subprocess">host_subprocess — no isolation, :ro enforced</option>
                <option value="disabled">disabled — not recommended</option>
              </select>
            </Field>
            <p className="text-2xs text-muted-fg">
              Docker is strongly recommended — forensic parsers routinely process untrusted input.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><h2 className="text-sm font-semibold uppercase tracking-wider">Human-in-the-loop policy</h2></CardHeader>
          <CardBody className="space-y-md">
            <Field label="Evidence collection">
              <HitlSelect value={settings.hitl_evidence_collection} onChange={(v) => update("hitl_evidence_collection", v)} />
            </Field>
            <Field label="Tool execution">
              <HitlSelect value={settings.hitl_tool_execution} onChange={(v) => update("hitl_tool_execution", v)} />
            </Field>
            <Field label="Report release">
              <HitlSelect value={settings.hitl_report_release} onChange={(v) => update("hitl_report_release", v)} />
            </Field>
            <p className="text-2xs text-muted-fg">
              Per DoD/CISA 2026 + NIST CAISI guidance — collection and report release should stay <code>required</code>.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><h2 className="text-sm font-semibold uppercase tracking-wider">Knowledge bases</h2></CardHeader>
          <CardBody className="space-y-md">
            <Field label="MITRE ATT&CK version">
              <input
                className="h-9 px-md w-32 bg-background border border-border rounded-md text-sm font-mono"
                value={settings.attack_version}
                onChange={(e) => update("attack_version", e.target.value)}
              />
            </Field>
            <Field label="Sigma rules path">
              <input
                className="h-9 px-md flex-1 bg-background border border-border rounded-md text-sm font-mono"
                value={settings.sigma_rules_path}
                onChange={(e) => update("sigma_rules_path", e.target.value)}
              />
            </Field>
            <Badge tone="muted">baked into svetovid/eztools image</Badge>
          </CardBody>
        </Card>

        <Card>
          <CardHeader className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider">Usage analytics</h2>
            {telemetryStatus && (
              <Badge tone={telemetryStatus.enabled ? "accent" : "muted"}>
                {telemetryStatus.enabled ? "on" : "off"} · {telemetryStatus.queued_count} queued
              </Badge>
            )}
          </CardHeader>
          <CardBody className="space-y-md">
            <Field label="Anonymous telemetry">
              <button
                type="button"
                role="switch"
                aria-checked={settings.telemetry_enabled}
                onClick={() => update("telemetry_enabled", !settings.telemetry_enabled)}
                className={cnSwitch(settings.telemetry_enabled)}
              >
                <span
                  className={cn(
                    "inline-block h-4 w-4 rounded-full bg-background shadow-sm transition-transform",
                    settings.telemetry_enabled ? "translate-x-5" : "translate-x-0.5"
                  )}
                />
              </button>
              <span className="text-xs text-foreground">
                {settings.telemetry_enabled ? "Enabled" : "Disabled"}
              </span>
            </Field>
            <Field label="Collection endpoint">
              <input
                className="h-9 px-md flex-1 bg-background border border-border rounded-md text-sm font-mono"
                placeholder="https://analytics.your-org.example/api/v1/telemetry"
                value={settings.telemetry_endpoint}
                onChange={(e) => update("telemetry_endpoint", e.target.value)}
              />
            </Field>
            <p className="text-2xs text-muted-fg leading-relaxed">
              When enabled, Svetovid records <strong>anonymous, aggregate</strong> usage metrics
              (goal id, duration, tool success rate, iteration count, your rating) to help
              improve the tool. Records are queued locally and uploaded to the endpoint above
              only if you set one. <strong>Never</strong> collected: evidence content, file
              paths, command arguments, LLM prompts/responses, API keys, or any user identity.
              Toggle off any time — existing queued data stays local until removed.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><h2 className="text-sm font-semibold uppercase tracking-wider">Reset</h2></CardHeader>
          <CardBody>
            <Button variant="destructive" onClick={reset}>Erase all settings and keys</Button>
          </CardBody>
        </Card>

        <div className="sticky bottom-0 bg-background/95 backdrop-blur-sm border-t border-border py-md flex justify-end gap-sm">
          <Button variant="ghost" onClick={() => { api.getSettings().then(setSettings); setDirty(false); }} disabled={!dirty}>
            Discard
          </Button>
          <Button variant="primary" onClick={save} disabled={!dirty}>Save</Button>
        </div>
      </div>
    </Screen>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-md">
      <label className="text-xs uppercase tracking-wider text-muted-fg w-48 shrink-0">{label}</label>
      <div className="flex-1 flex items-center gap-md">{children}</div>
    </div>
  );
}

function HitlSelect({ value, onChange }: { value: string; onChange: (v: "required" | "advisory" | "off") => void }) {
  return (
    <select
      className="h-9 px-md bg-background border border-border rounded-md text-sm font-mono"
      value={value}
      onChange={(e) => onChange(e.target.value as "required" | "advisory" | "off")}
    >
      <option value="required">required — agent pauses for approval</option>
      <option value="advisory">advisory — agent proceeds with warning</option>
      <option value="off">off — full autonomous</option>
    </select>
  );
}

// Class builder for the telemetry toggle switch track.
function cnSwitch(on: boolean): string {
  return cn(
    "relative inline-flex h-5 w-10 items-center rounded-full transition-colors cursor-pointer",
    "focus-visible:outline-2 focus-visible:outline-[var(--color-ring)] focus-visible:outline-offset-2",
    on ? "bg-accent" : "bg-muted"
  );
}
