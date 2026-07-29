// Screen 1 — API Key setup.
//
// Pick a provider (Ollama / GLM / KIMI), enter base_url + api_key + model,
// hit Test-connection. The active provider is set on Save. Status indicator
// (✓ connected / ✗ auth failed / ⚠ unreachable) gives live feedback.

import { useEffect, useState } from "react";
import { CheckCircle2, AlertCircle, WifiOff, Loader2, ChevronRight } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Button, Card, CardBody, CardHeader, Input, Label, Badge } from "@/components/ui/primitives";
import type { Provider, ProviderId, Settings as SettingsT, TestConnectionResult } from "@/lib/types";

interface Props {
  onNext: () => void;
}

const PROVIDER_BLURB: Record<ProviderId, string> = {
  ollama: "Local models. Data never leaves your machine. Slower tool-calling; pick a model ≥8B.",
  glm: "Zhipu BigModel (GLM-4 family). Strong Chinese-language incident reports.",
  kimi: "Moonshot KIMI. Long context (128k+) — good for large timelines.",
};

export function ApiKeySetup({ onNext }: Props) {
  const [settings, setSettings] = useState<SettingsT | null>(null);
  const [activeId, setActiveId] = useState<ProviderId | null>(null);
  const [edits, setEdits] = useState<Record<ProviderId, Partial<Provider>> | null>(null);
  const [testing, setTesting] = useState<ProviderId | null>(null);
  const [results, setResults] = useState<Record<ProviderId, TestConnectionResult | null>>(
    {} as Record<ProviderId, TestConnectionResult | null>
  );
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    api.getSettings().then((s) => {
      setSettings(s);
      setActiveId(s.active_provider);
      setEdits({
        ollama: { ...s.providers.ollama },
        glm: { ...s.providers.glm },
        kimi: { ...s.providers.kimi },
      });
    });
  }, []);

  if (!settings || !edits) {
    return <ScreenSkeleton />;
  }

  const active = activeId ? edits[activeId] : null;

  async function save() {
    if (!settings || !edits || !activeId) return;
    setSaving(true);
    const updated: SettingsT = {
      ...settings,
      active_provider: activeId,
      providers: {
        ollama: { ...settings.providers.ollama, ...edits.ollama } as Provider,
        glm: { ...settings.providers.glm, ...edits.glm } as Provider,
        kimi: { ...settings.providers.kimi, ...edits.kimi } as Provider,
      },
    };
    try {
      const saved = await api.saveSettings(updated);
      setSettings(saved);
      setEdits({
        ollama: { ...saved.providers.ollama },
        glm: { ...saved.providers.glm },
        kimi: { ...saved.providers.kimi },
      });
    } finally {
      setSaving(false);
    }
  }

  async function test(id: ProviderId) {
    if (!edits) return;
    // Save first so the backend hits the right credentials
    setTesting(id);
    try {
      await api.saveSettings({
        providers: { [id]: edits[id] } as unknown as Record<ProviderId, Provider>,
        active_provider: id,
      });
      const r = await api.testProvider(id);
      setResults((prev) => ({ ...prev, [id]: r }));
      // Sync the masked key back if backend wrote one
      const fresh = await api.getSettings();
      setSettings(fresh);
      setEdits({
        ollama: { ...fresh.providers.ollama },
        glm: { ...fresh.providers.glm },
        kimi: { ...fresh.providers.kimi },
      });
    } finally {
      setTesting(null);
    }
  }

  return (
    <Screen title="Connect a model" subtitle="Step 1 of 4 · Choose an LLM provider and verify reachability.">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-md max-w-5xl">
        {/* Provider picker */}
        <div className="lg:col-span-1 flex flex-col gap-md">
          {(["ollama", "glm", "kimi"] as ProviderId[]).map((pid) => {
            const p = edits[pid];
            const isActive = activeId === pid;
            const r = results[pid];
            return (
              <button
                key={pid}
                type="button"
                onClick={() => setActiveId(pid)}
                className={cn(
                  "text-left p-md rounded-md border transition-all cursor-pointer",
                  isActive
                    ? "border-accent bg-accent/10"
                    : "border-border bg-surface hover:border-muted-fg/50"
                )}
                aria-pressed={isActive}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold uppercase tracking-wider">{p.label}</span>
                  {r && <ConnectionBadge r={r} />}
                </div>
                <p className="mt-xs text-xs text-muted-fg leading-relaxed">
                  {PROVIDER_BLURB[pid]}
                </p>
                <p className="mt-sm text-2xs text-muted-fg">
                  <span className="text-muted-fg/70">model:</span> {p.model || "—"}
                </p>
              </button>
            );
          })}
        </div>

        {/* Active provider config form */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wider">
                {active ? active.label : "Select a provider"}
              </h2>
              {active && (
                <Badge tone={active.api_key ? "accent" : "muted"}>
                  {active.api_key ? "key set" : "no key"}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardBody className="space-y-md">
            {!active && (
              <p className="text-sm text-muted-fg">Pick a provider on the left to configure.</p>
            )}
            {active && activeId && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-md">
                  <div>
                    <Label htmlFor="base_url">Base URL</Label>
                    <Input
                      id="base_url"
                      value={active.base_url || ""}
                      onChange={(e) =>
                        setEdits({
                          ...edits,
                          [activeId]: { ...active, base_url: e.target.value },
                        })
                      }
                      placeholder="https://…"
                      autoCorrect="off"
                      spellCheck={false}
                    />
                  </div>
                  <div>
                    <Label htmlFor="model">Model</Label>
                    <Input
                      id="model"
                      value={active.model || ""}
                      onChange={(e) =>
                        setEdits({
                          ...edits,
                          [activeId]: { ...active, model: e.target.value },
                        })
                      }
                      placeholder="model name"
                      autoCorrect="off"
                      spellCheck={false}
                    />
                  </div>
                </div>
                <div>
                  <Label htmlFor="api_key">API key</Label>
                  <Input
                    id="api_key"
                    type="password"
                    value={active.api_key && active.api_key !== "***" ? active.api_key : ""}
                    placeholder={active.api_key === "***" ? "stored in keyring — type to replace" : "paste key"}
                    onChange={(e) =>
                      setEdits({
                        ...edits,
                        [activeId]: { ...active, api_key: e.target.value },
                      })
                    }
                    autoComplete="off"
                  />
                  <p className="mt-xs text-2xs text-muted-fg">
                    Keys are stored in your OS keyring, never in the config file.
                  </p>
                </div>

                {results[activeId] && (
                  <ResultLine r={results[activeId]!} />
                )}

                <div className="flex items-center justify-between pt-md border-t border-border">
                  <Button variant="ghost" onClick={() => test(activeId)} loading={testing === activeId}>
                    {!testing && <WifiOff className="h-3.5 w-3.5" />}
                    Test connection
                  </Button>
                  <div className="flex items-center gap-sm">
                    <Button onClick={save} loading={saving}>Save</Button>
                    <Button
                      variant="primary"
                      onClick={onNext}
                      disabled={!active.base_url || !active.model}
                    >
                      Continue <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardBody>
        </Card>
      </div>
    </Screen>
  );
}

function ConnectionBadge({ r }: { r: TestConnectionResult }) {
  if (r.ok) {
    return (
      <Badge tone="accent">
        <CheckCircle2 className="h-3 w-3" /> ok
      </Badge>
    );
  }
  if (r.status === "auth_failed") {
    return (
      <Badge tone="danger">
        <AlertCircle className="h-3 w-3" /> auth
      </Badge>
    );
  }
  return (
    <Badge tone="warning">
      <WifiOff className="h-3 w-3" /> {r.status}
    </Badge>
  );
}

function ResultLine({ r }: { r: TestConnectionResult }) {
  const tone = r.ok ? "text-status-done" : r.status === "auth_failed" ? "text-destructive" : "text-status-pending";
  const Icon = r.ok ? CheckCircle2 : r.status === "auth_failed" ? AlertCircle : WifiOff;
  return (
    <div className={cn("flex items-center gap-md text-xs", tone)}>
      <Icon className="h-3.5 w-3.5" />
      <span>{r.detail}</span>
      {r.models.length > 0 && (
        <span className="text-muted-fg">· {r.models.length} models</span>
      )}
    </div>
  );
}

export function Screen({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="h-full overflow-auto">
      <header className="px-2xl py-xl border-b border-border sticky top-0 bg-background/95 backdrop-blur-sm z-10">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-muted-fg mt-xs">{subtitle}</p>}
      </header>
      <div className="p-2xl">{children}</div>
    </div>
  );
}

function ScreenSkeleton() {
  return (
    <div className="h-full flex items-center justify-center text-muted-fg gap-md">
      <Loader2 className="h-4 w-4 animate-spin" />
      <span className="text-sm">Loading…</span>
    </div>
  );
}
