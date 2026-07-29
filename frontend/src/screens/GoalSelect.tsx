// Screen 3 — Goal selection.
//
// Shows the 22 investigation goals as cards grouped by cluster. Goals whose
// input artifacts are present in the most recent scan are highlighted as
// "Recommended". Each card shows the artifacts it consumes + tools it calls.

import { useEffect, useState } from "react";
import { ChevronRight, Star, Cpu, Network, MemoryStick, Bug, Smartphone, Cloud, GitBranch, Box, Layers, CalendarClock } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Badge, Button, Card, CardBody } from "@/components/ui/primitives";
import { Screen } from "./ApiKeySetup";
import type { Artifact, GoalManifest } from "@/lib/types";

interface Props {
  onNext: () => void;
  onStart?: (goalId: string) => void;
}

// Cluster ordering + iconography. Each cluster's lucide icon.
const CLUSTER_META: { id: string; label: string; icon: typeof Cpu }[] = [
  { id: "Windows", label: "Windows", icon: Cpu },
  { id: "Endpoint", label: "Linux & macOS", icon: Layers },
  { id: "Memory", label: "Memory", icon: MemoryStick },
  { id: "Network", label: "Network", icon: Network },
  { id: "Ransomware", label: "Ransomware", icon: Bug },
  { id: "Email", label: "Email & comms", icon: Bug },
  { id: "Mobile", label: "Mobile", icon: Smartphone },
  { id: "Cloud", label: "Cloud", icon: Cloud },
  { id: "SaaS", label: "SaaS / DevOps", icon: GitBranch },
  { id: "Container", label: "Containers", icon: Box },
  { id: "Cross-cutting", label: "Cross-cutting", icon: CalendarClock },
];

export function GoalSelect({ onNext, onStart }: Props) {
  const [goals, setGoals] = useState<GoalManifest[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  // Evidence from the most recent scan — pulled fresh from the WS state indirectly
  // (kept simple: re-scan is explicit on screen 2; here we just take last result).
  const [lastArtifacts, setLastArtifacts] = useState<Artifact[]>([]);

  useEffect(() => {
    api.listGoals().then((r) => setGoals(r.goals));
  }, []);

  // Goal match: how many of its input_artifacts are present in lastArtifacts
  const presentArtifactIds = new Set(lastArtifacts.map((a) => a.artifact_id));
  const matchScore = (g: GoalManifest) =>
    g.input_artifacts.filter((a) => presentArtifactIds.has(a)).length;

  const grouped = groupByCluster(goals);
  const orderedClusters = CLUSTER_META.filter((c) => grouped[c.id]?.length);

  async function start() {
    if (!selected) return;
    if (onStart) {
      onStart(selected);
    } else {
      onNext();
    }
  }

  return (
    <Screen
      title="Pick an investigation goal"
      subtitle="Step 3 of 4 · What do you want the agent to find? Cards are highlighted when their inputs are present."
    >
      <div className="max-w-6xl space-y-2xl">
        {orderedClusters.length === 0 && (
          <div className="text-center py-2xl text-muted-fg">
            No goals registered yet. (M0 ships G01; the rest arrive in M1–M10.)
          </div>
        )}
        {orderedClusters.map(({ id, label, icon: Icon }) => (
          <section key={id}>
            <div className="flex items-center gap-md mb-md">
              <Icon className="h-4 w-4 text-muted-fg" aria-hidden />
              <h2 className="text-sm font-semibold uppercase tracking-wider">{label}</h2>
              <span className="text-2xs text-muted-fg">· {grouped[id].length} goal{grouped[id].length === 1 ? "" : "s"}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-md">
              {grouped[id].map((g) => {
                const score = matchScore(g);
                const recommended = score > 0;
                const isSelected = selected === g.id;
                return (
                  <button
                    key={g.id}
                    type="button"
                    onClick={() => setSelected(g.id)}
                    aria-pressed={isSelected}
                    className={cn(
                      "text-left rounded-md border transition-all cursor-pointer overflow-hidden",
                      isSelected
                        ? "border-accent bg-accent/10 shadow-md"
                        : recommended
                        ? "border-border bg-surface hover:border-accent/60"
                        : "border-border bg-surface/50 hover:border-muted-fg/40"
                    )}
                  >
                    <div className="px-lg py-md flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-md">
                          <span className="text-2xs font-mono text-muted-fg">{g.id}</span>
                          {recommended && (
                            <Badge tone="accent">
                              <Star className="h-2.5 w-2.5" /> {score}/{g.input_artifacts.length}
                            </Badge>
                          )}
                        </div>
                        <h3 className="text-sm font-medium mt-xs">{g.label}</h3>
                      </div>
                    </div>
                    <p className="px-lg pb-md text-xs text-muted-fg leading-relaxed line-clamp-3">
                      {g.description}
                    </p>
                    <div className="px-lg py-md border-t border-border/60 flex items-center justify-between text-2xs">
                      <div className="flex flex-wrap gap-1">
                        {g.input_artifacts.map((a) => (
                          <Badge
                            key={a}
                            tone={presentArtifactIds.has(a) ? "accent" : "muted"}
                          >
                            {a}
                          </Badge>
                        ))}
                      </div>
                      <span className="text-muted-fg">
                        {g.nodes.length} step{g.nodes.length === 1 ? "" : "s"}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </section>
        ))}

        <div className="sticky bottom-0 bg-background/95 backdrop-blur-sm border-t border-border py-md flex justify-end gap-sm">
          <Button variant="ghost" onClick={onNext}>Skip</Button>
          <Button variant="primary" onClick={start} disabled={!selected}>
            Start investigation <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </Screen>
  );
}

function groupByCluster(goals: GoalManifest[]): Record<string, GoalManifest[]> {
  const out: Record<string, GoalManifest[]> = {};
  for (const g of goals) {
    (out[g.cluster] = out[g.cluster] || []).push(g);
  }
  return out;
}
