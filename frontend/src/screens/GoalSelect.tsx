// Screen 3 — Investigation request.
//
// Two modes:
//   1. "Describe" (primary): user types what happened in plain language.
//      The planner LLM evaluates and suggests a goal + customized plan.
//      User reviews the suggestion, then starts.
//   2. "Browse goals" (fallback): the old card grid, for when the user
//      knows exactly which goal they want.

import { useEffect, useState } from "react";
import {
  ChevronRight, Sparkles, Eye, Loader2, Wand2,
  Cpu, Network, MemoryStick, Bug, Smartphone, Cloud, GitBranch, Box, Layers, CalendarClock,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Badge, Button, Card, CardBody, CardHeader } from "@/components/ui/primitives";
import { Screen } from "./ApiKeySetup";
import type { Artifact, GoalManifest } from "@/lib/types";

interface Props {
  onNext: () => void;
}

interface PlanResult {
  goal_id: string;
  goal_label: string;
  goal_description: string;
  user_prompt: string;
  confidence: number;
  reasoning: string;
  suggested_tools: string[];
  evidence_found: number;
}

const SUGGESTIONS = [
  "Our Windows server was compromised. Find the attack timeline and identify any malware.",
  "We captured network traffic during an incident. Identify the C2 server and what data was exfiltrated.",
  "A container in our Kubernetes cluster is acting suspiciously. Analyze the CRIU checkpoint.",
  "We received a suspicious email. Check if it's phishing and trace any attachments.",
  "Our M365 tenant may be compromised. Check for mailbox takeover and unauthorized access.",
  "Ransomware encrypted our files. Identify the strain and check if decryption is possible.",
];

export function GoalSelect({ onNext }: Props) {
  const [mode, setMode] = useState<"describe" | "browse">("describe");
  const [request, setRequest] = useState("");
  const [evidencePath, setEvidencePath] = useState("");
  const [planning, setPlanning] = useState(false);
  const [plan, setPlan] = useState<PlanResult | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [goals, setGoals] = useState<GoalManifest[]>([]);

  useEffect(() => {
    api.listGoals().then((r) => setGoals(r.goals));
    // Try to get the evidence path from the scan we just did
    api.getSettings().then(() => {
      // Evidence path should be passed from the previous screen;
      // for now, leave empty — the smart endpoint accepts it
    });
  }, []);

  async function startDynamic() {
    if (!request.trim() || !evidencePath.trim()) return;
    setStarting(true);
    try {
      await api.smartInvestigation(request, evidencePath);
      onNext();
    } catch (e) {
      setPlanError(e instanceof Error ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  }

  async function planInvestigation() {
    if (!request.trim() || !evidencePath.trim()) return;
    setPlanning(true);
    setPlan(null);
    setPlanError(null);
    try {
      const result = await api.planInvestigation(request, evidencePath);
      setPlan(result);
    } catch (e) {
      setPlanError(e instanceof Error ? e.message : String(e));
    } finally {
      setPlanning(false);
    }
  }

  async function startWithPlan() {
    if (!plan || !evidencePath) return;
    setStarting(true);
    try {
      await api.startInvestigation(plan.goal_id, evidencePath, plan.user_prompt);
      onNext();
    } finally {
      setStarting(false);
    }
  }

  async function startWithGoal(goalId: string) {
    if (!evidencePath) return;
    setStarting(true);
    try {
      await api.startInvestigation(goalId, evidencePath, request);
      onNext();
    } finally {
      setStarting(false);
    }
  }

  // === Describe mode ===
  if (mode === "describe") {
    return (
      <Screen
        title="Describe what happened"
        subtitle="Tell the agent what to investigate. It will examine the evidence and build its own investigation plan."
      >
        <div className="max-w-3xl space-y-md">
          {/* Evidence path */}
          <Card>
            <CardBody>
              <label className="block text-xs uppercase tracking-wider text-muted-fg mb-1">
                Evidence folder
              </label>
              <input
                type="text"
                value={evidencePath}
                onChange={(e) => setEvidencePath(e.target.value)}
                placeholder="/path/to/evidence"
                className="w-full h-9 px-md bg-background border border-border rounded-md font-mono text-sm"
              />
            </CardBody>
          </Card>

          {/* Request textarea */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-md">
                <Wand2 className="h-4 w-4 text-accent" />
                <h2 className="text-sm font-semibold uppercase tracking-wider">
                  What do you want to investigate?
                </h2>
              </div>
            </CardHeader>
            <CardBody className="space-y-md">
              <textarea
                value={request}
                onChange={(e) => setRequest(e.target.value)}
                placeholder="Describe the incident... e.g. 'Our postgres container is mining crypto. Find the C2 server, the initial access vector, and what processes the attacker executed.'"
                rows={4}
                className="w-full px-md py-md bg-background border border-border rounded-md font-mono text-sm resize-none focus:outline-none focus:border-accent"
                autoFocus
              />

              {/* Quick suggestions */}
              <div className="flex flex-wrap gap-xs">
                {SUGGESTIONS.map((s, i) => (
                  <button
                    key={i}
                    onClick={() => setRequest(s)}
                    className="text-2xs px-md py-sm bg-muted text-muted-fg rounded-md hover:text-foreground hover:bg-secondary transition-colors cursor-pointer"
                  >
                    {s.length > 60 ? s.slice(0, 60) + "…" : s}
                  </button>
                ))}
              </div>

              <div className="flex items-center justify-between pt-sm border-t border-border">
                <button
                  onClick={() => setMode("browse")}
                  className="text-2xs text-muted-fg hover:text-foreground transition-colors cursor-pointer"
                >
                  Or browse all 23 goals manually →
                </button>
                <div className="flex items-center gap-sm">
                  <Button
                    variant="ghost"
                    onClick={planInvestigation}
                    disabled={!request.trim() || !evidencePath.trim() || planning}
                    loading={planning}
                  >
                    {!planning && <Sparkles className="h-3.5 w-3.5" />}
                    {planning ? "Analyzing…" : "Suggest goal"}
                  </Button>
                  <Button
                    variant="primary"
                    onClick={startDynamic}
                    disabled={!request.trim() || !evidencePath.trim() || starting}
                    loading={starting}
                  >
                    Start investigation
                  </Button>
                </div>
              </div>
            </CardBody>
          </Card>

          {/* Plan result */}
          {planError && (
            <Card className="border-destructive/50">
              <CardBody className="text-sm text-destructive">{planError}</CardBody>
            </Card>
          )}

          {plan && (
            <Card className="border-accent/40 animate-slide-up">
              <CardHeader>
                <div className="flex items-center gap-md">
                  <Sparkles className="h-4 w-4 text-accent" />
                  <h2 className="text-sm font-semibold uppercase tracking-wider">
                    Suggested investigation
                  </h2>
                  <Badge tone={plan.confidence > 0.7 ? "accent" : "warning"}>
                    {Math.round(plan.confidence * 100)}% confidence
                  </Badge>
                </div>
              </CardHeader>
              <CardBody className="space-y-md">
                <div>
                  <div className="flex items-center gap-md mb-xs">
                    <span className="font-mono text-2xs text-muted-fg">{plan.goal_id}</span>
                    <span className="text-sm font-medium">{plan.goal_label}</span>
                  </div>
                  <p className="text-xs text-muted-fg leading-relaxed">
                    {plan.reasoning}
                  </p>
                </div>

                {plan.user_prompt !== request && (
                  <div className="p-md bg-muted rounded-md">
                    <p className="text-2xs uppercase tracking-wider text-muted-fg mb-xs">
                      Refined prompt for the agent
                    </p>
                    <p className="text-xs font-mono leading-relaxed text-foreground">
                      {plan.user_prompt}
                    </p>
                  </div>
                )}

                {plan.suggested_tools.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {plan.suggested_tools.map((t) => (
                      <Badge key={t} tone="muted">{t}</Badge>
                    ))}
                  </div>
                )}

                {plan.evidence_found > 0 && (
                  <p className="text-2xs text-muted-fg">
                    {plan.evidence_found} artifact(s) detected in evidence folder
                  </p>
                )}

                <div className="flex items-center justify-between pt-sm border-t border-border">
                  <button
                    onClick={() => setPlan(null)}
                    className="text-xs text-muted-fg hover:text-foreground cursor-pointer"
                  >
                    ← Try a different description
                  </button>
                  <div className="flex items-center gap-sm">
                    <Button variant="ghost" onClick={() => setMode("browse")}>
                      <Eye className="h-3.5 w-3.5" /> Change goal
                    </Button>
                    <Button
                      variant="primary"
                      onClick={startWithPlan}
                      loading={starting}
                    >
                      Start investigation <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardBody>
            </Card>
          )}

          {planning && !plan && (
            <Card className="border-dashed">
              <CardBody className="flex items-center gap-md text-sm text-muted-fg">
                <Loader2 className="h-4 w-4 animate-spin text-accent" />
                Analyzing your request and matching to investigation goals…
              </CardBody>
            </Card>
          )}
        </div>
      </Screen>
    );
  }

  // === Browse mode (legacy card grid) ===
  return (
    <BrowseGoals
      goals={goals}
      evidencePath={evidencePath}
      setEvidencePath={setEvidencePath}
      onStart={startWithGoal}
      onBackToDescribe={() => setMode("describe")}
      onNext={onNext}
      starting={starting}
    />
  );
}

// ---------------------------------------------------------------------------
// Legacy browse-goals grid (preserved as fallback)
// ---------------------------------------------------------------------------

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

function BrowseGoals({
  goals, evidencePath, setEvidencePath, onStart, onBackToDescribe, onNext, starting,
}: {
  goals: GoalManifest[];
  evidencePath: string;
  setEvidencePath: (v: string) => void;
  onStart: (goalId: string) => void;
  onBackToDescribe: () => void;
  onNext: () => void;
  starting: boolean;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const grouped: Record<string, GoalManifest[]> = {};
  for (const g of goals) (grouped[g.cluster] = grouped[g.cluster] || []).push(g);
  const orderedClusters = CLUSTER_META.filter((c) => grouped[c.id]?.length);

  return (
    <Screen
      title="Pick an investigation goal"
      subtitle="Or switch back to natural-language mode"
    >
      <div className="max-w-6xl space-y-2xl">
        <div className="flex items-center justify-between">
          <button
            onClick={onBackToDescribe}
            className="text-xs text-accent hover:underline cursor-pointer"
          >
            ← Back to describe mode
          </button>
        </div>

        <Card>
          <CardBody>
            <label className="block text-xs uppercase tracking-wider text-muted-fg mb-1">
              Evidence folder
            </label>
            <input
              type="text"
              value={evidencePath}
              onChange={(e) => setEvidencePath(e.target.value)}
              placeholder="/path/to/evidence"
              className="w-full h-9 px-md bg-background border border-border rounded-md font-mono text-sm"
            />
          </CardBody>
        </Card>

        {orderedClusters.map(({ id, label, icon: Icon }) => (
          <section key={id}>
            <div className="flex items-center gap-md mb-md">
              <Icon className="h-4 w-4 text-muted-fg" />
              <h2 className="text-sm font-semibold uppercase tracking-wider">{label}</h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-md">
              {(grouped[id] || []).map((g) => (
                <button
                  key={g.id}
                  onClick={() => setSelected(g.id)}
                  className={cn(
                    "text-left rounded-md border transition-all cursor-pointer overflow-hidden p-md",
                    selected === g.id
                      ? "border-accent bg-accent/10 shadow-md"
                      : "border-border bg-surface hover:border-muted-fg/40"
                  )}
                >
                  <span className="text-2xs font-mono text-muted-fg">{g.id}</span>
                  <h3 className="text-sm font-medium mt-xs">{g.label}</h3>
                  <p className="text-xs text-muted-fg mt-xs line-clamp-3">{g.description}</p>
                </button>
              ))}
            </div>
          </section>
        ))}

        <div className="sticky bottom-0 bg-background/95 backdrop-blur-sm border-t border-border py-md flex justify-end gap-sm">
          <Button variant="ghost" onClick={onNext}>Skip</Button>
          <Button variant="primary" onClick={() => selected && onStart(selected)} disabled={!selected || !evidencePath || starting} loading={starting}>
            Start investigation <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </Screen>
  );
}
