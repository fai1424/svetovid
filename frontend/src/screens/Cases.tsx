// Screen — Cases (multi-case DB).
// M0 minimal: lists investigations the WS store has seen this session.
// M0.5+ persists to a case DB on disk so they survive restart.

import { FolderOpen } from "lucide-react";
import { Card, CardBody, Badge } from "@/components/ui/primitives";
import { Screen } from "./ApiKeySetup";
import { useEvents } from "@/lib/events";

export function Cases() {
  const investigations = useEvents((s) => s.investigations);
  const setActive = useEvents((s) => s.setActive);
  const list = Object.values(investigations).sort((a, b) =>
    a.started_at < b.started_at ? 1 : -1
  );

  return (
    <Screen
      title="Cases"
      subtitle="Investigations this session. Persisted-to-disk case DB lands in M0.5."
    >
      <div className="max-w-3xl space-y-md">
        {list.length === 0 && (
          <Card className="border-dashed">
            <CardBody className="text-center py-2xl text-muted-fg">
              <FolderOpen className="h-8 w-8 mx-auto mb-md opacity-50" />
              <p className="text-sm">No cases yet. Start one from the Goal screen.</p>
            </CardBody>
          </Card>
        )}
        {list.map((inv) => (
          <Card key={inv.id}>
            <CardBody className="flex items-center gap-md">
              <div className="flex-1">
                <div className="flex items-center gap-md">
                  <span className="font-mono text-2xs text-muted-fg">{inv.id}</span>
                  <Badge tone="muted">{inv.goal_id}</Badge>
                </div>
                <h3 className="text-sm mt-xs">{inv.goal_label}</h3>
                <p className="text-2xs text-muted-fg mt-xs">
                  {new Date(inv.started_at).toLocaleString()} · {inv.trace.length} events · {Object.keys(inv.tool_calls).length} tool calls
                </p>
              </div>
              <Badge
                tone={
                  inv.status === "done" ? "accent"
                  : inv.status === "failed" ? "danger"
                  : inv.status === "paused" ? "warning"
                  : "default"
                }
              >
                {inv.status}
              </Badge>
              <button
                className="text-xs text-accent hover:underline cursor-pointer"
                onClick={() => setActive(inv.id)}
              >
                open →
              </button>
            </CardBody>
          </Card>
        ))}
      </div>
    </Screen>
  );
}
