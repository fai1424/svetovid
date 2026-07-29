// Screen 2 — Evidence selection.
//
// Folder picker (native via @tauri-apps/plugin-dialog in the desktop shell;
// text input fallback when running in browser dev). Scan streams progress
// events through the WS store; results are grouped by artifact family and
// each row shows the goals it can feed.

import { useState } from "react";
import { FolderOpen, ScanLine, Loader2, ChevronRight, FileWarning } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { Button, Card, CardBody, CardHeader, Badge } from "@/components/ui/primitives";
import { Screen } from "./ApiKeySetup";
import { useEvents } from "@/lib/events";
import type { Artifact } from "@/lib/types";

interface Props {
  onNext: () => void;
}

export function EvidenceSelect({ onNext }: Props) {
  const [path, setPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const scanState = useEvents((s) => s.scan);

  async function pickFolder() {
    // Prefer native Tauri dialog when available; fall back to text input.
    try {
      const mod = await import("@tauri-apps/plugin-dialog");
      const picked = await mod.open({ directory: true, multiple: false });
      if (typeof picked === "string") setPath(picked);
    } catch {
      // browser/dev — user types path manually
    }
  }

  async function scan() {
    if (!path) return;
    setScanning(true);
    setError(null);
    setArtifacts([]);
    try {
      const r = await api.scan(path);
      setArtifacts(r.artifacts);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }

  // group artifacts by family for display
  const families = groupBy(artifacts, (a) => a.family);
  const totalGoals = new Set(artifacts.flatMap((a) => a.goals)).size;

  return (
    <Screen
      title="Point at evidence"
      subtitle="Step 2 of 4 · Pick a folder of forensic artifacts. The scanner auto-detects what's there."
    >
      <div className="max-w-5xl space-y-md">
        {/* Path picker */}
        <Card>
          <CardBody className="flex items-end gap-md">
            <div className="flex-1">
              <label className="block text-xs uppercase tracking-wider text-muted-fg mb-1">
                Evidence folder
              </label>
              <div className="flex items-center gap-md bg-background border border-border rounded-md h-9 px-md">
                <FolderOpen className="h-3.5 w-3.5 text-muted-fg" />
                <input
                  type="text"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="/path/to/evidence  (or use the picker →)"
                  className="flex-1 bg-transparent outline-none text-sm font-mono"
                  autoCorrect="off"
                  spellCheck={false}
                />
              </div>
            </div>
            <Button variant="outline" onClick={pickFolder}>Browse…</Button>
            <Button variant="primary" onClick={scan} loading={scanning} disabled={!path}>
              {!scanning && <ScanLine className="h-3.5 w-3.5" />}
              Scan
            </Button>
          </CardBody>
        </Card>

        {/* Live scan progress */}
        {(scanning || scanState.status === "scanning") && (
          <Card>
            <CardBody className="flex items-center gap-md text-sm">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-status-running" />
              <span>scanned {scanState.scanned.toLocaleString()} files</span>
              <span className="text-muted-fg">·</span>
              <FoundSummary found={scanState.found} />
            </CardBody>
          </Card>
        )}

        {error && (
          <Card className="border-destructive/50">
            <CardBody className="flex items-center gap-md text-sm text-destructive">
              <FileWarning className="h-4 w-4" /> {error}
            </CardBody>
          </Card>
        )}

        {/* Scan results */}
        {artifacts.length > 0 && (
          <>
            <Card>
              <CardHeader className="flex items-center justify-between">
                <h2 className="text-sm font-semibold uppercase tracking-wider">
                  {artifacts.length} artifact{artifacts.length === 1 ? "" : "s"} · {Object.keys(families).length} families
                </h2>
                <Badge tone="accent">{totalGoals} goal{totalGoals === 1 ? "" : "s"} available</Badge>
              </CardHeader>
              <CardBody className="p-0">
                <ul className="divide-y divide-border">
                  {Object.entries(families).map(([family, items]) => (
                    <li key={family} className="px-lg py-md">
                      <div className="flex items-baseline justify-between">
                        <span className="text-sm font-medium">{family}</span>
                        <span className="text-2xs text-muted-fg uppercase tracking-wider">
                          {items[0].artifact_id} · {items.length} file{items.length === 1 ? "" : "s"}
                        </span>
                      </div>
                      <ul className="mt-xs space-y-xs">
                        {items.slice(0, 5).map((a) => (
                          <li key={a.path} className="text-xs text-muted-fg font-mono truncate" title={a.path}>
                            {a.path}
                          </li>
                        ))}
                        {items.length > 5 && (
                          <li className="text-2xs text-muted-fg italic">… and {items.length - 5} more</li>
                        )}
                      </ul>
                      <div className="mt-sm flex flex-wrap gap-1">
                        {Array.from(new Set(items.flatMap((a) => a.goals))).map((g) => (
                          <Badge key={g} tone="muted">{g}</Badge>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
              </CardBody>
            </Card>
            <div className="flex justify-end">
              <Button variant="primary" onClick={onNext}>
                Continue to goal <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            </div>
          </>
        )}

        {!scanning && artifacts.length === 0 && !error && (
          <EmptyHint />
        )}
      </div>
    </Screen>
  );
}

function FoundSummary({ found }: { found: Record<string, number> }) {
  const entries = Object.entries(found);
  if (entries.length === 0) return <span className="text-muted-fg">no artifacts yet</span>;
  return (
    <span className="text-muted-fg">
      {entries.map(([k, v]) => `${v} ${k}`).join(" · ")}
    </span>
  );
}

function EmptyHint() {
  return (
    <Card className="border-dashed">
      <CardBody className="text-center py-2xl text-muted-fg">
        <FolderOpen className="h-8 w-8 mx-auto mb-md opacity-50" />
        <p className="text-sm">Pick a folder and scan to see what's inside.</p>
        <p className="text-2xs mt-xs">Recognizes: .evtx, .pcap/.pcapng, memory (.raw/.vmem/.lime), $MFT, .pf, registry hives, E01, iOS backups, Android dumps, Zeek logs, K8s/cloud audit logs.</p>
      </CardBody>
    </Card>
  );
}

function groupBy<T>(arr: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of arr) {
    const k = key(item);
    (out[k] = out[k] || []).push(item);
  }
  return out;
}
