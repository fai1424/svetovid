// Svetovid app shell — top bar + screen router.
//
// Screens are stepped through the user flow:
//   api-key → evidence → goal → investigation
// but all reachable at any time from the top nav. State lives in zustand
// (settings/scanned-evidence/active-investigation) so screens don't prop-drill.

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  FolderTree,
  KeyRound,
  Library,
  Settings as SettingsIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { useEvents, setAnnouncer } from "@/lib/events";
import { RatingPrompt } from "@/components/RatingPrompt";
import { ApiKeySetup } from "@/screens/ApiKeySetup";
import { EvidenceSelect } from "@/screens/EvidenceSelect";
import { GoalSelect } from "@/screens/GoalSelect";
import { Investigation } from "@/screens/Investigation";
import { Cases } from "@/screens/Cases";
import { Settings } from "@/screens/Settings";
import { ErrorBoundary } from "@/components/ErrorBoundary";

type ScreenId = "apikey" | "evidence" | "goal" | "investigation" | "cases" | "settings";

interface NavItem {
  id: ScreenId;
  label: string;
  icon: typeof Activity;
}

const NAV: NavItem[] = [
  { id: "apikey", label: "Model", icon: KeyRound },
  { id: "evidence", label: "Evidence", icon: FolderTree },
  { id: "goal", label: "Goal", icon: Library },
  { id: "investigation", label: "Investigation", icon: Activity },
  { id: "cases", label: "Cases", icon: FolderTree }, // placeholder icon; replaced below
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

export default function App() {
  const [screen, setScreen] = useState<ScreenId>("apikey");
  const connect = useEvents((s) => s.connect);
  const connected = useEvents((s) => s.connected);

  // a11y §1: aria-live region for streaming announcements
  const liveRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setAnnouncer((msg: string) => {
      if (liveRef.current) liveRef.current.textContent = msg;
    });
  }, []);

  useEffect(() => {
    // Fetch the auth token, then connect the WebSocket with it.
    (async () => {
      const { fetchAuthToken } = await import("./lib/api");
      const token = await fetchAuthToken();
      const { setWsToken } = await import("./lib/events");
      setWsToken(token);
      connect();
    })();
  }, [connect]);

  const navItems = useMemo(() => NAV, []);
  const activeInv = useEvents((s) => {
    const id = s.activeInvestigationId;
    return id ? !!s.investigations[id] : false;
  });
  const badge = (id: ScreenId) => {
    if (id === "investigation" && activeInv) {
      return (
        <span className="ml-auto h-1.5 w-1.5 rounded-full bg-status-running animate-pulse-soft" aria-hidden />
      );
    }
    return null;
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      {/* Sidebar nav */}
      <nav
        aria-label="Sections"
        className="flex w-44 flex-col border-r border-border bg-surface py-md"
      >
        <div className="px-lg py-md flex items-center gap-2">
          <SvetovidMark className="h-5 w-5 text-accent" />
          <span className="text-sm font-semibold tracking-tight">SVETOVID</span>
        </div>
        <ul className="flex-1 flex flex-col gap-xs px-md">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = screen === item.id;
            return (
              <li key={item.id}>
                <button
                  type="button"
                  aria-current={active ? "page" : undefined}
                  onClick={() => setScreen(item.id)}
                  className={cn(
                    "w-full flex items-center gap-md px-md h-8 rounded-md text-sm transition-colors cursor-pointer",
                    active
                      ? "bg-secondary text-on-secondary"
                      : "text-muted-fg hover:text-foreground hover:bg-muted"
                  )}
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  <span>{item.label}</span>
                  {badge(item.id)}
                </button>
              </li>
            );
          })}
        </ul>
        <div className="px-lg py-md flex items-center gap-2 text-2xs text-muted-fg">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              connected ? "bg-status-running" : "bg-status-failed"
            )}
            aria-label={connected ? "connected" : "disconnected"}
          />
          <span>{connected ? "backend connected" : "reconnecting…"}</span>
        </div>
      </nav>

      {/* Screen host */}
      <main className="flex-1 overflow-hidden">
        <ErrorBoundary>
          {screen === "apikey" && <ApiKeySetup onNext={() => setScreen("evidence")} />}
          {screen === "evidence" && (
            <EvidenceSelect onNext={() => setScreen("goal")} />
          )}
          {screen === "goal" && (
            <GoalSelect onNext={() => setScreen("investigation")} />
          )}
          {screen === "investigation" && <Investigation />}
          {screen === "cases" && <Cases />}
          {screen === "settings" && <Settings />}
        </ErrorBoundary>
      </main>

      {/* a11y live region for streaming announcements */}
      <div ref={liveRef} aria-live="polite" className="sr-live" />

      {/* Post-investigation rating toast (anonymous, opt-out telemetry) */}
      <RatingPrompt />
    </div>
  );
}

// Four-faced Svetovid mark — minimalist, on-brand. The "signature element"
// candidate per frontend-design: a 4-quadrant glyph evoking the god's four
// faces and the four panes of the Investigation screen.
function SvetovidMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={className} fill="none" aria-hidden>
      <rect x="2" y="2" width="9" height="9" fill="currentColor" />
      <rect x="13" y="2" width="9" height="9" fill="currentColor" fillOpacity="0.5" />
      <rect x="2" y="13" width="9" height="9" fill="currentColor" fillOpacity="0.5" />
      <rect x="13" y="13" width="9" height="9" fill="currentColor" />
    </svg>
  );
}
