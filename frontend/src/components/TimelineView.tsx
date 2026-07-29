// TimelineView — vertical investigation timeline (Gap 5).
//
// Renders each TimelineEntry as a node on a vertical rail, color-coded by
// the first MITRE ATT&CK tactic referenced in its mitre_tags. Built from
// pure CSS (no charting library) so it stays light and themeable through
// the design tokens. Filterable by source via a dropdown.
//
// Tactic → color mapping is a fixed, accessible 14-color palette covering
// the Enterprise ATT&CK tactics. The exact hex lives inline (one place)
// because ATT&CK has no canonical color scheme; we picked perceptually
// distinct hues that read on the dark theme.

import { useMemo, useState } from "react";
import { cn } from "@/lib/cn";
import type { TimelineEntry } from "@/lib/types";

export interface TimelineViewProps {
  entries: TimelineEntry[];
  /** Optional technique-id filter — only entries whose mitre_tags include
   * this id are shown. Used by the ATT&CK heatmap "click to filter". */
  techniqueFilter?: string | null;
  onClearTechniqueFilter?: () => void;
}

// The 14 Enterprise ATT&CK tactics + a perceptually-distinct color each.
// Mapping a technique to its tactic is done via the TACTIC_BY_TECHNIQUE
// table below (compact subset of the most common techniques).
export const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "#60a5fa", // blue-400
  "resource-development": "#38bdf8", // sky-400
  "initial-access": "#fb923c", // orange-400
  "execution": "#a78bfa", // violet-400
  "persistence": "#f472b6", // pink-400
  "privilege-escalation": "#f87171", // red-400
  "defense-evasion": "#facc15", // yellow-400
  "credential-access": "#fbbf24", // amber-400
  "discovery": "#34d399", // emerald-400
  "lateral-movement": "#2dd4bf", // teal-400
  "collection": "#4ade80", // green-400
  "command-and-control": "#22d3ee", // cyan-400
  "exfiltration": "#fde047", // yellow-300
  "impact": "#ef4444", // red-500
  "unknown": "#64748b", // slate-500
};

// Compact subset: technique-id → ATT&CK tactic. Covers the ~50 most common
// Enterprise techniques so timeline badges resolve to a real tactic. Any
// technique not in the table falls back to "unknown" (slate).
//
// NOTE: a few techniques legitimately map to multiple tactics in the real
// matrix (e.g. T1078 is both initial-access and privilege-escalation). For
// the v1 color legend we keep a single canonical mapping per technique id
// (the primary tactic) so every key is unique.
export const TACTIC_BY_TECHNIQUE: Record<string, string> = {
  // reconnaissance
  T1595: "reconnaissance", T1592: "reconnaissance", T1590: "reconnaissance",
  T1593: "reconnaissance", T1596: "reconnaissance", T1594: "reconnaissance",
  // resource-development
  T1583: "resource-development", T1587: "resource-development",
  T1588: "resource-development", T1586: "resource-development",
  T1585: "resource-development", T1584: "resource-development",
  T1608: "resource-development",
  // initial-access
  T1190: "initial-access", T1133: "initial-access", T1566: "initial-access",
  T1195: "initial-access", T1199: "initial-access", T1200: "initial-access",
  T1091: "initial-access",
  // execution
  T1059: "execution", T1106: "execution", T1129: "execution",
  T1204: "execution", T1047: "execution",
  // persistence
  T1053: "persistence", T1547: "persistence", T1136: "persistence",
  T1543: "persistence", T1098: "persistence", T1505: "persistence",
  T1546: "persistence",
  // privilege-escalation
  T1068: "privilege-escalation", T1548: "privilege-escalation",
  T1134: "privilege-escalation",
  // defense-evasion
  T1112: "defense-evasion", T1027: "defense-evasion", T1140: "defense-evasion",
  T1036: "defense-evasion", T1562: "defense-evasion", T1070: "defense-evasion",
  T1218: "defense-evasion", T1202: "defense-evasion",
  // credential-access
  T1110: "credential-access", T1056: "credential-access", T1003: "credential-access",
  T1555: "credential-access", T1539: "credential-access", T1528: "credential-access",
  T1557: "credential-access", T1606: "credential-access",
  // discovery
  T1087: "discovery", T1046: "discovery", T1083: "discovery",
  T1018: "discovery", T1057: "discovery", T1082: "discovery",
  T1069: "discovery", T1497: "discovery",
  // lateral-movement
  T1021: "lateral-movement", T1077: "lateral-movement", T1570: "lateral-movement",
  T1020: "lateral-movement", T1550: "lateral-movement", T1072: "lateral-movement",
  // collection
  T1005: "collection", T1560: "collection", T1113: "collection",
  T1119: "collection", T1074: "collection", T1030: "collection",
  // command-and-control
  T1071: "command-and-control", T1571: "command-and-control",
  T1573: "command-and-control", T1105: "command-and-control",
  T1132: "command-and-control", T1090: "command-and-control",
  T1008: "command-and-control", T1104: "command-and-control",
  T1568: "command-and-control",
  // exfiltration
  T1041: "exfiltration", T1567: "exfiltration", T1048: "exfiltration",
  T1029: "exfiltration", T1537: "exfiltration", T1052: "exfiltration",
  // impact
  T1040: "impact", T1486: "impact", T1485: "impact", T1490: "impact",
  T1498: "impact", T1561: "impact", T1489: "impact", T1529: "impact",
  T1499: "impact",
};

export function tacticForTechnique(techniqueId: string): string {
  // Technique ids may be sub-techniques (T1059.001) — strip the suffix
  // for the tactic lookup, then fall back to the full id.
  const base = techniqueId.split(".")[0];
  return TACTIC_BY_TECHNIQUE[techniqueId] || TACTIC_BY_TECHNIQUE[base] || "unknown";
}

export function colorForEntry(entry: TimelineEntry): string {
  const tag = (entry.mitre_tags || [])[0];
  if (!tag) return TACTIC_COLORS.unknown;
  return TACTIC_COLORS[tacticForTechnique(tag)] || TACTIC_COLORS.unknown;
}

export function TimelineView({ entries, techniqueFilter, onClearTechniqueFilter }: TimelineViewProps) {
  const [sourceFilter, setSourceFilter] = useState<string>("all");

  // Build the source dropdown options from the data we actually have.
  const sources = useMemo(() => {
    const set = new Set<string>();
    for (const e of entries) if (e.source) set.add(e.source);
    return ["all", ...Array.from(set).sort()];
  }, [entries]);

  const visible = useMemo(() => {
    let list = [...entries];
    if (sourceFilter !== "all") list = list.filter((e) => e.source === sourceFilter);
    if (techniqueFilter) {
      list = list.filter((e) => (e.mitre_tags || []).includes(techniqueFilter));
    }
    return list.sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  }, [entries, sourceFilter, techniqueFilter]);

  if (entries.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-center px-xl py-2xl text-xs text-muted-fg">
        Timeline entries will appear here as the agent extracts them.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Sticky filter header */}
      <div className="flex-none sticky top-0 z-10 flex items-center gap-md px-lg py-sm bg-surface/95 backdrop-blur border-b border-border">
        <span className="text-2xs uppercase tracking-wider text-muted-fg">Source</span>
        <select
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value)}
          className="h-7 px-md bg-background border border-border rounded-md text-2xs font-mono text-foreground focus-visible:outline-2 focus-visible:outline-[var(--color-ring)]"
        >
          {sources.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All sources" : s}
            </option>
          ))}
        </select>
        <span className="text-2xs text-muted-fg">
          {visible.length} / {entries.length}
        </span>
        {techniqueFilter && (
          <button
            type="button"
            onClick={onClearTechniqueFilter}
            className="ml-auto text-2xs font-mono text-accent hover:underline cursor-pointer"
          >
            clear filter: {techniqueFilter} ✕
          </button>
        )}
      </div>

      {/* The vertical rail */}
      <div className="flex-1 overflow-auto px-lg py-md">
        <ol className="relative">
          {/* the rail line itself */}
          <span className="absolute left-[5px] top-1 bottom-1 w-px bg-border" aria-hidden />
          {visible.map((entry, i) => {
            const color = colorForEntry(entry);
            return (
              <li key={`${entry.timestamp}-${i}`} className="relative pl-xl pb-md animate-fade-in">
                {/* node dot, colored by tactic */}
                <span
                  className="absolute left-0 top-1 h-[11px] w-[11px] rounded-full border-2 border-background"
                  style={{ backgroundColor: color }}
                  aria-hidden
                />
                <div className="flex items-baseline justify-between gap-md">
                  <time className="font-mono text-2xs text-muted-fg tabular-nums shrink-0">
                    {formatTimestamp(entry.timestamp)}
                  </time>
                  {entry.source && (
                    <span className="text-2xs uppercase tracking-wider text-muted-fg/80">
                      {entry.source}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 text-xs text-foreground leading-snug">
                  {entry.event || entry.description || "(no event text)"}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-xs">
                  {entry.actor && (
                    <span className="text-2xs font-mono text-muted-fg">{entry.actor}</span>
                  )}
                  {(entry.mitre_tags || []).map((t) => {
                    const tactic = tacticForTechnique(t);
                    return (
                      <span
                        key={t}
                        className="inline-flex items-center px-1 py-0 text-2xs font-mono rounded-sm border"
                        style={{
                          color,
                          borderColor: `${color}66`,
                          backgroundColor: `${color}1a`,
                        }}
                        title={tactic}
                      >
                        {t}
                      </span>
                    );
                  })}
                </div>
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}

function formatTimestamp(iso: string): string {
  // Prefer a readable time; fall back to the raw string for non-ISO inputs.
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-GB", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
