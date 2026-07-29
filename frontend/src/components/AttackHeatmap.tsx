// AttackHeatmap — static ATT&CK Enterprise matrix grid (Gap 6).
//
// Renders a compact subset of the matrix (14 tactics × ~10 techniques each)
// as an HTML grid. Each cell is colored by how many timeline/IOC entries
// reference that technique (white = 0, light green = 1-2, bright green =
// 3+). Clicking a cell invokes onSelectTechnique so the parent can filter
// the timeline.
//
// No external graphing library — just Tailwind grid classes + inline colors
// so the heatmap reads on the dark theme. The technique subset is the most
// common Enterprise techniques (good enough for a v1 overview); the full
// matrix is far too large for a single screen anyway.

import { useMemo } from "react";
import { TACTIC_COLORS } from "./TimelineView";
import { cn } from "@/lib/cn";

export interface AttackHeatmapProps {
  /** The techniques that appear in the investigation's data, with a count
   * each so we can shade the cells. */
  techniqueCounts?: Record<string, number>;
  /** Currently-selected technique (from a previous click). */
  selectedTechnique?: string | null;
  /** Called when the user clicks a cell. Pass null to clear. */
  onSelectTechnique?: (techniqueId: string | null) => void;
}

// Compact Enterprise matrix: tactic → ordered list of (id, short-name).
// Deliberately a subset (~10 per tactic) of the most commonly seen
// techniques. Tactics without findings still render as an empty column so
// the matrix shape is stable.
export const ATTACK_MATRIX: { tactic: string; techniques: { id: string; name: string }[] }[] = [
  {
    tactic: "Reconnaissance",
    techniques: [
      { id: "T1595", name: "Active Scanning" },
      { id: "T1592", name: "Gather Victim Host Info" },
      { id: "T1590", name: "Gather Victim Host Info" },
      { id: "T1589", name: "Gather Victim Identity Info" },
      { id: "T1591", name: "Gather Victim Org Info" },
      { id: "T1596", name: "Search Open Technical DB" },
      { id: "T1593", name: "Search Open Websites" },
      { id: "T1588", name: "Obtain Capabilities" },
      { id: "T1607", name: "Deploy System" },
      { id: "T1594", name: "Search Victim-Owned Websites" },
    ],
  },
  {
    tactic: "Resource Development",
    techniques: [
      { id: "T1583", name: "Acquire Infrastructure" },
      { id: "T1587", name: "Develop Capabilities" },
      { id: "T1588", name: "Obtain Capabilities" },
      { id: "T1586", name: "Compromise Accounts" },
      { id: "T1585", name: "Establish Accounts" },
      { id: "T1584", name: "Compromise Infrastructure" },
      { id: "T1608", name: "Stage Capabilities" },
      { id: "T1589", name: "Gather Victim Identity Info" },
      { id: "T1592", name: "Gather Victim Host Info" },
      { id: "T1590", name: "Gather Victim Network Info" },
    ],
  },
  {
    tactic: "Initial Access",
    techniques: [
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1190", name: "Exploit Public App" },
      { id: "T1133", name: "External Remote Services" },
      { id: "T1566", name: "Phishing" },
      { id: "T1195", name: "Supply Chain Compromise" },
      { id: "T1199", name: "Trusted Relationship" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1133", name: "External Remote Services" },
      { id: "T1200", name: "Hardware Additions" },
      { id: "T1091", name: "Replication Through Removable Media" },
    ],
  },
  {
    tactic: "Execution",
    techniques: [
      { id: "T1059", name: "Command and Scripting" },
      { id: "T1059.001", name: "PowerShell" },
      { id: "T1059.003", name: "Windows Command Shell" },
      { id: "T1059.004", name: "Unix Shell" },
      { id: "T1106", name: "Native API" },
      { id: "T1129", name: "Shared Modules" },
      { id: "T1204", name: "User Execution" },
      { id: "T1047", name: "WMI" },
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1106", name: "Native API" },
    ],
  },
  {
    tactic: "Persistence",
    techniques: [
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1547", name: "Boot or Logon Autostart" },
      { id: "T1547.001", name: "Registry Run Keys" },
      { id: "T1136", name: "Create Account" },
      { id: "T1543", name: "Create/Modify System Process" },
      { id: "T1543.003", name: "Windows Service" },
      { id: "T1098", name: "Account Manipulation" },
      { id: "T1136", name: "Create Account" },
      { id: "T1505", name: "Server Software Component" },
      { id: "T1546", name: "Event Triggered Execution" },
    ],
  },
  {
    tactic: "Privilege Escalation",
    techniques: [
      { id: "T1068", name: "Exploitation for Priv Esc" },
      { id: "T1548", name: "Abuse Elevation Control" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1548.002", name: "Bypass UAC" },
      { id: "T1134", name: "Access Token Manipulation" },
      { id: "T1547", name: "Boot or Logon Autostart" },
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1543", name: "Create/Modify System Process" },
      { id: "T1068", name: "Exploitation for Priv Esc" },
    ],
  },
  {
    tactic: "Defense Evasion",
    techniques: [
      { id: "T1112", name: "Modify Registry" },
      { id: "T1027", name: "Obfuscated Files" },
      { id: "T1140", name: "Deobfuscate/Decode" },
      { id: "T1036", name: "Masquerading" },
      { id: "T1562", name: "Impair Defenses" },
      { id: "T1070", name: "Indicator Removal" },
      { id: "T1218", name: "System Binary Proxy Exec" },
      { id: "T1202", name: "Indirect Command Execution" },
      { id: "T1036", name: "Masquerading" },
      { id: "T1140", name: "Deobfuscate/Decode" },
    ],
  },
  {
    tactic: "Credential Access",
    techniques: [
      { id: "T1110", name: "Brute Force" },
      { id: "T1056", name: "Input Capture" },
      { id: "T1003", name: "OS Credential Dumping" },
      { id: "T1003.001", name: "LSASS Memory" },
      { id: "T1555", name: "Credentials from Password Store" },
      { id: "T1539", name: "Steal Web Session Cookie" },
      { id: "T1528", name: "Steal Application Access Token" },
      { id: "T1110", name: "Brute Force" },
      { id: "T1557", name: "Adversary-in-the-Middle" },
      { id: "T1606", name: "Forge Web Credentials" },
    ],
  },
  {
    tactic: "Discovery",
    techniques: [
      { id: "T1087", name: "Account Discovery" },
      { id: "T1046", name: "Network Service Discovery" },
      { id: "T1083", name: "File and Directory Discovery" },
      { id: "T1018", name: "Remote System Discovery" },
      { id: "T1057", name: "Process Discovery" },
      { id: "T1082", name: "System Information Discovery" },
      { id: "T1087", name: "Account Discovery" },
      { id: "T1069", name: "Permission Groups Discovery" },
      { id: "T1082", name: "System Information Discovery" },
      { id: "T1497", name: "Virtualization/Sandbox Evasion" },
    ],
  },
  {
    tactic: "Lateral Movement",
    techniques: [
      { id: "T1021", name: "Remote Services" },
      { id: "T1021.001", name: "RDP" },
      { id: "T1077", name: "Windows Admin Shares" },
      { id: "T1570", name: "Lateral Tool Transfer" },
      { id: "T1020", name: "Automated Exfiltration" },
      { id: "T1550", name: "Use Alternate Auth Material" },
      { id: "T1072", name: "Software Deployment Tools" },
      { id: "T1550", name: "Use Alternate Auth Material" },
      { id: "T1570", name: "Lateral Tool Transfer" },
      { id: "T1021", name: "Remote Services" },
    ],
  },
  {
    tactic: "Collection",
    techniques: [
      { id: "T1005", name: "Data from Local System" },
      { id: "T1560", name: "Archive Collected Data" },
      { id: "T1113", name: "Screen Capture" },
      { id: "T1119", name: "Automated Collection" },
      { id: "T1056", name: "Input Capture" },
      { id: "T1074", name: "Data Staged" },
      { id: "T1560", name: "Archive Collected Data" },
      { id: "T1030", name: "Data Transfer Size Limits" },
      { id: "T1113", name: "Screen Capture" },
      { id: "T1056", name: "Input Capture" },
    ],
  },
  {
    tactic: "Command and Control",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol" },
      { id: "T1071.001", name: "Web Protocols" },
      { id: "T1571", name: "Non-Standard Port" },
      { id: "T1573", name: "Encrypted Channel" },
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1132", name: "Data Encoding" },
      { id: "T1090", name: "Proxy" },
      { id: "T1008", name: "Fallback Channels" },
      { id: "T1104", name: "Multi-Stage Channels" },
      { id: "T1568", name: "Dynamic Resolution" },
    ],
  },
  {
    tactic: "Exfiltration",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2" },
      { id: "T1567", name: "Exfiltration Over Web Service" },
      { id: "T1048", name: "Exfiltration Over Alt Protocol" },
      { id: "T1029", name: "Exfiltration Over Phys Medium" },
      { id: "T1030", name: "Data Transfer Size Limits" },
      { id: "T1537", name: "Transfer Data to Cloud Account" },
      { id: "T1567", name: "Exfiltration Over Web Service" },
      { id: "T1048", name: "Exfiltration Over Alt Protocol" },
      { id: "T1029", name: "Exfiltration Over Phys Medium" },
      { id: "T1052", name: "Exfiltration Over Phys Medium" },
    ],
  },
  {
    tactic: "Impact",
    techniques: [
      { id: "T1040", name: "Network Denial of Service" },
      { id: "T1486", name: "Data Encrypted for Impact" },
      { id: "T1485", name: "Data Destruction" },
      { id: "T1490", name: "Inhibit System Recovery" },
      { id: "T1498", name: "Network Denial of Service" },
      { id: "T1561", name: "Disk Wipe" },
      { id: "T1489", name: "Service Stop" },
      { id: "T1529", name: "System Shutdown/Reboot" },
      { id: "T1499", name: "Endpoint Denial of Service" },
      { id: "T1485", name: "Data Destruction" },
    ],
  },
];

function cellColor(count: number): string {
  if (count <= 0) return "transparent";
  if (count <= 2) return "rgba(34, 197, 94, 0.35)"; // green-500 @ 35%
  return "rgba(34, 197, 94, 0.85)"; // green-500 @ 85%
}

export function AttackHeatmap({
  techniqueCounts = {},
  selectedTechnique = null,
  onSelectTechnique,
}: AttackHeatmapProps) {
  const totals = useMemo(() => {
    let withFindings = 0;
    let totalFindings = 0;
    for (const col of ATTACK_MATRIX) {
      for (const t of col.techniques) {
        const c = techniqueCounts[t.id] || 0;
        if (c > 0) {
          withFindings += 1;
          totalFindings += c;
        }
      }
    }
    return { withFindings, totalFindings };
  }, [techniqueCounts]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex-none px-lg py-sm border-b border-border flex items-center gap-md">
        <span className="text-xs font-semibold uppercase tracking-wider">ATT&amp;CK Enterprise</span>
        <span className="text-2xs text-muted-fg">
          {totals.withFindings} techniques · {totals.totalFindings} findings
        </span>
        <div className="ml-auto flex items-center gap-xs text-2xs text-muted-fg">
          <span>0</span>
          <span className="inline-block h-3 w-3 rounded-sm border border-border" style={{ background: "transparent" }} />
          <span className="inline-block h-3 w-3 rounded-sm" style={{ background: cellColor(1) }} />
          <span className="inline-block h-3 w-3 rounded-sm" style={{ background: cellColor(3) }} />
          <span>3+</span>
        </div>
      </div>

      {/* Matrix grid */}
      <div className="flex-1 overflow-auto p-md">
        <div className="grid gap-xs" style={{ gridTemplateColumns: `repeat(${ATTACK_MATRIX.length}, minmax(0, 1fr))` }}>
          {ATTACK_MATRIX.map((col) => {
            const tacticKey = col.tactic.toLowerCase().replace(/\s+/g, "-");
            const color = TACTIC_COLORS[tacticKey] || TACTIC_COLORS.unknown;
            return (
              <div key={col.tactic} className="min-w-0">
                {/* Tactic header */}
                <div
                  className="text-center text-2xs font-semibold uppercase tracking-tight py-xs mb-xs rounded-sm"
                  style={{ color, backgroundColor: `${color}1a`, borderBottom: `2px solid ${color}` }}
                  title={col.tactic}
                >
                  {col.tactic}
                </div>
                {/* Technique cells */}
                <div className="flex flex-col gap-0.5">
                  {col.techniques.map((t, i) => {
                    const count = techniqueCounts[t.id] || 0;
                    const isSelected = selectedTechnique === t.id;
                    const hasFindings = count > 0;
                    return (
                      <button
                        key={`${t.id}-${i}`}
                        type="button"
                        onClick={() => onSelectTechnique?.(isSelected ? null : t.id)}
                        title={`${t.id} — ${t.name}${hasFindings ? ` (${count})` : ""}`}
                        className={cn(
                          "group relative text-left px-1 py-0.5 rounded-sm transition-all",
                          "border border-transparent hover:border-border",
                          hasFindings ? "cursor-pointer" : "cursor-default opacity-70",
                          isSelected && "ring-2 ring-[var(--color-ring)]",
                        )}
                        style={{ backgroundColor: cellColor(count) }}
                      >
                        <div className="flex items-baseline gap-1 min-w-0">
                          <span
                            className={cn(
                              "font-mono text-2xs shrink-0",
                              hasFindings ? "text-foreground font-semibold" : "text-muted-fg",
                            )}
                          >
                            {t.id}
                          </span>
                          {hasFindings && (
                            <span className="text-2xs font-mono text-foreground/80">{count}</span>
                          )}
                        </div>
                        <div
                          className={cn(
                            "truncate text-2xs leading-tight",
                            hasFindings ? "text-foreground/90" : "text-muted-fg/60",
                          )}
                        >
                          {t.name}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
        <p className="mt-md text-2xs text-muted-fg/70">
          Showing a compact subset of common Enterprise techniques. Click a highlighted cell to
          filter the timeline to events tagged with that technique.
        </p>
      </div>
    </div>
  );
}
