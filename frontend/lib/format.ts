export function fmtDate(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
}

export function fmtDateTime(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

export function relative(value?: string | null): string {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";
  const mins = Math.round((Date.now() - then) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 31) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 24) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
}

export function duration(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds}s`;
}

export const TAG_LABELS: Record<string, string> = {
  rce: "Remote code execution",
  privilege_escalation: "Privilege escalation",
  auth_bypass: "Authentication bypass",
  sqli: "SQL injection",
  path_traversal: "Path traversal",
  memory_corruption: "Memory corruption",
  info_disclosure: "Information disclosure",
  dos: "Denial of service",
};

/** Short forms for tight spaces (table cells, chips). */
export const TAG_SHORT: Record<string, string> = {
  rce: "RCE",
  privilege_escalation: "Priv esc",
  auth_bypass: "Auth bypass",
  sqli: "SQLi",
  path_traversal: "Traversal",
  memory_corruption: "Memory",
  info_disclosure: "Info leak",
  dos: "DoS",
};

export const PLATFORM_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  android: "Android",
  cloud: "Cloud",
  active_directory: "Active Directory",
  identity: "Identity",
  web: "Web",
  network: "Network",
};

/**
 * A short, readable label for a vulnerability row.
 *
 * CISA gives KEV entries a curated short name ("Microsoft Netlogon Privilege
 * Escalation Vulnerability"); for everything else the backend only has the NVD
 * description, and slicing it mid-sentence produced the unreadable lines this
 * table used to show. In that case describe the impact instead.
 */
export function vulnLabel(v: {
  title: string | null;
  tags: string[];
  platforms: string[];
  vendor: string | null;
}): string {
  if (v.title && v.title.length <= 70) return v.title;
  const impact = v.tags.map((t) => TAG_LABELS[t] || t);
  const where = v.platforms.map((p) => PLATFORM_LABELS[p] || p).slice(0, 2);
  if (impact.length) return [impact.slice(0, 2).join(" · "), where.join("/")].filter(Boolean).join(" — ");
  if (v.title) return v.title.slice(0, 70).trimEnd() + "…";
  return "No summary available";
}

export function riskLevel(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function riskLabel(score: number): string {
  return { critical: "Critical priority", high: "High priority", medium: "Worth reviewing", low: "Low priority" }[
    riskLevel(score)
  ];
}

export function riskColor(score: number): string {
  return {
    critical: "var(--risk-critical)",
    high: "var(--risk-high)",
    medium: "var(--risk-medium)",
    low: "var(--risk-none)",
  }[riskLevel(score)];
}

export function severityClass(sev?: string | null): string {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
      return "sev sev-critical";
    case "HIGH":
      return "sev sev-high";
    case "MEDIUM":
      return "sev sev-medium";
    case "LOW":
      return "sev sev-low";
    default:
      return "sev sev-none";
  }
}

export function tierLabel(tier: number): string {
  return (
    {
      1: "Tier 1 — government, vendor or original research",
      2: "Tier 2 — security research organisation",
      3: "Tier 3 — security news",
      4: "Tier 4 — community, unverified",
    }[tier] || `Tier ${tier}`
  );
}
