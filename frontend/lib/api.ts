/** Server-side API client. The browser never talks to the backend directly
 *  (except for /api/... export downloads, which Next.js proxies). */

const BASE = process.env.API_INTERNAL_URL || "http://backend:8000";

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export type Query = Record<string, string | number | boolean | string[] | undefined | null>;

function toQuery(params: Query = {}): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    if (Array.isArray(value)) value.forEach((v) => v && sp.append(key, String(v)));
    else sp.append(key, String(value));
  }
  const q = sp.toString();
  return q ? `?${q}` : "";
}

export async function api<T>(path: string, params?: Query): Promise<T> {
  const res = await fetch(`${BASE}${path}${toQuery(params)}`, {
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(String(detail), res.status);
  }
  return (await res.json()) as T;
}

/** Returns null instead of throwing when the backend is unreachable, so a
 *  single failing panel never takes down the whole dashboard. */
export async function apiSafe<T>(path: string, params?: Query): Promise<T | null> {
  try {
    return await api<T>(path, params);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- types
export interface Paged<T> {
  total: number;
  page: number;
  page_size: number;
  items: T[];
}

export interface Reason {
  factor: string;
  points: number;
  detail: string;
}

export interface Vuln {
  cve_id: string;
  title: string | null;
  vendor: string | null;
  product: string | null;
  severity: string | null;
  cvss_score: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  actively_exploited: boolean;
  has_exploit: boolean;
  has_poc: boolean;
  exploit_count: number;
  poc_count: number;
  published: string | null;
  first_seen: string | null;
  last_updated: string | null;
  last_activity_at: string | null;
  source_count: number;
  tags: string[];
  platforms: string[];
  techniques: { id: string; method: string }[];
  relevance_score: number;
  relevance_reasons: Reason[];
  description?: string | null;
  cwes?: string[];
}

export interface SourceInfo {
  key: string;
  name: string;
  tier: number;
  source_type: string;
  homepage?: string;
}

export interface Doc {
  id: number;
  title: string;
  summary: string | null;
  url: string;
  doc_type: string;
  source: SourceInfo;
  tier: number;
  categories: string[];
  authors: string[];
  reports_exploitation: boolean;
  published_at: string | null;
  collected_at: string | null;
  cves: string[];
  entities: { stix_id: string; type: string; name: string; external_id: string | null }[];
  link?: { confidence: string; method: string; evidence: string | null } | null;
}

export interface ExploitItem {
  id: number;
  external_id: string;
  title: string;
  description: string | null;
  url: string;
  kind: string;
  platform: string | null;
  exploit_type: string | null;
  author: string | null;
  verified: boolean;
  stars: number | null;
  language: string | null;
  cve_ids: string[];
  source: SourceInfo;
  tier: number;
  published_at: string | null;
  collected_at: string | null;
  warning: string | null;
}

export interface AttackItem {
  stix_id: string;
  external_id: string | null;
  type: string;
  name: string;
  aliases: string[];
  platforms: string[];
  tactics: string[];
  url: string | null;
  is_subtechnique: boolean;
  description: string;
  mentions: number | null;
  evidence?: { document_id: number; title: string; url: string; source: string; snippet: string | null }[];
}

export interface SourceHealth {
  key: string;
  name: string;
  homepage: string;
  endpoint: string;
  category: string;
  source_type: string;
  tier: number;
  method: string;
  phase: number;
  enabled: boolean;
  requires_auth: boolean;
  interval_seconds: number;
  health: string;
  last_attempt: string | null;
  last_successful_fetch: string | null;
  last_status: string | null;
  last_error: string | null;
  latency_ms: number | null;
  items_fetched: number;
  items_new: number;
  items_updated: number;
  consecutive_failures: number;
  implemented: boolean;
  notes: string;
  rate_limit: string;
  fields: string[];
}
