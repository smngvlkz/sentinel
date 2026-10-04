import type { Severity } from "./threats";

// Same address as the dashboard; next.config.ts forwards /api to the API.
const API_BASE = "/api";

export interface Alert {
  id: number;
  timestamp: string;
  threat_type: string;
  severity: Severity;
  source_ip: string;
  destination_ip: string;
  source_port: string;
  destination_port: string;
  /** Hostname learned from DNS/HTTP/TLS, if payload inspection is on. */
  source_name: string | null;
  destination_name: string | null;
  /** Friendly name someone gave this device, e.g. "Living room TV". */
  source_device: string | null;
  destination_device: string | null;
  confidence: number;
  detection_source: string;
  features: Record<string, number>;
  reviewed_at: string | null;
}

export interface AlertSummary {
  threat_type: string;
  count: number;
  avg_confidence: number;
}

export interface TopIP {
  source_ip: string;
  source_device: string | null;
  alert_count: number;
  threat_types: string[];
}

export interface Stats {
  window_hours: number;
  total_alerts: number;
  unique_sources: number;
  last_alert_at: string | null;
  by_severity: Record<Severity, { total: number; unreviewed: number }>;
  /** The most severe level that still has unreviewed alerts, if any. */
  attention: { severity: Severity; count: number; latest: Alert } | null;
}

export type ReviewStatus = "all" | "unreviewed" | "reviewed";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  services: {
    database: { ok: boolean; error?: string };
    redis: { ok: boolean; error?: string };
    capture: {
      state: "live" | "idle" | "never" | "unknown";
      last_packet_seconds_ago?: number | null;
    };
    analyzer: {
      running: boolean;
      model_loaded?: boolean;
      packets_processed?: number;
    };
  };
}

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("Can't reach the API");
  }
  if (!res.ok) throw new ApiError(`${path} returned ${res.status}`);
  return res.json();
}

export const fetchHealth = () => request<Health>("/health");

export const fetchStats = (hours: number) => request<Stats>(`/stats?hours=${hours}`);

export function fetchAlerts(
  hours: number,
  { severity, status = "all", limit = 100 }: { severity?: Severity; status?: ReviewStatus; limit?: number } = {},
) {
  const q = new URLSearchParams({ hours: String(hours), limit: String(limit), status });
  if (severity) q.set("severity", severity);
  return request<{ alerts: Alert[]; count: number }>(`/alerts?${q}`);
}

export const fetchAlertSummary = (hours: number) =>
  request<{ summary: AlertSummary[] }>(`/alerts/summary?hours=${hours}`);

export const fetchTopIPs = (hours: number, limit = 8) =>
  request<{ top_ips: TopIP[] }>(`/top-ips?limit=${limit}&hours=${hours}`);

/** Give a device a friendly name; null or "" removes it. */
export const nameDevice = (ip: string, name: string | null) =>
  request<{ ip: string; name: string | null }>("/devices/name", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, name }),
  });

/** Mark alerts reviewed (or unreviewed) by id, or every match of a filter. */
export const reviewAlerts = (
  body: { reviewed?: boolean } & ({ ids: number[] } | { hours: number; severity?: Severity }),
) =>
  request<{ updated: number }>("/alerts/review", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
