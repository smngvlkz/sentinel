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

export class ApiError extends Error {
  /** The HTTP status, or 0 if the API couldn't be reached at all. */
  constructor(message: string, readonly status = 0) {
    super(message);
  }
}

/** The API wants a login (a password is set and this browser has no session). */
export const needsLogin = (e: unknown) => e instanceof ApiError && e.status === 401;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("Can't reach the API");
  }
  if (!res.ok) {
    // The API explains refusals in plain language ("Wrong password."); show that.
    const detail = await res.json().then((b) => b?.detail, () => null);
    throw new ApiError(typeof detail === "string" ? detail : `${path} returned ${res.status}`, res.status);
  }
  return res.json();
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export interface AuthStatus {
  password_set: boolean;
  logged_in: boolean;
  /** No password yet, and the dashboard is reachable from this machine only. */
  setup_allowed: boolean;
}

export const fetchAuthStatus = () => request<AuthStatus>("/auth/status");
export const logIn = (password: string) => post<{ ok: boolean }>("/auth/login", { password });
export const logOut = () => post<{ ok: boolean }>("/auth/logout", {});
export const setUpPassword = (password: string) => post<{ ok: boolean }>("/auth/setup", { password });
export const changePassword = (current: string, next: string) =>
  post<{ ok: boolean }>("/auth/password", { current, new: next });

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
  post<{ ip: string; name: string | null }>("/devices/name", { ip, name });

/** Mark alerts reviewed (or unreviewed) by id, or every match of a filter. */
export const reviewAlerts = (
  body: { reviewed?: boolean } & ({ ids: number[] } | { hours: number; severity?: Severity }),
) =>
  post<{ updated: number }>("/alerts/review", body);
