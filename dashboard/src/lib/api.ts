const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface Alert {
  id: number;
  timestamp: string;
  threat_type: string;
  source_ip: string;
  destination_ip: string;
  source_port: string;
  destination_port: string;
  confidence: number;
  detection_source: string;
  features: Record<string, number>;
}

export interface AlertSummary {
  threat_type: string;
  count: number;
  avg_confidence: number;
}

export interface TopIP {
  source_ip: string;
  alert_count: number;
  threat_types: string[];
}

export interface LiveTraffic {
  stream_length: number;
  first_entry: [string, Record<string, string>] | null;
  last_entry: [string, Record<string, string>] | null;
}

export async function fetchAlerts(limit = 50, hours = 24): Promise<{ alerts: Alert[]; count: number }> {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}&hours=${hours}`, { cache: "no-store" });
  return res.json();
}

export async function fetchAlertSummary(hours = 24): Promise<{ summary: AlertSummary[] }> {
  const res = await fetch(`${API_BASE}/alerts/summary?hours=${hours}`, { cache: "no-store" });
  return res.json();
}

export async function fetchTopIPs(limit = 10, hours = 24): Promise<{ top_ips: TopIP[] }> {
  const res = await fetch(`${API_BASE}/top-ips?limit=${limit}&hours=${hours}`, { cache: "no-store" });
  return res.json();
}

export async function fetchLiveTraffic(): Promise<LiveTraffic> {
  const res = await fetch(`${API_BASE}/traffic/live`, { cache: "no-store" });
  return res.json();
}

export async function fetchHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
  return res.json();
}
