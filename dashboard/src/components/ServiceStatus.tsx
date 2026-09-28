import type { Health } from "@/lib/api";

type Tone = "ok" | "warn" | "down";

interface Item {
  label: string;
  tone: Tone;
  detail: string;
}

const DOT: Record<Tone, string> = {
  ok: "bg-ok-dot",
  warn: "bg-medium-dot",
  down: "bg-high-dot",
};

function items(health: Health | null): Item[] {
  if (!health) {
    return [{ label: "API", tone: "down", detail: "Not reachable" }];
  }
  const { capture, analyzer, database, redis } = health.services;

  const traffic: Item =
    capture.state === "live"
      ? { label: "Traffic", tone: "ok", detail: "Packets arriving" }
      : capture.state === "idle"
        ? {
            label: "Traffic",
            tone: "warn",
            detail: `No packets for ${Math.round((capture.last_packet_seconds_ago ?? 0) / 60)} min`,
          }
        : { label: "Traffic", tone: "warn", detail: "Waiting for capture" };

  return [
    traffic,
    analyzer.running
      ? {
          label: "Analyzer",
          tone: "ok",
          detail: analyzer.model_loaded ? "Rules and ML model" : "Rules only (no ML model trained)",
        }
      : { label: "Analyzer", tone: "down", detail: "Not running" },
    { label: "Database", tone: database.ok ? "ok" : "down", detail: database.ok ? "Connected" : "Not reachable" },
    { label: "Redis", tone: redis.ok ? "ok" : "down", detail: redis.ok ? "Connected" : "Not reachable" },
  ];
}

export default function ServiceStatus({ health }: { health: Health | null }) {
  return (
    <ul className="hidden items-center gap-4 text-xs font-medium text-fg-2 md:flex" aria-label="Service status">
      {items(health).map((item) => (
        <li key={item.label} className="flex items-center gap-1.5" title={item.detail}>
          <span
            className={`size-1.5 rounded-full ${DOT[item.tone]} ${item.tone === "ok" && item.label === "Traffic" ? "live-dot" : ""}`}
            aria-hidden
          />
          {item.label}
          <span className="sr-only">: {item.detail}</span>
        </li>
      ))}
    </ul>
  );
}
