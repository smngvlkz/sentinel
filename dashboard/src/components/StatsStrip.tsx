import type { Health, Stats } from "@/lib/api";
import { Label } from "./ui";

export default function StatsStrip({ stats, health }: { stats: Stats | null; health: Health | null }) {
  const analyzer = health?.services.analyzer;
  const items: { label: string; value: string; hint: string }[] = [
    { label: "Alerts", value: stats ? stats.total_alerts.toLocaleString() : "–", hint: "In the selected range" },
    { label: "Sources", value: stats ? stats.unique_sources.toLocaleString() : "–", hint: "Distinct IPs behind alerts" },
    {
      label: "Packets checked",
      value: analyzer?.packets_processed != null ? compact(analyzer.packets_processed) : "–",
      hint: "Since the analyzer started",
    },
    {
      label: "Detection",
      value: !analyzer?.running ? "Off" : analyzer.model_loaded ? "Rules + ML" : "Rules",
      hint: analyzer?.model_loaded ? "Anomaly model loaded" : "No anomaly model trained",
    },
  ];

  return (
    <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="rounded-xl border border-line bg-bg p-4 shadow-sm sm:p-5">
          <Label as="dt">{item.label}</Label>
          <dd className="mt-2 font-mono text-xl font-medium tracking-tight sm:text-2xl">{item.value}</dd>
          <dd className="mt-1 text-xs text-fg-3">{item.hint}</dd>
        </div>
      ))}
    </dl>
  );
}

function compact(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}
