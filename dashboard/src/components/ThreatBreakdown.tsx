import type { AlertSummary } from "@/lib/api";
import { threatInfo } from "@/lib/threats";
import { Card, SeverityIndicator, ThreatIcon } from "./ui";

export default function ThreatBreakdown({ data }: { data: AlertSummary[] }) {
  if (!data.length) return null;
  const max = Math.max(...data.map((d) => d.count));

  return (
    <Card title="By type">
      <ul className="space-y-4 p-5">
        {data.map((d) => {
          const info = threatInfo(d.threat_type);
          return (
            <li key={d.threat_type} className="flex items-center gap-3">
              <ThreatIcon type={d.threat_type} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate font-medium">{info.name}</span>
                  <SeverityIndicator severity={info.severity} label={false} />
                  <span className="w-14 text-right font-mono text-[13px] text-fg-2">{d.count.toLocaleString()}</span>
                </div>
                <div className="mt-1.5 h-1 rounded-full bg-bg-3" aria-hidden>
                  <div
                    className="h-full rounded-full bg-fg-3"
                    style={{ width: `${Math.max(2, (d.count / max) * 100)}%` }}
                  />
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
