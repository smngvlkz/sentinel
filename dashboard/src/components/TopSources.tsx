import type { TopIP } from "@/lib/api";
import { threatInfo } from "@/lib/threats";
import { Address, Card, OriginTag, ThreatIcon } from "./ui";

export default function TopSources({ data }: { data: TopIP[] }) {
  if (!data.length) return null;

  return (
    <Card title="Top sources">
      <ul>
        {data.map((ip) => (
          <li key={ip.source_ip} className="border-b border-line px-5 py-3 last:border-b-0">
            <div className="flex items-center gap-2">
              <Address ip={ip.source_ip} device={ip.source_device} layout="inline" />
              <OriginTag ip={ip.source_ip} />
              <span className="ml-auto font-mono text-[13px] text-fg-2">{ip.alert_count.toLocaleString()}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
              {ip.threat_types.map((t) => (
                <span key={t} className="flex items-center gap-1.5 text-xs text-fg-3">
                  <ThreatIcon type={t} size="sm" />
                  {threatInfo(t).name}
                </span>
              ))}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
