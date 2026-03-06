"use client";

import type { AlertSummary } from "@/lib/api";
import { formatThreatType } from "@/lib/format";

export default function ThreatChart({ data }: { data: AlertSummary[] }) {
  if (!data.length) {
    return (
      <div className="border border-[#1a1a1a] bg-[#111111] h-full">
        <div className="border-b border-[#1a1a1a] px-2 py-1 text-[13px] uppercase tracking-widest text-[#444444]">
          Threat Distribution
        </div>
        <div className="p-3 text-[#333333]">NO DATA</div>
      </div>
    );
  }

  const max = Math.max(...data.map((d) => d.count));

  return (
    <div className="border border-[#1a1a1a] bg-[#111111] h-full">
      <div className="border-b border-[#1a1a1a] px-2 py-1 text-[13px] uppercase tracking-widest text-[#444444]">
        Threat Distribution
      </div>
      <div className="p-2 space-y-1">
        {data.map((d) => {
          const pct = (d.count / max) * 100;
          const color =
            d.threat_type === "SYN_FLOOD" ? "#cc3333" :
            d.threat_type === "PORT_SCAN" ? "#cc9933" :
            d.threat_type === "ANOMALY" ? "#00cc66" :
            d.threat_type === "HIGH_FREQUENCY" ? "#cc9933" :
            "#3377cc";

          return (
            <div key={d.threat_type}>
              <div className="flex items-center justify-between text-[13px] mb-0.5">
                <span className="text-[#777777]">{formatThreatType(d.threat_type)}</span>
                <span className="tabular-nums text-[#999999]">{d.count.toLocaleString()}</span>
              </div>
              <div className="h-2 bg-[#0a0a0a] border border-[#1a1a1a]">
                <div className="h-full" style={{ width: `${pct}%`, backgroundColor: color, opacity: 0.7 }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
