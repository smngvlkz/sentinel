"use client";

import type { Alert } from "@/lib/api";
import { formatThreatType } from "@/lib/format";

function ts(raw: string) {
  const d = new Date(raw);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

const SEV: Record<string, string> = {
  SYN_FLOOD: "CRIT",
  PORT_SCAN: "WARN",
  HIGH_FREQUENCY: "WARN",
  LARGE_PAYLOAD: "INFO",
  ANOMALY: "CRIT",
};

const SEV_COLOR: Record<string, string> = {
  CRIT: "text-[#cc3333]",
  WARN: "text-[#cc9933]",
  INFO: "text-[#3377cc]",
};

export default function AlertFeed({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="border border-[#1a1a1a] bg-[#111111]">
      <div className="border-b border-[#1a1a1a] px-2 py-1 flex items-center justify-between">
        <span className="text-[14px] uppercase tracking-widest text-[#444444]">Event Log</span>
        <span className="text-[14px] text-[#333333]">{alerts.length} entries</span>
      </div>
      <div className="overflow-auto max-h-[280px] font-mono">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-[#1a1a1a] text-[14px] text-[#333333] uppercase sticky top-0 bg-[#111111]">
              <th className="text-left px-2 py-1 font-normal w-16">Time</th>
              <th className="text-left px-2 py-1 font-normal w-10">Sev</th>
              <th className="text-left px-2 py-1 font-normal w-28">Type</th>
              <th className="text-left px-2 py-1 font-normal">Source</th>
              <th className="text-left px-2 py-1 font-normal">Dest</th>
              <th className="text-right px-2 py-1 font-normal w-12">Conf</th>
              <th className="text-left px-2 py-1 font-normal w-12">Eng</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => {
              const sev = SEV[a.threat_type] || "INFO";
              return (
                <tr key={a.id} className="border-b border-[#0f0f0f] hover:bg-[#151515]">
                  <td className="px-2 py-0.5 text-[#444444] tabular-nums">{ts(a.timestamp)}</td>
                  <td className={`px-2 py-0.5 font-bold ${SEV_COLOR[sev]}`}>{sev}</td>
                  <td className="px-2 py-0.5 text-[#888888]">{formatThreatType(a.threat_type)}</td>
                  <td className="px-2 py-0.5 text-[#999999] tabular-nums">{a.source_ip}:{a.source_port}</td>
                  <td className="px-2 py-0.5 text-[#666666] tabular-nums">{a.destination_ip}:{a.destination_port}</td>
                  <td className="px-2 py-0.5 text-right tabular-nums text-[#666666]">{(a.confidence * 100).toFixed(0)}%</td>
                  <td className="px-2 py-0.5 text-[#444444]">{a.detection_source === "rules" ? "RUL" : "ML"}</td>
                </tr>
              );
            })}
            {!alerts.length && (
              <tr><td colSpan={7} className="px-2 py-3 text-[#333333]">AWAITING EVENTS...</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
