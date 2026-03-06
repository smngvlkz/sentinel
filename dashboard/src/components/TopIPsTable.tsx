"use client";

import type { TopIP } from "@/lib/api";
import { formatThreatType } from "@/lib/format";

export default function TopIPsTable({ data }: { data: TopIP[] }) {
  return (
    <div className="border border-[#1a1a1a] bg-[#111111] h-full">
      <div className="border-b border-[#1a1a1a] px-2 py-1 text-[14px] uppercase tracking-widest text-[#444444]">
        Top Offenders
      </div>
      <div className="overflow-auto">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-[#1a1a1a] text-[14px] text-[#444444] uppercase">
              <th className="text-left px-2 py-1 font-normal">#</th>
              <th className="text-left px-2 py-1 font-normal">Source</th>
              <th className="text-right px-2 py-1 font-normal">Hits</th>
              <th className="text-left px-2 py-1 font-normal">Classification</th>
            </tr>
          </thead>
          <tbody>
            {data.map((ip, i) => (
              <tr
                key={ip.source_ip}
                className={`border-b border-[#111111] ${i === 0 ? "bg-[#1a0a0a]" : "hover:bg-[#151515]"}`}
              >
                <td className="px-2 py-1 text-[#333333] tabular-nums">{String(i + 1).padStart(2, "0")}</td>
                <td className="px-2 py-1 text-[#999999] tabular-nums">{ip.source_ip}</td>
                <td className="px-2 py-1 text-right tabular-nums text-[#cc3333] font-bold">
                  {ip.alert_count.toLocaleString()}
                </td>
                <td className="px-2 py-1">
                  <div className="flex gap-1">
                    {ip.threat_types.map((t) => (
                      <span key={t} className="text-[14px] text-[#666666]">{formatThreatType(t)}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {!data.length && (
              <tr><td colSpan={4} className="px-2 py-3 text-[#333333]">NO DATA</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
