"use client";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  severity?: "normal" | "warn" | "crit";
}

export default function StatCard({ label, value, sub, severity = "normal" }: StatCardProps) {
  const valColor = severity === "crit" ? "text-[#cc3333]" : severity === "warn" ? "text-[#cc9933]" : "text-[#cccccc]";

  return (
    <div className="border border-[#1a1a1a] bg-[#111111]">
      <div className="border-b border-[#1a1a1a] px-2 py-1 text-[12px] uppercase tracking-widest text-[#444444]">
        {label}
      </div>
      <div className="px-2 py-2">
        <span className={`text-lg font-bold ${valColor} tabular-nums`}>
          {typeof value === "number" ? value.toLocaleString() : value}
        </span>
        {sub && <span className="ml-2 text-[12px] text-[#444444]">{sub}</span>}
      </div>
    </div>
  );
}
