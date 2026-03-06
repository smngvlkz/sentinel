"use client";

interface StatusIndicatorProps {
  label: string;
  active: boolean;
}

export default function StatusIndicator({ label, active }: StatusIndicatorProps) {
  return (
    <span className="inline-flex items-center gap-1 text-[12px]">
      <span
        className={`inline-block w-1.5 h-1.5 ${active ? "bg-[#00cc66]" : "bg-[#cc3333]"}`}
        style={active ? { animation: "blink 2s ease-in-out infinite" } : undefined}
      />
      <span className="text-[#444444] uppercase">{label}</span>
      <span className={active ? "text-[#00cc66]" : "text-[#cc3333]"}>{active ? "OK" : "DOWN"}</span>
    </span>
  );
}
