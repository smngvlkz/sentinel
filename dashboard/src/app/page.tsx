"use client";

import { useEffect, useState, useCallback } from "react";
import StatCard from "@/components/StatCard";
import ThreatChart from "@/components/ThreatChart";
import TopIPsTable from "@/components/TopIPsTable";
import AlertFeed from "@/components/AlertFeed";
import StatusIndicator from "@/components/StatusIndicator";
import {
  fetchAlerts,
  fetchAlertSummary,
  fetchTopIPs,
  fetchLiveTraffic,
  fetchHealth,
  type Alert,
  type AlertSummary,
  type TopIP,
} from "@/lib/api";
import { formatThreatType } from "@/lib/format";

const POLL_MS = 4000;

export default function Dashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary[]>([]);
  const [topIPs, setTopIPs] = useState<TopIP[]>([]);
  const [streamLen, setStreamLen] = useState(0);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [apiUp, setApiUp] = useState(false);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(async () => {
    try {
      const [aRes, sRes, iRes, tRes, hRes] = await Promise.all([
        fetchAlerts(50),
        fetchAlertSummary(),
        fetchTopIPs(15),
        fetchLiveTraffic(),
        fetchHealth(),
      ]);
      setAlerts(aRes.alerts);
      setSummary(sRes.summary);
      setTopIPs(iRes.top_ips);
      setStreamLen(tRes.stream_length);
      setTotalAlerts(sRes.summary.reduce((a, s) => a + s.count, 0));
      setApiUp(hRes.status === "ok");
      setTick((t) => t + 1);
    } catch {
      setApiUp(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, POLL_MS);
    return () => clearInterval(iv);
  }, [refresh]);

  const now = new Date();
  const timeStr = now.toLocaleTimeString("en-GB", { hour12: false });
  const dateStr = now.toLocaleDateString("en-ZA");

  return (
    <div className="min-h-screen bg-[#0c0c0c] flex flex-col">
      {/* ── Top Bar ── */}
      <header className="border-b border-[#1a1a1a] bg-[#0a0a0a] px-3 py-1.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-4">
          <span className="text-[14px] font-bold tracking-wider">
            <span className="text-[#cc3333]">SENTINEL</span>
            <span className="text-[#555555]">AI</span>
          </span>
          <span className="text-[12px] text-[#2a2a2a]">|</span>
          <span className="text-[12px] text-[#333333]">NIDS v2.4.1</span>
          <span className="text-[12px] text-[#2a2a2a]">|</span>
          <span className="text-[12px] text-[#333333]">NODE: mac-mini-m4</span>
        </div>
        <div className="flex items-center gap-4">
          <StatusIndicator label="REDIS" active={streamLen > 0} />
          <StatusIndicator label="PG" active={apiUp} />
          <StatusIndicator label="API" active={apiUp} />
          <span className="text-[12px] text-[#2a2a2a]">|</span>
          <span className="text-[12px] text-[#333333] tabular-nums">{dateStr}</span>
          <span className="text-[12px] text-[#555555] tabular-nums">{timeStr}</span>
          <span className="text-[12px] text-[#222222] tabular-nums">cycle:{tick}</span>
        </div>
      </header>

      {/* ── Main Grid ── */}
      <div className="flex-1 p-2 flex flex-col gap-2 overflow-hidden">
        {/* Row 1: Stats */}
        <div className="grid grid-cols-5 gap-2 shrink-0">
          <StatCard label="Total Alerts (24h)" value={totalAlerts} severity="crit" />
          <StatCard label="Stream Depth" value={streamLen} sub="pkts" />
          <StatCard label="Unique Sources" value={topIPs.length} severity={topIPs.length > 5 ? "warn" : "normal"} />
          <StatCard
            label="Top Threat"
            value={summary.length ? formatThreatType(summary[0].threat_type) : "---"}
            severity={summary.length ? "crit" : "normal"}
          />
          <StatCard
            label="Avg Confidence"
            value={summary.length ? `${(summary.reduce((a, s) => a + s.avg_confidence, 0) / summary.length * 100).toFixed(1)}%` : "---"}
          />
        </div>

        {/* Row 2: Charts + Table */}
        <div className="grid grid-cols-3 gap-2 flex-1 min-h-0">
          <ThreatChart data={summary} />
          <div className="col-span-2">
            <TopIPsTable data={topIPs} />
          </div>
        </div>

        {/* Row 3: Event Log */}
        <div className="shrink-0">
          <AlertFeed alerts={alerts} />
        </div>
      </div>

      {/* ── Status Bar ── */}
      <footer className="border-t border-[#1a1a1a] bg-[#0a0a0a] px-3 py-1 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3 text-[12px] text-[#333333]">
          <span>CAPTURE: LIVE</span>
          <span className="text-[#1a1a1a]">|</span>
          <span>ENGINE: RULES{summary.some(s => s.threat_type === "ANOMALY") ? "+ML" : ""}</span>
          <span className="text-[#1a1a1a]">|</span>
          <span>POLL: {POLL_MS / 1000}s</span>
        </div>
        <div className="text-[12px] text-[#222222]">
          sentinelai
        </div>
      </footer>
    </div>
  );
}
