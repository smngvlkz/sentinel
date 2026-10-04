"use client";

import { useCallback, useEffect, useState } from "react";
import AccountControls from "@/components/AccountControls";
import AlertDrawer from "@/components/AlertDrawer";
import AlertTable, { type SeverityFilter, type StatusFilter } from "@/components/AlertTable";
import GettingStarted from "@/components/GettingStarted";
import LoginScreen from "@/components/LoginScreen";
import Logo from "@/components/Logo";
import ServiceStatus from "@/components/ServiceStatus";
import StatsStrip from "@/components/StatsStrip";
import StatusBar from "@/components/StatusBar";
import ThreatBreakdown from "@/components/ThreatBreakdown";
import ThemeToggle from "@/components/ThemeToggle";
import TopSources from "@/components/TopSources";
import { Cmd } from "@/components/ui";
import {
  fetchAlerts,
  fetchAlertSummary,
  fetchAuthStatus,
  fetchHealth,
  fetchStats,
  fetchTopIPs,
  nameDevice,
  needsLogin,
  reviewAlerts,
  type Alert,
  type AlertSummary,
  type AuthStatus,
  type Health,
  type Stats,
  type TopIP,
} from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { threatInfo } from "@/lib/threats";

const POLL_MS = 4000;
const ALERT_LIMIT = 100;
const REPO_URL = "https://github.com/smngvlkz/sentinel";

const WINDOWS = [
  { hours: 1, label: "1h" },
  { hours: 24, label: "24h" },
  { hours: 168, label: "7d" },
];

export default function Dashboard() {
  const [hours, setHours] = useState(24);
  const [loaded, setLoaded] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertSummary[]>([]);
  const [topIPs, setTopIPs] = useState<TopIP[]>([]);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [tableSeverity, setTableSeverity] = useState<SeverityFilter>("all");
  const [tableStatus, setTableStatus] = useState<StatusFilter>("all");
  const [markingAll, setMarkingAll] = useState(false);
  const [auth, setAuth] = useState<AuthStatus | null>(null);

  // Whether a password is set and this browser is logged in. Checked on load,
  // after logging in or out, and whenever the API asks for a login.
  const checkAuth = useCallback(async () => {
    try {
      setAuth(await fetchAuthStatus());
    } catch {
      // API unreachable: the offline message below already says so.
    }
  }, []);
  const locked = Boolean(auth?.password_set && !auth.logged_in);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const refresh = useCallback(async () => {
    try {
      setHealth(await fetchHealth());
    } catch (e) {
      if (needsLogin(e)) {
        await checkAuth(); // the session ended or expired: back to the login screen
        return;
      }
      setHealth(null);
      setLoaded(true);
      return;
    }

    // Each panel keeps its last good data if its own request fails,
    // e.g. while Postgres restarts.
    const [s, a, sum, ips] = await Promise.allSettled([
      fetchStats(hours),
      fetchAlerts(hours, {
        limit: ALERT_LIMIT,
        status: tableStatus,
        severity: tableSeverity === "all" ? undefined : tableSeverity,
      }),
      fetchAlertSummary(hours),
      fetchTopIPs(hours),
    ]);
    if (s.status === "fulfilled") setStats(s.value);
    if (a.status === "fulfilled") setAlerts(a.value.alerts);
    if (sum.status === "fulfilled") setSummary(sum.value.summary);
    if (ips.status === "fulfilled") setTopIPs(ips.value.top_ips);
    setUpdatedAt(new Date().toISOString());
    setLoaded(true);
  }, [hours, tableSeverity, tableStatus, checkAuth]);

  useEffect(() => {
    if (locked) return; // nothing to load until someone logs in
    refresh();
    const poll = setInterval(refresh, POLL_MS);
    return () => clearInterval(poll);
  }, [refresh, locked]);

  useEffect(() => {
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, []);

  const closeDrawer = useCallback(() => setSelected(null), []);

  const setTableFilter = (severity: SeverityFilter, status: StatusFilter) => {
    setTableSeverity(severity);
    setTableStatus(status);
  };

  // "Review" in the status bar: open the alert, and narrow the table behind
  // it to the same unreviewed alerts so "Next alert" walks through them.
  const startReview = (alert: Alert) => {
    setTableFilter(threatInfo(alert.threat_type).severity, "unreviewed");
    setSelected(alert);
  };

  // The next alert still waiting for review in the current table view.
  const nextToReview = alerts.find((a) => a.reviewed_at === null && a.id !== selected?.id);

  const markAllReviewed = async () => {
    setMarkingAll(true);
    try {
      await reviewAlerts({ hours, severity: tableSeverity === "all" ? undefined : tableSeverity });
      await refresh();
    } finally {
      setMarkingAll(false);
    }
  };

  const changeDeviceName = async (ip: string, name: string | null) => {
    await nameDevice(ip, name);
    setSelected((a) =>
      a && {
        ...a,
        source_device: a.source_ip === ip ? name : a.source_device,
        destination_device: a.destination_ip === ip ? name : a.destination_device,
      },
    );
    await refresh();
  };

  const changeReviewed = async (alert: Alert, reviewed: boolean) => {
    await reviewAlerts({ ids: [alert.id], reviewed });
    setSelected({ ...alert, reviewed_at: reviewed ? new Date().toISOString() : null });
    await refresh();
  };

  const capture = health?.services.capture;
  const idleMinutes =
    capture?.state === "idle" ? Math.round((capture.last_packet_seconds_ago ?? 0) / 60) : null;

  const timeRange = health && (
    <div role="radiogroup" aria-label="Time range" className="flex shrink-0 rounded-lg border border-line bg-bg-3 p-0.5">
      {WINDOWS.map((w) => (
        <button
          key={w.hours}
          type="button"
          role="radio"
          aria-checked={hours === w.hours}
          onClick={() => setHours(w.hours)}
          className={`rounded-md px-3 py-1 font-mono text-xs font-medium transition-colors duration-200 ${
            hours === w.hours ? "bg-bg text-fg shadow-sm" : "text-fg-3 hover:text-fg"
          }`}
        >
          {w.label}
        </button>
      ))}
    </div>
  );

  if (locked) return <LoginScreen onLoggedIn={checkAuth} />;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b border-line bg-bg/80 backdrop-blur">
        <div className="flex h-14 items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2.5">
            <span className="flex items-center gap-2 text-fg">
              <Logo className="size-6" />
              <span className="text-base font-semibold tracking-tight">SentinelAI</span>
            </span>
            {health && (
              <span className="rounded-full border border-line px-2 py-px font-mono text-[11px] text-fg-3">
                v{health.version}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 sm:gap-5">
            {loaded && <ServiceStatus health={health} />}
            {auth && <AccountControls auth={auth} onChange={checkAuth} />}
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="fade-in-up w-full flex-1 space-y-4 px-4 py-6 sm:px-6 lg:px-8">
        {loaded ? (
          <StatusBar health={health} stats={stats} hours={hours} now={now} onReview={startReview}>
            {timeRange}
          </StatusBar>
        ) : (
          <div className="rounded-xl border border-line bg-bg p-5 text-fg-3 shadow-sm">Checking your network…</div>
        )}

        {idleMinutes !== null && idleMinutes >= 1 && (
          <p className="rounded-xl border border-medium-line bg-medium-soft px-5 py-3 text-medium">
            No traffic for {idleMinutes} {idleMinutes === 1 ? "minute" : "minutes"}. If packet capture stopped, start
            it again with <Cmd>make capture</Cmd>.
          </p>
        )}

        {health && <StatsStrip stats={stats} health={health} />}

        {health && (
          <div
            className="grid grid-cols-[minmax(0,1fr)] items-start gap-4 lg:grid-cols-[minmax(0,1fr)_360px] 2xl:grid-cols-[minmax(0,1fr)_440px]"
          >
            <AlertTable
              alerts={alerts}
              limit={ALERT_LIMIT}
              bySeverity={stats?.by_severity}
              now={now}
              severity={tableSeverity}
              status={tableStatus}
              onFilterChange={setTableFilter}
              onMarkAllReviewed={markAllReviewed}
              markingAll={markingAll}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
              empty={
                capture?.state === "never" ? (
                  <GettingStarted />
                ) : (
                  "No alerts in this time range. They appear here as soon as something suspicious is detected."
                )
              }
            />
            <div className="space-y-4">
              <ThreatBreakdown data={summary} />
              <TopSources data={topIPs} />
            </div>
          </div>
        )}
      </main>

      <footer className="flex w-full flex-wrap justify-between gap-2 px-4 py-5 text-xs text-fg-3 sm:px-6 lg:px-8">
        <span>
          {loaded && !health
            ? `Retrying every ${POLL_MS / 1000} seconds`
            : updatedAt
              ? `Updated ${timeAgo(updatedAt, now)}`
              : "Connecting…"}
        </span>
        <a href={REPO_URL} className="transition-colors duration-200 hover:text-fg">
          Documentation on GitHub
        </a>
      </footer>

      {selected && (
        <AlertDrawer
          key={selected.id}
          alert={selected}
          onClose={closeDrawer}
          onReviewChange={changeReviewed}
          onNameDevice={changeDeviceName}
          onNext={nextToReview ? () => setSelected(nextToReview) : undefined}
        />
      )}
    </div>
  );
}
