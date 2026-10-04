import type { Alert, Health, Stats } from "@/lib/api";
import { threatInfo, type Severity } from "@/lib/threats";
import { plural, timeAgo } from "@/lib/format";
import { Address, Cmd, Pill } from "./ui";

const PERIOD: Record<number, string> = {
  1: "the last hour",
  24: "the last 24 hours",
  168: "the last 7 days",
};

const ATTENTION_LABEL: Record<Severity, string> = {
  high: "Review needed",
  medium: "Worth checking",
  low: "Low risk",
};

// An alert this recent is treated as still happening.
const ONGOING_MS = 2 * 60 * 1000;

interface Props {
  health: Health | null;
  stats: Stats | null;
  hours: number;
  now: number;
  onReview: (alert: Alert) => void;
  children?: React.ReactNode;
}

/**
 * Answers "is my network okay?". Only unreviewed alerts ask for attention,
 * so once everything has been reviewed the bar settles back to calm.
 */
export default function StatusBar({ health, stats, hours, now, onReview, children }: Props) {
  const period = PERIOD[hours] ?? `the last ${hours} hours`;
  let pill: React.ReactNode;
  let title: string;
  let detail: React.ReactNode;
  let context: string | null = null;
  let action: React.ReactNode = null;

  if (!health) {
    pill = <Pill tone="high">Offline</Pill>;
    title = "Can't reach the SentinelAI API";
    detail = (
      <>
        Start the services with <Cmd>make up</Cmd> or check them with <Cmd>make status</Cmd>. If other devices
        can open the dashboard, the API won&apos;t start until a password is set: run <Cmd>make password</Cmd>.
      </>
    );
  } else if (!health.services.database.ok || !health.services.redis.ok) {
    pill = <Pill tone="high">Degraded</Pill>;
    const down = [!health.services.database.ok && "Database", !health.services.redis.ok && "Redis"].filter(Boolean);
    title = `${down.join(" and ")} ${down.length > 1 ? "are" : "is"} down. Alerts aren't being recorded.`;
    detail = (
      <>
        See what went wrong with <Cmd>make logs</Cmd>.
      </>
    );
  } else if (health.services.capture.state === "never" && !stats?.total_alerts) {
    pill = <Pill tone="low">Waiting</Pill>;
    title = "Waiting for network traffic";
    detail = "Everything is running. Start packet capture or the demo to see results.";
  } else if (!stats || stats.total_alerts === 0) {
    pill = <Pill tone="ok">All clear</Pill>;
    title = "No threats detected";
    detail = `Nothing suspicious in ${period}.`;
  } else if (!stats.attention) {
    pill = <Pill tone="ok">All reviewed</Pill>;
    title = "Every alert has been reviewed";
    detail = `${plural(stats.total_alerts, "alert")} from ${plural(stats.unique_sources, "source")} in ${period}, nothing new since.`;
  } else {
    const { severity, count, latest } = stats.attention;
    const info = threatInfo(latest.threat_type);
    const ongoing = now - new Date(latest.timestamp).getTime() < ONGOING_MS;
    pill = (
      <Pill tone={severity} pulse={ongoing && severity === "high"}>
        {ATTENTION_LABEL[severity]}
      </Pill>
    );
    title = `${plural(count, `${severity}-severity alert`)} to review`;
    detail = (
      <>
        {ongoing ? "Happening now: " : "Latest: "}
        {info.name.toLowerCase()} from{" "}
        <Address ip={latest.source_ip} name={latest.source_name} device={latest.source_device} layout="banner" /> to{" "}
        <Address
          ip={latest.destination_ip}
          name={latest.destination_name}
          device={latest.destination_device}
          layout="banner"
        />
        ,{" "}
        {timeAgo(latest.timestamp, now)}.
      </>
    );
    context = `${plural(stats.total_alerts, "alert")} from ${plural(stats.unique_sources, "source")} in ${period}.`;
    action = (
      <button
        type="button"
        onClick={() => onReview(latest)}
        className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium whitespace-nowrap text-accent-fg transition-all duration-200 hover:bg-accent-hover"
      >
        Review
      </button>
    );
  }

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-line bg-bg p-5 shadow-sm lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2.5">
          {pill}
          <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        </div>
        <p className="mt-1.5 text-fg-2">{detail}</p>
        {context && <p className="mt-0.5 text-[13px] text-fg-3">{context}</p>}
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {action}
        {children}
      </div>
    </div>
  );
}
