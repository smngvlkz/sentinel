import {
  Activity,
  Network,
  Package,
  Radar,
  RadioTower,
  ServerCrash,
  ShieldAlert,
  Shuffle,
  Waves,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import type { Severity } from "@/lib/threats";
import { ipOrigin, ORIGIN_LABEL } from "@/lib/format";

export const SEVERITY_LABEL: Record<Severity, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

const PILL: Record<Severity | "ok", { box: string; dot: string }> = {
  high: { box: "bg-high-soft text-high border-high-line", dot: "bg-high-dot" },
  medium: { box: "bg-medium-soft text-medium border-medium-line", dot: "bg-medium-dot" },
  low: { box: "bg-low-soft text-low border-low-line", dot: "bg-low-dot" },
  ok: { box: "bg-ok-soft text-ok border-ok-line", dot: "bg-ok-dot" },
};

/** Rounded status pill with a leading dot, e.g. severity or service state. */
export function Pill({ tone, children, pulse }: { tone: Severity | "ok"; children: React.ReactNode; pulse?: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap ${PILL[tone].box}`}
    >
      <span className={`size-1.5 rounded-full ${PILL[tone].dot} ${pulse ? "live-dot" : ""}`} aria-hidden />
      {children}
    </span>
  );
}

const BARS: Record<Severity, number> = { low: 1, medium: 2, high: 3 };

const BAR_FILL: Record<Severity, string> = {
  high: "bg-high-dot",
  medium: "bg-medium-dot",
  low: "bg-fg-3",
};

/**
 * Signal-strength style severity: 1–3 ascending bars, filled bars in the
 * severity colour, then the level in neutral text. Colour stays small.
 */
export function SeverityIndicator({ severity, label = true }: { severity: Severity; label?: boolean }) {
  const filled = BARS[severity];
  return (
    <span className="inline-flex items-center gap-2" aria-label={`${SEVERITY_LABEL[severity]} severity`} role="img">
      <span className="flex h-3 items-end gap-[2px]" aria-hidden>
        {[1, 2, 3].map((n) => (
          <span
            key={n}
            className={`w-[3px] rounded-[1px] ${n <= filled ? BAR_FILL[severity] : "bg-line-strong"}`}
            style={{ height: `${4 + (n - 1) * 4}px` }}
          />
        ))}
      </span>
      {label && (
        <span className="text-[13px] leading-3 text-fg-2" aria-hidden>
          {SEVERITY_LABEL[severity]}
        </span>
      )}
    </span>
  );
}

/** Small uppercase, tracked label: the section heading style throughout. */
export function Label({ children, as: Tag = "p" }: { children: React.ReactNode; as?: "p" | "h2" | "h3" | "dt" | "span" }) {
  return <Tag className="text-xs font-medium tracking-wider text-fg-3 uppercase">{children}</Tag>;
}

export function Card({
  title,
  aside,
  children,
  className = "",
}: {
  title?: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-line bg-bg shadow-sm ${className}`} aria-label={title}>
      {title && (
        <header className="flex min-h-12 items-center justify-between gap-4 border-b border-line px-5">
          <Label as="h2">{title}</Label>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

const THREAT_ICON: Record<string, LucideIcon> = {
  SYN_FLOOD: Waves,
  PORT_SCAN: Radar,
  HIGH_FREQUENCY: Activity,
  LARGE_PAYLOAD: Package,
  ANOMALY: Shuffle,
  REQUEST_FLOOD: ServerCrash,
  DISTRIBUTED_FLOOD: Network,
  NETWORK_SWEEP: Waypoints,
  BEACONING: RadioTower,
};

/** Monochrome icon for a threat type; shape, not colour, tells types apart. */
export function ThreatIcon({ type, size = "md" }: { type: string; size?: "sm" | "md" }) {
  const Icon = THREAT_ICON[type] ?? ShieldAlert;
  if (size === "sm") return <Icon className="size-3.5 shrink-0 text-fg-3" strokeWidth={1.75} aria-hidden />;
  return (
    <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-line bg-bg-2" aria-hidden>
      <Icon className="size-4 text-fg-2" strokeWidth={1.75} />
    </span>
  );
}

export function Address({
  ip,
  port,
  name,
  device,
  layout = "stack",
}: {
  ip: string;
  port?: string;
  /** Optional hostname — shown as the primary label when known. */
  name?: string | null;
  /** Friendly device name someone set; wins over the learned hostname. */
  device?: string | null;
  /**
   * stack — name above, muted IP below (drawer / table cells).
   * inline — name then muted IP on one line (tight spots).
   * banner — "name · ip" for prose in the status strip.
   */
  layout?: "stack" | "inline" | "banner";
}) {
  const portSuffix =
    port && port !== "0" ? <span className="text-fg-3">:{port}</span> : null;
  const label = device || name;
  // Same type as the alert title ("Unusual traffic"): body size, sans, medium.
  const hostLabel = (
    <span className="truncate font-medium leading-tight" title={device && name ? `${name} · ${ip}` : ip}>
      {label}
    </span>
  );
  const ipLine = (
    <span className="font-mono text-xs text-fg-3">
      {ip}
      {portSuffix}
    </span>
  );

  if (!label) {
    return (
      <span className="font-mono text-[13px] whitespace-nowrap">
        {ip}
        {portSuffix}
      </span>
    );
  }

  if (layout === "banner") {
    return (
      <span className="whitespace-nowrap">
        <span className="font-medium">{label}</span>
        <span className="text-fg-3"> · </span>
        <span className="font-mono text-xs text-fg-3">{ip}</span>
      </span>
    );
  }

  if (layout === "inline") {
    return (
      <span className="inline-flex max-w-full flex-wrap items-baseline gap-x-1.5">
        {hostLabel}
        {ipLine}
      </span>
    );
  }

  return (
    <span className="flex min-w-0 flex-col gap-0.5">
      {hostLabel}
      {ipLine}
    </span>
  );
}

export function OriginTag({ ip }: { ip: string }) {
  const origin = ipOrigin(ip);
  const tone = origin === "internet" ? "border-medium-line bg-medium-soft text-medium" : "border-line bg-bg-3 text-fg-3";
  return (
    <span className={`inline-block rounded-md border px-1.5 py-px text-[11px] font-medium whitespace-nowrap ${tone}`}>
      {ORIGIN_LABEL[origin]}
    </span>
  );
}

export function Cmd({ children }: { children: React.ReactNode }) {
  return <code className="rounded-md bg-code px-1.5 py-0.5 font-mono text-[12px] text-fg">{children}</code>;
}
