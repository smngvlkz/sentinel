"use client";

import { Check } from "lucide-react";
import type { Alert, ReviewStatus, Stats } from "@/lib/api";
import { crowdLabel, threatInfo, type Severity } from "@/lib/threats";
import { formatDateTime, shortAgo } from "@/lib/format";
import { Address, Card, SeverityIndicator, ThreatIcon } from "./ui";

export type SeverityFilter = "all" | Severity;
export type StatusFilter = Extract<ReviewStatus, "all" | "unreviewed">;

const SEVERITY_TABS: { key: SeverityFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
];

const STATUS_TABS: { key: StatusFilter; label: string }[] = [
  { key: "unreviewed", label: "To review" },
  { key: "all", label: "All" },
];

const TH = "px-3 py-2.5 text-xs font-medium tracking-wider text-fg-3 uppercase";

interface Props {
  alerts: Alert[];
  limit: number;
  bySeverity: Stats["by_severity"] | undefined;
  now: number;
  severity: SeverityFilter;
  status: StatusFilter;
  onFilterChange: (severity: SeverityFilter, status: StatusFilter) => void;
  onMarkAllReviewed: () => void;
  markingAll: boolean;
  selectedId: number | null;
  onSelect: (alert: Alert) => void;
  /** Shown when there are no alerts at all in the time range. */
  empty: React.ReactNode;
}

export default function AlertTable({
  alerts,
  limit,
  bySeverity,
  now,
  severity,
  status,
  onFilterChange,
  onMarkAllReviewed,
  markingAll,
  selectedId,
  onSelect,
  empty,
}: Props) {
  const count = (s: SeverityFilter, st: StatusFilter): number => {
    if (!bySeverity) return 0;
    const pick = (x: { total: number; unreviewed: number }) => (st === "unreviewed" ? x.unreviewed : x.total);
    return s === "all" ? Object.values(bySeverity).reduce((sum, x) => sum + pick(x), 0) : pick(bySeverity[s]);
  };
  const totalInRange = count("all", "all");
  const unreviewedHere = count(severity, "unreviewed");
  const matching = count(severity, status);
  const label = severity === "all" ? "" : `${severity}-severity `;

  const toolbar = totalInRange > 0 && (
    <div className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-2.5">
      <Segmented
        label="Review status"
        options={STATUS_TABS.map((t) => ({ ...t, count: count(severity, t.key) }))}
        value={status}
        onChange={(v) => onFilterChange(severity, v)}
      />
      <Segmented
        label="Severity"
        options={SEVERITY_TABS.map((t) => ({ ...t, count: count(t.key, status) }))}
        value={severity}
        onChange={(v) => onFilterChange(v, status)}
      />
      {unreviewedHere > 0 && (
        <button
          type="button"
          onClick={onMarkAllReviewed}
          disabled={markingAll}
          className="flex w-full items-center justify-center gap-1.5 rounded-lg sm:ml-auto sm:w-auto border border-line bg-bg px-2.5 py-1 text-xs font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg disabled:opacity-50"
        >
          <Check className="size-3.5" strokeWidth={2} aria-hidden />
          {markingAll ? "Marking…" : `Mark ${unreviewedHere.toLocaleString()} ${label}as reviewed`}
        </button>
      )}
    </div>
  );

  let body: React.ReactNode;
  if (totalInRange === 0) {
    body = <div className="p-5 text-fg-2">{empty}</div>;
  } else if (alerts.length === 0) {
    body = (
      <div className="flex flex-wrap items-center gap-3 p-5 text-fg-2">
        {status === "unreviewed" ? `No ${label}alerts left to review.` : `No ${label}alerts in this time range.`}
        {(status !== "all" || severity !== "all") && (
          <button
            type="button"
            onClick={() => onFilterChange("all", "all")}
            className="text-[13px] font-medium text-link hover:underline"
          >
            Show all alerts
          </button>
        )}
      </div>
    );
  } else {
    body = (
      <div className="md:max-h-[620px] md:overflow-auto">
        {/* Phones: one stacked row per alert. A five-column table can't fit. */}
        <ul className="md:hidden">
          {alerts.map((a) => {
            const info = threatInfo(a.threat_type);
            const reviewed = a.reviewed_at !== null;
            return (
              <li key={a.id} className="border-b border-line last:border-b-0">
                <button
                  type="button"
                  onClick={() => onSelect(a)}
                  aria-current={a.id === selectedId || undefined}
                  className={`flex w-full items-start gap-3 px-4 py-3 text-left transition-colors duration-200 hover:bg-bg-2 ${
                    a.id === selectedId ? "bg-bg-3" : ""
                  } ${reviewed ? "text-fg-3" : ""}`}
                >
                  <ThreatIcon type={a.threat_type} />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <span className={`truncate ${reviewed ? "" : "font-medium"}`}>{info.name}</span>
                      <span className="ml-auto flex shrink-0 items-center gap-1.5 font-mono text-xs text-fg-3">
                        {reviewed && <Check className="size-3.5 text-ok" strokeWidth={2.25} aria-label="Reviewed" role="img" />}
                        {shortAgo(a.timestamp, now)}
                      </span>
                    </span>
                    <span className="mt-1 flex items-center gap-2">
                      <SeverityIndicator severity={info.severity} />
                    </span>
                    {/* Source, then "→ destination" below it: the same two lines in every row. */}
                    <span className="mt-1.5 flex flex-col gap-0.5 text-fg-2">
                      <Endpoint alert={a} side="source" layout="inline" />
                      <span className="flex min-w-0 items-baseline gap-1.5">
                        <span className="text-fg-muted" aria-label="to">→</span>
                        <Endpoint alert={a} side="destination" layout="inline" />
                      </span>
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>

        <table className="hidden w-full table-fixed border-collapse text-left md:table">
          <colgroup>
            <col className="w-[26%]" />
            <col className="w-[130px]" />
            <col />
            <col />
            <col className="w-[104px]" />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-bg-2">
            <tr className="border-b border-line">
              <th scope="col" className={`${TH} pl-5`}>Alert</th>
              <th scope="col" className={TH}>Severity</th>
              <th scope="col" className={TH}>Source</th>
              <th scope="col" className={TH}>Destination</th>
              <th scope="col" className={`${TH} pr-5 text-right`}>Time</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => {
              const info = threatInfo(a.threat_type);
              const selected = a.id === selectedId;
              const reviewed = a.reviewed_at !== null;
              return (
                <tr
                  key={a.id}
                  onClick={() => onSelect(a)}
                  className={`cursor-pointer border-b border-line transition-colors duration-200 last:border-b-0 hover:bg-bg-2 ${
                    selected ? "bg-bg-3" : ""
                  } ${reviewed ? "text-fg-3" : ""}`}
                >
                  <td className="py-2 pr-3 pl-5">
                    <div className="flex items-center gap-3">
                      <ThreatIcon type={a.threat_type} />
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelect(a);
                        }}
                        aria-current={selected || undefined}
                        className={`truncate text-left hover:underline ${reviewed ? "" : "font-medium"}`}
                      >
                        {info.name}
                      </button>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <SeverityIndicator severity={info.severity} />
                  </td>
                  <td className="px-3 py-2.5">
                    <Endpoint alert={a} side="source" />
                  </td>
                  <td className="px-3 py-2.5">
                    <Endpoint alert={a} side="destination" />
                  </td>
                  <td className="py-2.5 pr-5 pl-3 text-right font-mono text-xs whitespace-nowrap text-fg-3">
                    <span className="inline-flex items-center gap-1.5" title={formatDateTime(a.timestamp)}>
                      {reviewed && (
                        <Check className="size-3.5 text-ok" strokeWidth={2.25} aria-label="Reviewed" role="img" />
                      )}
                      {shortAgo(a.timestamp, now)}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {matching > alerts.length && (
          <p className="border-t border-line px-5 py-2.5 text-xs text-fg-3">
            Showing the latest {alerts.length.toLocaleString()} of {matching.toLocaleString()}.
            {alerts.length >= limit ? " Narrow the time range or severity to see older ones." : ""}
          </p>
        )}
      </div>
    );
  }

  return (
    <Card title="Alerts">
      {toolbar}
      {body}
    </Card>
  );
}

function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { key: T; label: string; count: number }[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex rounded-lg border border-line bg-bg-3 p-0.5">
      {options.map((o) => (
        <button
          key={o.key}
          type="button"
          role="radio"
          aria-checked={value === o.key}
          onClick={() => onChange(o.key)}
          className={`rounded-md px-2.5 py-0.5 text-xs font-medium transition-colors duration-200 ${
            value === o.key ? "bg-bg text-fg shadow-sm" : "text-fg-3 hover:text-fg"
          }`}
        >
          {o.label} <span className="font-mono text-fg-muted">{o.count.toLocaleString()}</span>
        </button>
      ))}
    </div>
  );
}

/** One address, or "63 internet sources" when that side of the alert is a crowd. */
function Endpoint({
  alert,
  side,
  layout,
}: {
  alert: Alert;
  side: "source" | "destination";
  layout?: "stack" | "inline";
}) {
  const crowd = crowdLabel(alert.threat_type, alert.features);
  if (crowd?.side === side) return <span className="text-[13px] font-medium">{crowd.text}</span>;
  return side === "source" ? (
    <Address ip={alert.source_ip} name={alert.source_name} device={alert.source_device} layout={layout} />
  ) : (
    <Address
      ip={alert.destination_ip}
      port={alert.destination_port}
      name={alert.destination_name}
      device={alert.destination_device}
      layout={layout}
    />
  );
}
