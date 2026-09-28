"use client";

import { useEffect, useRef, useState } from "react";
import { Check, ChevronRight } from "lucide-react";
import type { Alert } from "@/lib/api";
import { crowdLabel, DEFAULT_FEATURES, FEATURE_LABELS, threatInfo } from "@/lib/threats";
import { formatDateTime, timeAgo } from "@/lib/format";
import { Address, Label, OriginTag, SeverityIndicator, ThreatIcon } from "./ui";

interface Props {
  alert: Alert;
  onClose: () => void;
  onReviewChange: (alert: Alert, reviewed: boolean) => Promise<void>;
  /** Open the next alert waiting for review; absent when there isn't one. */
  onNext?: () => void;
}

export default function AlertDrawer({ alert, onClose, onReviewChange, onNext }: Props) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reviewed = alert.reviewed_at !== null;

  const toggleReviewed = async () => {
    setSaving(true);
    setError(null);
    try {
      await onReviewChange(alert, !reviewed);
    } catch {
      setError("Couldn't save. Check that the API is running and try again.");
    } finally {
      setSaving(false);
    }
  };

  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const info = threatInfo(alert.threat_type);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key !== "Tab" || !dialogRef.current) return;
      // Keep keyboard focus inside the dialog while it's open.
      const focusable = dialogRef.current.querySelectorAll<HTMLElement>("button, a[href], [tabindex]:not([tabindex='-1'])");
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = overflow;
      opener?.focus();
    };
  }, [onClose]);

  const features = (info.features ?? DEFAULT_FEATURES)
    .filter((key) => FEATURE_LABELS[key] && alert.features?.[key] != null)
    .map((key) => [key, FEATURE_LABELS[key]] as const);
  const crowd = crowdLabel(alert.threat_type, alert.features);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <aside
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-title"
        className="drawer-in relative flex h-full w-full max-w-[500px] flex-col overflow-y-auto border-l border-line bg-bg shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-line px-6 py-5">
          <div>
            <div className="flex items-center gap-3">
              <ThreatIcon type={alert.threat_type} />
              <h2 id="alert-title" className="text-lg font-semibold tracking-tight">
                {info.name}
              </h2>
            </div>
            <div className="mt-2 flex items-center gap-3">
              <SeverityIndicator severity={info.severity} />
              <span className="font-mono text-xs text-fg-3">{formatDateTime(alert.timestamp)}</span>
            </div>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="-mr-2 rounded-lg border border-line px-2.5 py-1 text-xs font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg"
          >
            Close
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-b border-line px-6 py-3">
          {reviewed ? (
            <>
              <span className="flex items-center gap-1.5 text-[13px] text-ok">
                <Check className="size-4" strokeWidth={2.25} aria-hidden />
                Reviewed {timeAgo(alert.reviewed_at, Date.now())}
              </span>
              <button
                type="button"
                onClick={toggleReviewed}
                disabled={saving}
                className="ml-auto rounded-lg border border-line px-2.5 py-1 text-xs font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg disabled:opacity-50"
              >
                {saving ? "Saving…" : "Undo"}
              </button>
              {onNext ? (
                <button
                  type="button"
                  onClick={onNext}
                  className="flex items-center gap-1 rounded-lg bg-accent py-1.5 pr-2 pl-3 text-[13px] font-medium text-accent-fg transition-all duration-200 hover:bg-accent-hover"
                >
                  Next alert
                  <ChevronRight className="size-4" strokeWidth={2} aria-hidden />
                </button>
              ) : (
                <span className="w-full text-[13px] text-fg-3">Nothing else to review in this view.</span>
              )}
            </>
          ) : (
            <>
              <span className="text-[13px] text-fg-2">Not reviewed yet</span>
              {onNext && (
                <button
                  type="button"
                  onClick={onNext}
                  className="ml-auto rounded-lg border border-line px-2.5 py-1.5 text-[13px] font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg"
                >
                  Skip
                </button>
              )}
              <button
                type="button"
                onClick={toggleReviewed}
                disabled={saving}
                className={`${onNext ? "" : "ml-auto"} flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-accent-fg transition-all duration-200 hover:bg-accent-hover disabled:opacity-50`}
              >
                <Check className="size-4" strokeWidth={2} aria-hidden />
                {saving ? "Saving…" : "Mark as reviewed"}
              </button>
            </>
          )}
          {error && (
            <p className="w-full text-[13px] text-high" role="alert">
              {error}
            </p>
          )}
        </div>

        <dl className="mx-6 mt-5 grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2.5 rounded-xl border border-line bg-bg-2 p-4">
          <Label as="dt">From</Label>
          <dd className="flex flex-wrap items-center gap-2">
            {crowd?.side === "source" && <span className="font-medium">{crowd.text}, latest</span>}
            <Address ip={alert.source_ip} port={alert.source_port} />
            <OriginTag ip={alert.source_ip} />
          </dd>
          <Label as="dt">To</Label>
          <dd className="flex flex-wrap items-center gap-2">
            {crowd?.side === "destination" && <span className="font-medium">{crowd.text}, latest</span>}
            <Address ip={alert.destination_ip} port={alert.destination_port} />
            <OriginTag ip={alert.destination_ip} />
          </dd>
          <Label as="dt">Caught by</Label>
          <dd className="text-[13px]">
            {alert.detection_source === "ml"
              ? `Anomaly model, ${(alert.confidence * 100).toFixed(0)}% confidence`
              : "Detection rule"}
          </dd>
        </dl>

        <section className="px-6 pt-6">
          <Label as="h3">What this means</Label>
          <p className="mt-2 max-w-[60ch] text-fg-2">{info.what}</p>
        </section>

        {info.nextSteps.length > 0 && (
          <section className="px-6 pt-6">
            <Label as="h3">What to do</Label>
            <ul className="mt-2 max-w-[60ch] list-disc space-y-2 pl-5 text-fg-2 marker:text-fg-muted">
              {info.nextSteps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </section>
        )}

        {features.length > 0 && (
          <section className="px-6 py-6">
            <Label as="h3">What the detector saw</Label>
            <dl className="mt-2 divide-y divide-line">
              {features.map(([key, { label, format }]) => (
                <div key={key} className="flex items-baseline justify-between gap-4 py-2">
                  <dt className="text-fg-2">{label}</dt>
                  <dd className="font-mono text-[13px]">{format(alert.features[key])}</dd>
                </div>
              ))}
            </dl>
          </section>
        )}
      </aside>
    </div>
  );
}
