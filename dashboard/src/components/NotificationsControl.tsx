"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Bell, BellOff, BellRing } from "lucide-react";
import { Cmd } from "@/components/ui";
import {
  fetchNotifications,
  sendTestNotification,
  type ChannelResult,
  type NotificationChannel,
  type NotificationStatus,
} from "@/lib/api";
import { timeAgo } from "@/lib/format";

// Same look as the account buttons beside it: icon and text from sm up, icon only on phones.
const BUTTON =
  "flex h-8 items-center justify-center gap-1.5 rounded-lg border border-line text-xs font-medium whitespace-nowrap text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg max-sm:w-8 sm:h-auto sm:px-2.5 sm:py-1";

const CHANNEL_NAME: Record<NotificationChannel, string> = { ntfy: "ntfy", email: "Email", webhook: "Webhook" };
const SEVERITY_WORDS: Record<string, string> = {
  high: "High-severity alerts",
  medium: "Medium and high-severity alerts",
  low: "Every alert",
};
const STATUS_MS = 30_000;
const OPEN_STATUS_MS = 2_000;

const list = (channels: NotificationChannel[]) => channels.map((c) => CHANNEL_NAME[c]).join(", ");

function clock(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** One line for where things stand, and what to do about it if anything. */
function summary(s: NotificationStatus): { tone: "ok" | "off" | "problem"; title: string; detail: React.ReactNode } {
  if (!s.running) {
    return {
      tone: "problem",
      title: "The notifier isn't running",
      detail: (
        <>
          Start it with <Cmd>make up</Cmd>. Until then, alerts are recorded here but nothing is sent.
        </>
      ),
    };
  }
  if (s.error) {
    return {
      tone: "problem",
      title: "Notification settings need fixing",
      detail: (
        <>
          <span className="break-words [overflow-wrap:anywhere]">{s.error}.</span> Fix it in{" "}
          <Cmd>config/notifications.toml</Cmd>; changes apply within a few seconds.
        </>
      ),
    };
  }
  if (!s.enabled) {
    return {
      tone: "off",
      title: "Notifications are off",
      detail: (
        <>
          Turn them on in <Cmd>config/notifications.toml</Cmd>. The README&apos;s Notifications section walks through
          phone, email and chat.
        </>
      ),
    };
  }
  return {
    tone: "ok",
    title: "Notifications are on",
    detail: `${SEVERITY_WORDS[s.min_severity ?? "high"]} go to ${list(s.channels)}.${
      s.quiet_now ? " Quiet hours now: only what quiet hours let through is sent." : ""
    }`,
  };
}

/**
 * A message isn't getting through: still being retried, or given up on with
 * nothing sent successfully since.
 */
function stuck(s: NotificationStatus) {
  const p = s.problem;
  if (!p) return false;
  if (p.status === "pending") return true;
  return !s.last_sent || Date.parse(s.last_sent.sent_at) < Date.parse(p.created_at);
}

function resultText(r: ChannelResult) {
  if (r.status === "sent") return "sent";
  if (r.status === "failed") return `failed: ${r.last_error ?? "unknown error"}`;
  if (r.attempts > 0) return `failed, retrying: ${r.last_error ?? "unknown error"}`;
  return "sending…";
}

function NotificationsDialog({
  status,
  onClose,
  refresh,
}: {
  status: NotificationStatus | null;
  onClose: () => void;
  refresh: () => Promise<void>;
}) {
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [testedAt, setTestedAt] = useState<string | null>(null);
  // As in PasswordDialog: the opener, read while rendering, and the latest
  // onClose in a ref, so the effect below runs once.
  const [opener] = useState(() => document.activeElement as HTMLElement | null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCloseRef.current();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      opener?.focus();
    };
  }, [opener]);

  // Live while open, so a test's result shows up as it happens.
  useEffect(() => {
    const poll = setInterval(refresh, OPEN_STATUS_MS);
    return () => clearInterval(poll);
  }, [refresh]);

  const test = async () => {
    setTesting(true);
    setTestError(null);
    try {
      const { requested_at } = await sendTestNotification();
      setTestedAt(requested_at);
      await refresh();
    } catch (e) {
      setTestError(e instanceof Error ? e.message : "Couldn't ask for a test.");
    } finally {
      setTesting(false);
    }
  };

  const s = status && summary(status);
  // Only show a test result from this dialog's own click, not an old one.
  const ownTest =
    testedAt && status?.last_test && Date.parse(status.last_test.requested_at) >= Date.parse(testedAt)
      ? status.last_test
      : null;
  const canTest = Boolean(status?.running && !status.error && status.channels.length);
  const now = Date.now();

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="notifications-title"
        className="fade-in-up relative w-full max-w-md space-y-4 rounded-xl border border-line bg-bg p-6 shadow-2xl"
      >
        <div className="space-y-1">
          <h2 id="notifications-title" className="text-lg font-semibold tracking-tight">
            Notifications
          </h2>
          {s ? (
            <>
              <p
                className={`text-sm font-medium ${s.tone === "ok" ? "text-ok" : s.tone === "problem" ? "text-high" : "text-fg"}`}
              >
                {s.title}
              </p>
              <p className="text-sm text-fg-3">{s.detail}</p>
            </>
          ) : (
            <p className="text-sm text-fg-3">Checking…</p>
          )}
        </div>

        {status && (status.last_sent || stuck(status)) && (
          <dl className="space-y-2 rounded-lg border border-line bg-bg-2 px-3 py-2.5 text-[13px]">
            {status.last_sent && (
              <div>
                <dt className="text-fg-3">Last sent</dt>
                <dd className="text-fg">
                  {status.last_sent.title}, {timeAgo(status.last_sent.sent_at, now)}
                  {status.sent_24h > 1 && <span className="text-fg-3"> · {status.sent_24h} in the last day</span>}
                </dd>
              </div>
            )}
            {status.problem && stuck(status) && (
              <div>
                <dt className="text-fg-3">Not getting through</dt>
                <dd className="break-words text-high [overflow-wrap:anywhere]">
                  {CHANNEL_NAME[status.problem.channel]}: {status.problem.last_error}
                  {status.problem.status === "pending"
                    ? ` Trying again at ${clock(status.problem.next_attempt_at)}.`
                    : " Gave up after several tries."}
                </dd>
              </div>
            )}
          </dl>
        )}

        {ownTest && (
          <ul className="space-y-1 text-[13px]" aria-live="polite">
            {!ownTest.handled_at && <li className="text-fg-3">Waiting for the notifier…</li>}
            {ownTest.results.map((r) => (
              <li key={r.channel} className={r.status === "sent" ? "text-ok" : r.attempts > 0 ? "text-high" : "text-fg-3"}>
                <span className="font-medium">{CHANNEL_NAME[r.channel]}</span>: {resultText(r)}
              </li>
            ))}
          </ul>
        )}
        {testError && (
          <p role="alert" className="text-sm text-high">
            {testError}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-line px-3 py-1.5 text-[13px] font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg"
          >
            Close
          </button>
          <button
            type="button"
            onClick={test}
            disabled={!canTest || testing}
            className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-accent-fg transition-all duration-200 hover:bg-accent-hover disabled:opacity-50"
          >
            {testing ? "Sending…" : "Send test notification"}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

/** Header button showing whether notifications are on; opens their status and a test button. */
export default function NotificationsControl() {
  const [status, setStatus] = useState<NotificationStatus | null>(null);
  const [open, setOpen] = useState(false);

  // Failures are ignored: the API is unreachable or asking for a login, and the page says so already.
  const refresh = useCallback(() => fetchNotifications().then(setStatus, () => {}), []);

  useEffect(() => {
    const first = setTimeout(refresh, 0);
    const poll = setInterval(refresh, STATUS_MS);
    return () => {
      clearTimeout(first);
      clearInterval(poll);
    };
  }, [refresh]);

  const on = status?.enabled && status.running;
  const problem = status && (!status.running || Boolean(status.error) || stuck(status));
  const Icon = problem ? BellRing : on ? Bell : BellOff;
  const label = !status ? "Notifications" : problem ? "Notifications: needs attention" : on ? "Notifications on" : "Notifications off";

  return (
    <>
      <button type="button" className={BUTTON} onClick={() => setOpen(true)} aria-label={label} title={label}>
        <Icon className={`size-4 sm:size-3.5 ${problem ? "text-high" : ""}`} strokeWidth={1.75} aria-hidden />
        <span className="max-sm:sr-only">{on && !problem ? "Notifications on" : "Notifications"}</span>
      </button>
      {open && <NotificationsDialog status={status} onClose={() => setOpen(false)} refresh={refresh} />}
    </>
  );
}
