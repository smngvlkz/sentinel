"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { changePassword, setUpPassword } from "@/lib/api";

const MIN_LENGTH = 8; // Matches dashboard-api/auth.py

/**
 * "setup": the first password, offered while the dashboard is reachable from
 * this machine only. "change": needs the current one; other sessions are
 * logged out, this one stays.
 */
export default function PasswordDialog({
  mode,
  onDone,
  onClose,
}: {
  mode: "setup" | "change";
  onDone: () => void;
  onClose: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The button that opened the dialog, read while rendering: by the time an
  // effect runs, autoFocus has already moved focus into the dialog.
  const [opener] = useState(() => document.activeElement as HTMLElement | null);
  // The latest onClose, so the effect below runs once. The dashboard re-renders
  // every second; re-running it would hand focus back to the opener mid-typing.
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

  const submit = async () => {
    if (next.length < MIN_LENGTH) return setError(`Use at least ${MIN_LENGTH} characters.`);
    if (next !== again) return setError("The two new passwords don't match.");
    setBusy(true);
    setError(null);
    try {
      if (mode === "setup") await setUpPassword(next);
      else await changePassword(current, next);
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't save the password.");
    } finally {
      setBusy(false);
    }
  };

  const field = (id: string, label: string, value: string, set: (v: string) => void, autoComplete: string, autoFocus = false) => (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-fg">
        {label}
      </label>
      <input
        id={id}
        type="password"
        autoFocus={autoFocus}
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => set(e.target.value)}
        className="w-full rounded-lg border border-line bg-bg px-3 py-2 text-sm focus:border-line-strong focus:outline-none"
      />
    </div>
  );

  // Rendered on <body>: it's opened from the header, whose backdrop blur would
  // otherwise make "fixed" mean the header's box instead of the window's.
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-title"
        className="fade-in-up relative w-full max-w-sm rounded-xl border border-line bg-bg p-6 shadow-2xl"
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div className="space-y-1">
            <h2 id="password-title" className="text-lg font-semibold tracking-tight">
              {mode === "setup" ? "Set a password" : "Change password"}
            </h2>
            <p className="text-sm text-fg-3">
              {mode === "setup"
                ? "From now on the dashboard asks for it, on this machine too. You'll need one before opening it from other devices."
                : "Every other device that's logged in will be logged out."}
            </p>
          </div>
          {mode === "change" && field("current-password", "Current password", current, setCurrent, "current-password", true)}
          {field("new-password", "New password", next, setNext, "new-password", mode === "setup")}
          {field("new-password-again", "New password again", again, setAgain, "new-password")}
          {error && (
            <p role="alert" className="text-sm text-high">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-line px-3 py-1.5 text-[13px] font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !next || !again || (mode === "change" && !current)}
              className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-accent-fg transition-all duration-200 hover:bg-accent-hover disabled:opacity-50"
            >
              {busy ? "Saving…" : mode === "setup" ? "Set password" : "Change password"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}
