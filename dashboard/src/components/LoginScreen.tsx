"use client";

import { useState } from "react";
import Logo from "@/components/Logo";
import { Cmd } from "@/components/ui";
import { logIn } from "@/lib/api";

/** Shown instead of the dashboard once a password is set and this browser isn't logged in. */
export default function LoginScreen({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await logIn(password);
      onLoggedIn();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't log in.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="fade-in-up flex min-h-screen items-center justify-center px-4">
      <form
        className="w-full max-w-sm space-y-5 rounded-xl border border-line bg-bg p-6 shadow-sm"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="flex items-center gap-2 text-fg">
          <Logo className="size-6" />
          <span className="text-base font-semibold tracking-tight">SentinelAI</span>
        </div>
        <div className="space-y-2">
          <label htmlFor="password" className="block text-sm font-medium text-fg">
            Password
          </label>
          <input
            id="password"
            type="password"
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-line bg-bg px-3 py-2 text-sm focus:border-line-strong focus:outline-none"
          />
          {error && (
            <p role="alert" className="text-sm text-high">
              {error}
            </p>
          )}
        </div>
        <button
          type="submit"
          disabled={busy || !password}
          className="w-full rounded-lg bg-accent px-3 py-2 text-sm font-medium text-accent-fg transition-all duration-200 hover:bg-accent-hover disabled:opacity-50"
        >
          {busy ? "Logging in…" : "Log in"}
        </button>
        <p className="text-xs leading-relaxed text-fg-3">
          Forgot your password? Run <Cmd>make password</Cmd> on the machine running SentinelAI to set a new one.
        </p>
      </form>
    </main>
  );
}
