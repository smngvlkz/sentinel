"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

type Choice = "system" | "light" | "dark";

const OPTIONS: { value: Choice; label: string }[] = [
  { value: "system", label: "Auto" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

/** Applies the choice and returns whether the dashboard is now dark. */
function apply(choice: Choice): boolean {
  const dark = choice === "dark" || (choice === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  return dark;
}

function saved(): Choice {
  try {
    const t = localStorage.getItem("theme");
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

export default function ThemeToggle() {
  const [choice, setChoice] = useState<Choice>("system");
  // The theme actually showing, for the phone button's label.
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    // Read the saved choice after mount; the inline script in layout.tsx
    // has already applied it, so this only syncs the control.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setChoice(saved());
    setIsDark(document.documentElement.dataset.theme === "dark");
  }, []);

  useEffect(() => {
    if (choice !== "system") return;
    const media = matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setIsDark(apply("system"));
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [choice]);

  const select = (next: Choice) => {
    setChoice(next);
    setIsDark(apply(next));
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {
      // Private mode or storage blocked: the choice still applies for this visit.
    }
  };

  return (
    <>
      {/* Phones: one sun/moon button, like the website's. It follows the system
          until tapped, then flips between light and dark. It shows the theme
          you'd switch to; the icon comes from data-theme on <html>, which the
          inline script in layout.tsx sets before first paint. */}
      <button
        type="button"
        onClick={() => select(isDark ? "light" : "dark")}
        aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
        title={isDark ? "Light theme" : "Dark theme"}
        className="flex size-8 items-center justify-center rounded-lg border border-line text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg sm:hidden"
      >
        <Moon className="size-4 dark:hidden" strokeWidth={1.75} aria-hidden />
        <Sun className="hidden size-4 dark:block" strokeWidth={1.75} aria-hidden />
      </button>
      <div role="radiogroup" aria-label="Theme" className="hidden rounded-lg border border-line bg-bg-3 p-0.5 sm:flex">
      {OPTIONS.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={choice === o.value}
          onClick={() => select(o.value)}
          className={`rounded-md px-2 py-0.5 text-xs font-medium transition-colors duration-200 ${
            choice === o.value ? "bg-bg text-fg shadow-sm" : "text-fg-3 hover:text-fg"
          }`}
        >
          {o.label}
        </button>
      ))}
      </div>
    </>
  );
}
