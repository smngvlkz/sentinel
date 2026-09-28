"use client";

import { useEffect, useState } from "react";

type Choice = "system" | "light" | "dark";

const OPTIONS: { value: Choice; label: string }[] = [
  { value: "system", label: "Auto" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

function apply(choice: Choice) {
  const dark = choice === "dark" || (choice === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
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

  useEffect(() => {
    // Read the saved choice after mount; the inline script in layout.tsx
    // has already applied it, so this only syncs the control.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setChoice(saved());
  }, []);

  useEffect(() => {
    if (choice !== "system") return;
    const media = matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => apply("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [choice]);

  const select = (next: Choice) => {
    setChoice(next);
    apply(next);
    try {
      if (next === "system") localStorage.removeItem("theme");
      else localStorage.setItem("theme", next);
    } catch {
      // Private mode or storage blocked: the choice still applies for this visit.
    }
  };

  return (
    <div role="radiogroup" aria-label="Theme" className="flex rounded-lg border border-line bg-bg-3 p-0.5">
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
  );
}
