"use client";

import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

type Choice = "system" | "light" | "dark";

const OPTIONS: { value: Choice; label: string; Icon: typeof Sun }[] = [
  { value: "system", label: "Auto", Icon: Monitor },
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
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

  const current = OPTIONS.find((o) => o.value === choice) ?? OPTIONS[0];
  const after = OPTIONS[(OPTIONS.indexOf(current) + 1) % OPTIONS.length];

  return (
    <>
      {/* Phones: one button that steps Auto → Light → Dark, so the header fits. */}
      <button
        type="button"
        onClick={() => select(after.value)}
        aria-label={`Theme: ${current.label}. Switch to ${after.label}.`}
        title={`Theme: ${current.label}`}
        className="flex size-8 items-center justify-center rounded-lg border border-line text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg sm:hidden"
      >
        <current.Icon className="size-4" strokeWidth={1.75} aria-hidden />
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
