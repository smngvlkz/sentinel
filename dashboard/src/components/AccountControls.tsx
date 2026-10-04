"use client";

import { useState } from "react";
import PasswordDialog from "@/components/PasswordDialog";
import { logOut, type AuthStatus } from "@/lib/api";

const BUTTON =
  "rounded-lg border border-line px-2.5 py-1 text-xs font-medium text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg";

/** Header controls: set a first password, or change it and log out. */
export default function AccountControls({ auth, onChange }: { auth: AuthStatus; onChange: () => void }) {
  const [dialog, setDialog] = useState<"setup" | "change" | null>(null);

  const done = () => {
    setDialog(null);
    onChange();
  };

  let controls = null;
  if (auth.password_set && auth.logged_in) {
    controls = (
      <>
        <button type="button" className={BUTTON} onClick={() => setDialog("change")}>
          Change password
        </button>
        <button type="button" className={BUTTON} onClick={() => logOut().finally(onChange)}>
          Log out
        </button>
      </>
    );
  } else if (!auth.password_set && auth.setup_allowed) {
    controls = (
      <button type="button" className={BUTTON} onClick={() => setDialog("setup")}>
        Set a password
      </button>
    );
  }

  return (
    <>
      {controls && <div className="flex items-center gap-2">{controls}</div>}
      {dialog && <PasswordDialog mode={dialog} onDone={done} onClose={() => setDialog(null)} />}
    </>
  );
}
