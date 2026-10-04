"use client";

import { useState } from "react";
import { KeyRound, LockKeyhole, LogOut } from "lucide-react";
import PasswordDialog from "@/components/PasswordDialog";
import { logOut, type AuthStatus } from "@/lib/api";

// Icon and text from sm up; icon only on phones, where the header has no room for words.
const BUTTON =
  "flex h-8 items-center justify-center gap-1.5 rounded-lg border border-line text-xs font-medium whitespace-nowrap text-fg-2 transition-colors duration-200 hover:bg-bg-2 hover:text-fg max-sm:w-8 sm:h-auto sm:px-2.5 sm:py-1";

function Label({ Icon, text }: { Icon: typeof KeyRound; text: string }) {
  return (
    <>
      <Icon className="size-4 sm:size-3.5" strokeWidth={1.75} aria-hidden />
      <span className="max-sm:sr-only">{text}</span>
    </>
  );
}

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
          <Label Icon={KeyRound} text="Change password" />
        </button>
        <button type="button" className={BUTTON} onClick={() => logOut().finally(onChange)}>
          <Label Icon={LogOut} text="Log out" />
        </button>
      </>
    );
  } else if (!auth.password_set && auth.setup_allowed) {
    controls = (
      <button type="button" className={BUTTON} onClick={() => setDialog("setup")}>
        <Label Icon={LockKeyhole} text="Set a password" />
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
