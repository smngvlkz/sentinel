import { Cmd } from "./ui";

/**
 * Shown in place of the alert table when no packets have ever arrived,
 * which almost always means capture hasn't been started yet.
 */
export default function GettingStarted() {
  return (
    <div className="max-w-[62ch] space-y-3">
      <p>No network traffic has reached SentinelAI yet. Start one of these:</p>
      <div className="grid gap-3 sm:grid-cols-2">
        <Option
          title="Watch your real network"
          body="Captures packets from the interface set in .env. Needs sudo to read raw traffic."
          command="make capture"
        />
        <Option
          title="Try it with simulated attacks"
          body="Replays a flood, a port scan and more every minute. Doesn't touch your real network."
          command="make demo"
        />
      </div>
    </div>
  );
}

function Option({ title, body, command }: { title: string; body: string; command: string }) {
  return (
    <div className="rounded-xl border border-line bg-bg-2 p-4">
      <p className="font-medium text-fg">{title}</p>
      <p className="mt-1 text-[13px] text-fg-2">{body}</p>
      <p className="mt-3">
        <Cmd>$ {command}</Cmd>
      </p>
    </div>
  );
}
