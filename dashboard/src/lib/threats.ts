// Plain-language descriptions of each threat type, shown in the alert
// detail panel. Written for someone who runs a home or small-office
// network, not a security analyst.

export type Severity = "high" | "medium" | "low";

export interface ThreatInfo {
  name: string;
  /** Keep in sync with SEVERITY in dashboard-api/main.py, which filters and counts by it. */
  severity: Severity;
  /** One sentence for lists: "{src} ... {dst}". */
  headline: (src: string, dst: string) => string;
  what: string;
  nextSteps: string[];
}

export const THREATS: Record<string, ThreatInfo> = {
  SYN_FLOOD: {
    name: "Connection flood",
    severity: "high",
    headline: (src, dst) => `${src} flooded ${dst} with connection requests`,
    what:
      "A stream of half-open connection requests (SYN packets). Each one makes the target set aside memory and wait for a reply that never comes. Enough of them can slow a machine down or knock it offline.",
    nextSteps: [
      "If the source is on the internet, block it at your router's firewall. For a sustained attack, your ISP can filter it upstream.",
      "If the source is inside your network, find that device. It may be infected, or an app may be stuck retrying a connection.",
    ],
  },
  PORT_SCAN: {
    name: "Port scan",
    severity: "medium",
    headline: (src, dst) => `${src} checked which ports are open on ${dst}`,
    what:
      "Someone tried many different ports on one machine to see which ones answer. Each open port is a possible way in, so scanning is usually the first step before an attack.",
    nextSteps: [
      "Scans from the internet are common background noise. They're harmless if your router isn't forwarding ports you don't use, so check its port-forwarding settings.",
      "A scan from inside your network is more concerning. Find the device and check what's running on it.",
    ],
  },
  HIGH_FREQUENCY: {
    name: "Traffic burst",
    severity: "medium",
    headline: (src, dst) => `${src} sent an unusually fast burst of traffic to ${dst}`,
    what:
      "One source sent a rapid stream of small packets that weren't part of a normal connection. That's the signature of a flood meant to overwhelm a device or service. Large downloads don't trigger this.",
    nextSteps: [
      "Check what the source device was doing at that time.",
      "If this was expected, such as a game server or a VoIP device, raise high_frequency.min_packet_rate in config/detection.toml and run make restart.",
    ],
  },
  LARGE_PAYLOAD: {
    name: "Oversized packet",
    severity: "low",
    headline: (src, dst) => `${src} sent an oversized packet to ${dst}`,
    what:
      "A single packet was far larger than most networks allow (usually 1,500 bytes), outside any normal connection. It can be a malformed packet crafted to crash software, or simply jumbo frames on a network set up for them.",
    nextSteps: [
      "If your network uses jumbo frames, raise large_payload.min_packet_size in config/detection.toml.",
      "Otherwise, look at which service the source was talking to on the destination port.",
    ],
  },
  ANOMALY: {
    name: "Unusual traffic",
    severity: "medium",
    headline: (src, dst) => `Traffic from ${src} to ${dst} didn't match your normal patterns`,
    what:
      "The machine-learning model has learned what your network usually looks like, and this traffic didn't fit. It isn't a specific attack, just a prompt to take a look.",
    nextSteps: [
      "Compare the numbers below with what you'd expect from these two devices.",
      "If normal activity keeps getting flagged, record more baseline traffic and retrain (make train-collect, then make train-model).",
    ],
  },
};

export function threatInfo(type: string): ThreatInfo {
  return (
    THREATS[type] ?? {
      name: type.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase()),
      severity: "low",
      headline: (src, dst) => `${src} triggered a ${type} alert against ${dst}`,
      what: "This alert type has no description yet.",
      nextSteps: [],
    }
  );
}

// Friendly labels for the flow features stored with each alert.
export const FEATURE_LABELS: Record<string, { label: string; format: (v: number) => string }> = {
  packet_rate: { label: "Packets per second", format: (v) => v.toFixed(0) },
  syn_ratio: { label: "Share that were connection requests", format: (v) => `${(v * 100).toFixed(0)}%` },
  unique_dst_ports: { label: "Different ports tried", format: (v) => v.toFixed(0) },
  packet_size: { label: "Size of this packet", format: (v) => `${v.toLocaleString()} bytes` },
  total_packets: { label: "Packets in this conversation", format: (v) => v.toLocaleString() },
  flow_duration: { label: "Conversation length", format: (v) => `${v.toFixed(1)} s` },
  avg_packet_size: { label: "Average packet size", format: (v) => `${v.toFixed(0)} bytes` },
  byte_rate: { label: "Data rate", format: (v) => `${(v / 1024).toFixed(1)} KB/s` },
};
