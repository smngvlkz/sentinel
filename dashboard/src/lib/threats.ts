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
  /** Which of the alert's recorded numbers to show; defaults to the per-flow ones. */
  features?: string[];
  /** For threats involving many hosts: which side is the crowd, and the feature counting it. */
  crowd?: { side: "source" | "destination"; feature: string; noun: string };
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
  REQUEST_FLOOD: {
    name: "Request flood",
    severity: "high",
    headline: (src, dst) => `${src} flooded ${dst} with requests`,
    what:
      "One device opened hundreds of complete connections to a single service within seconds, far faster than any normal app. This is how HTTP floods take down websites and apps: each request looks legitimate on its own, but the volume doesn't.",
    nextSteps: [
      "If the source is on the internet, block it at your router's firewall, or rate-limit the service if it's meant to be public.",
      "If the source is one of your own devices, find the program responsible. It could be a misbehaving app, a stuck script, or malware.",
      "If you were load-testing a server on purpose, raise request_flood.min_new_connections_10s in config/detection.toml.",
    ],
    features: ["service_new_conns_10s", "conn_packets_out", "conn_packets_in", "conn_bytes_in"],
  },
  DISTRIBUTED_FLOOD: {
    name: "Distributed flood",
    severity: "high",
    headline: (_src, dst) => `Many internet hosts converged on ${dst}`,
    what:
      "Dozens of different internet hosts started connecting to one of your devices within a minute. Spreading an attack across many machines, often a botnet, is how distributed denial-of-service (DDoS) attacks get past limits that stop any single source.",
    nextSteps: [
      "If this device isn't meant to accept connections from the internet, check your router for port forwarding or UPnP rules exposing it.",
      "If it's a server, your hosting provider or ISP can filter a large attack before it reaches you.",
      "Peer-to-peer software (torrents, some games) can look like this. If that's expected, raise distributed_flood.min_external_sources_60s.",
    ],
    features: ["responder_external_sources_60s", "responder_new_conns_10s"],
    crowd: { side: "source", feature: "responder_external_sources_60s", noun: "internet sources" },
  },
  NETWORK_SWEEP: {
    name: "Network sweep",
    severity: "medium",
    headline: (src) => `${src} probed many devices on your network`,
    what:
      "One device tried to connect to many other devices on your network, all on the same port, within a minute. That's how worms spread and how attackers map a network after getting in.",
    nextSteps: [
      "If you don't recognise the source device, disconnect it from the network and investigate.",
      "Network inventory tools, some printers and media servers scan like this. If it's one of those, raise network_sweep.min_local_hosts_60s.",
      "Note the port: 445 is Windows file sharing and 22 is SSH, both favourite targets.",
    ],
    features: ["initiator_same_port_local_hosts_60s", "initiator_new_conns_60s"],
    crowd: { side: "destination", feature: "initiator_same_port_local_hosts_60s", noun: "devices" },
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
  service_new_conns_10s: { label: "New connections to this service in 10 s", format: (v) => v.toLocaleString() },
  conn_packets_out: { label: "Packets sent in this connection", format: (v) => v.toLocaleString() },
  conn_packets_in: { label: "Packets received in this connection", format: (v) => v.toLocaleString() },
  conn_bytes_in: { label: "Data received in this connection", format: (v) => `${(v / 1024).toFixed(1)} KB` },
  responder_external_sources_60s: { label: "Internet hosts connecting in 60 s", format: (v) => v.toLocaleString() },
  responder_new_conns_10s: { label: "New connections to this device in 10 s", format: (v) => v.toLocaleString() },
  initiator_same_port_local_hosts_60s: { label: "Devices contacted on this port in 60 s", format: (v) => v.toLocaleString() },
  initiator_new_conns_60s: { label: "Connections opened in 60 s", format: (v) => v.toLocaleString() },
};

// The per-flow numbers shown for threats that don't choose their own.
export const DEFAULT_FEATURES = [
  "packet_rate", "syn_ratio", "unique_dst_ports", "packet_size", "total_packets", "flow_duration", "avg_packet_size", "byte_rate",
];

/** "63 internet sources" for threats involving many hosts on one side, else null. */
export function crowdLabel(type: string, features: Record<string, number> | undefined): {
  side: "source" | "destination";
  text: string;
} | null {
  const crowd = threatInfo(type).crowd;
  const count = crowd && features?.[crowd.feature];
  if (!crowd || !count) return null;
  return { side: crowd.side, text: `${count.toLocaleString()} ${crowd.noun}` };
}
