/**
 * Every number and fact on the site lives here, so results can be updated
 * in one place when docs/evaluation.md changes.
 *
 * Source for all CIC-IDS2017 figures: docs/evaluation.md (rules only, known
 * mislabelled host pairs excluded, scored per labelled flow).
 * Last checked against it: 2026-09-29.
 *
 * Only what works today goes in `features`; anything planned goes in `next`,
 * which the page labels "Planned" and links to the roadmap.
 */

export const site = {
  name: "SentinelAI",
  version: "0.6.2",
  repo: "https://github.com/smngvlkz/sentinel",
  evaluationDoc: "https://github.com/smngvlkz/sentinel/blob/master/docs/evaluation.md",
  roadmapDoc: "https://github.com/smngvlkz/sentinel/blob/master/docs/ROADMAP.md",
  license: "MIT",
  pitch: "Intrusion detection for your home network,\nexplained in plain language.",
  subPitch:
    "SentinelAI watches your network's traffic, spots port scans, floods and network sweeps, and tells you what each alert means and what to do about it. It runs on your own hardware.",
};

// Both taken from the same `make demo` run, so they show the same alerts.
export const screenshots = {
  light: { src: "/dashboard-light.png", width: 3200, height: 2000 },
  dark: { src: "/dashboard-dark.png", width: 3200, height: 2000 },
  alt: "The SentinelAI dashboard: alerts to review, a table of recent alerts with severity, source and destination, and counts by type.",
};

export const dataset = {
  name: "CIC-IDS2017",
  url: "https://www.unb.ca/cic/datasets/ids-2017.html",
};

export type ResultRow = { attack: string; flows: string; caught: string; minutes: string; missed?: boolean };

export type Day = {
  id: string;
  name: string;
  tag: string;
  summary: string;
  rows: ResultRow[];
  normal: { label: string; value: string }[];
};

export const days: Day[] = [
  {
    id: "friday",
    name: "Friday",
    tag: "Thresholds tuned on this day",
    summary: "A port scan, an HTTP flood and a botnet, in 9.9 million packets.",
    rows: [
      { attack: "Port scan", flows: "158,924", caught: "99.7%", minutes: "12 of 26" },
      { attack: "DDoS (HTTP flood)", flows: "128,027", caught: "99.9%", minutes: "21 of 21" },
      { attack: "Botnet (Ares)", flows: "1,966", caught: "23.9%", minutes: "387 of 592" },
    ],
    normal: [
      { label: "Normal flows wrongly flagged, check-in rule aside", value: "0 of 380,557" },
      { label: "Flagged by the check-in rule (one polling server)", value: "1,441" },
      { label: "Normal machines with a false alarm that day", value: "1 of 7" },
    ],
  },
  {
    id: "wednesday",
    name: "Wednesday",
    tag: "Held out, thresholds frozen",
    summary: "Five denial-of-service attacks SentinelAI was never tuned on, in 13.7 million packets.",
    rows: [
      { attack: "DoS Hulk (HTTP flood)", flows: "231,073", caught: "96.7%", minutes: "18 of 22" },
      { attack: "DoS GoldenEye (HTTP flood)", flows: "10,293", caught: "37.8%", minutes: "5 of 9" },
      { attack: "DoS Slowhttptest (slow HTTP)", flows: "5,499", caught: "46.2%", minutes: "7 of 20" },
      { attack: "DoS Slowloris (slow HTTP)", flows: "5,796", caught: "0%", minutes: "0 of 27", missed: true },
      { attack: "Heartbleed", flows: "11", caught: "0%", minutes: "0 of 21", missed: true },
    ],
    normal: [
      { label: "Normal flows wrongly flagged, check-in rule aside", value: "0 of 432,832" },
      { label: "Flagged by the check-in rule (one polling server)", value: "1,486" },
      { label: "Normal machines with a false alarm that day", value: "0 of 11" },
    ],
  },
  {
    id: "monday",
    name: "Monday",
    tag: "Held out, no attacks",
    summary: "Ordinary office traffic with no attacks, in 11.6 million packets.",
    rows: [],
    normal: [
      { label: "Normal flows wrongly flagged, check-in rule aside", value: "0 of 529,442" },
      { label: "Flagged by the check-in rule (two workstations and one polling server)", value: "7,877" },
      { label: "Normal machines with a false alarm that day", value: "3 of 13" },
    ],
  },
  {
    id: "tuesday",
    name: "Tuesday",
    tag: "Held out, then used once to test a fix",
    summary: "FTP and SSH password guessing, in 11.5 million packets. No version of SentinelAI has caught these: they aren't floods or scans, which is what its rules look for. Shown so you can see its limits.",
    rows: [
      { attack: "FTP password guessing", flows: "7,938", caught: "0%", minutes: "0 of 64", missed: true },
      { attack: "SSH password guessing", flows: "5,897", caught: "0%", minutes: "0 of 63", missed: true },
    ],
    normal: [
      { label: "Normal flows wrongly flagged, check-in rule aside (one alert)", value: "937 of 431,737" },
      { label: "Flagged by the check-in rule (one polling server)", value: "1,650" },
      { label: "Normal machines with a false alarm that day", value: "2 of 12" },
    ],
  },
  {
    id: "thursday",
    name: "Thursday",
    tag: "Held out, then used once to test a fix",
    summary: "Web attacks and an infiltration, in 9.2 million packets. No version of SentinelAI has caught the web attacks: each is an ordinary-looking web request, and what makes it an attack (the passwords tried, the code slipped in) is inside the request, which it doesn't read. The infiltration shows up only through the infected machine scanning the network (below). Shown so you can see its limits.",
    rows: [
      { attack: "Web login brute force", flows: "1,507", caught: "0%", minutes: "0 of 44", missed: true },
      { attack: "Cross-site scripting", flows: "652", caught: "0%", minutes: "0 of 21", missed: true },
      { attack: "SQL injection", flows: "21", caught: "0%", minutes: "0 of 3", missed: true },
      { attack: "Infiltration (as labelled)", flows: "36", caught: "0%", minutes: "0 of 53", missed: true },
    ],
    normal: [
      { label: "Normal flows wrongly flagged, check-in rule aside (mostly the infected machine's scan)", value: "66,854 of 456,163" },
      { label: "Flagged by the check-in rule (one polling server)", value: "1,644" },
      { label: "Normal machines with a false alarm that day (every one scanned by the infected machine)", value: "10 of 11" },
      { label: "…counting that documented scan as an attack (decided after seeing this result)", value: "1 of 11" },
    ],
  },
];

export const resultsCaption =
  "CIC-IDS2017, Canadian Institute for Cybersecurity. Friday's thresholds were partly tuned on the same day. Wednesday and Monday were held out: every threshold was frozen before they were replayed. Tuesday and Thursday were kept untouched to test the 0.6.2 connection-flood fix, which failed its target there (details in the evaluation). All five days are shown with 0.6.2's rules.";

export const resultNotes: string[] = [
  "Botnet flow recall looks low because every check-in before the first alert counts as missed. All five infected machines were flagged, each about 45 minutes after it started.",
  "The check-in rule is noisy. It flagged a server that polls an internet service all day on every day tested, and on Monday also two workstations that kept reconnecting to dozens of web services for hours. Timing alone can't tell that apart from malware, and the rule hasn't been tuned to hide it. On a real laptop over 24 hours it flagged a code editor and the Claude apps 50 times, so it's off by default. These results were measured with it on.",
  "An earlier version of these results had a scoring bug, found by the held-out Wednesday test. The numbers here are the corrected ones.",
  "Thursday's infiltration scores 0% because the dataset labels only 36 of its flows as attacks. SentinelAI did flag it: the infected machine scanning the whole network raised port-scan and connection-flood alerts on every machine it scanned. Those count as false alarms above, because the dataset labels the scan as normal.",
  "Tuesday's password guessing and Thursday's web attacks aren't caught by any rule: repeated logins look like normal connections, and web attacks live in page contents, which SentinelAI doesn't read.",
  "In 0.6.2, browsers opening many connections at once and quick bursts of lookups to an office server stopped raising false alarms, and floods that repeat after a pause stopped being missed. Every number on these tabs is measured with those rules. Normal machines are counted on each day leaving out every machine involved in a labelled attack.",
];

export type FeatureIcon = "radar" | "message" | "tag" | "check" | "shuffle" | "gauge" | "lock" | "play";

export type Feature = { tag: string; icon: FeatureIcon; title: string; body: string; points?: string[] };

export const features: Feature[] = [
  {
    tag: "Detection",
    icon: "radar",
    title: "Detection rules you can read",
    body: "Eight rules, each a few lines of Python with thresholds in one config file.",
    points: [
      "Port scans and network sweeps",
      "Connection floods, request floods and distributed floods",
      "Traffic bursts and oversized packets",
      "Regular check-ins, the pattern botnets use to reach their controller (off by default: everyday apps do it too)",
    ],
  },
  {
    tag: "Alerts",
    icon: "message",
    title: "Alerts in plain language",
    body: "Every alert says what happened, whether the source is on your network or the internet, the evidence behind it, and what to do next.",
  },
  {
    tag: "Names",
    icon: "tag",
    title: "Names, not just addresses",
    body: "Give your devices names like Living room TV, and optionally let SentinelAI learn which sites they talk to, so an alert reads Office laptop → api.example.com instead of two IP addresses.",
    points: [
      "Device names you set, shown everywhere, including on older alerts",
      "Optional hostnames from DNS, HTTP and TLS, kept in memory only (off by default)",
      "Anything that isn't a valid hostname is dropped, never cleaned up into a different name",
    ],
  },
  {
    tag: "Review",
    icon: "check",
    title: "A review workflow",
    body: "Mark alerts as reviewed one at a time or in bulk. The dashboard only asks for attention while something is unreviewed, then settles back to calm.",
  },
  {
    tag: "Anomaly model",
    icon: "shuffle",
    title: "An optional anomaly model",
    body: "An Isolation Forest trained on your own network's normal traffic flags what doesn't fit. It's off until you train it, and its alerts are never rated high.",
  },
  {
    tag: "Resilience",
    icon: "gauge",
    title: "Built to run unattended",
    body: "Everything SentinelAI keeps has a hard limit, in memory and on disk, so it can run for months without filling up your machine. Ten million spoofed connections leave its memory flat at about 410 MB.",
    points: [
      "Old alerts deleted after 90 days, with at most 500,000 kept (about 750 MB), so the database can't fill your disk",
      "Connections seen more than once are protected, so a flood has a much harder time pushing a slow scan out of memory before it's caught",
      "A Memory limit reached alert if a flood ever gets that far",
      "/health shows memory, the analyzer's backlog, lost packets and the database's size",
    ],
  },
  {
    tag: "Privacy",
    icon: "lock",
    title: "Private by design",
    body: "Everything runs on your hardware. By default it reads packet headers, not contents; optional hostname learning reads only DNS answers, HTTP Host headers and TLS server names. Every service listens on this machine only, unless you set a password and open the dashboard to your phone. No account, no cloud.",
  },
  {
    tag: "Demo",
    icon: "play",
    title: "See it work in two minutes",
    body: "make demo replays seven kinds of simulated attack against a full local install, no root needed. The fake internet attackers use addresses reserved for documentation, so they can't be mistaken for real ones.",
  },
];

export type NextIcon = "cpu" | "bell" | "sparkles";

export type NextItem = { icon: NextIcon; title: string; body: string };

// Planned, not built. Details and "done" criteria are in docs/ROADMAP.md.
export const next: NextItem[] = [
  {
    icon: "cpu",
    title: "Raspberry Pi installer",
    body: "A Raspberry Pi 4 or 5 on a mirror port of your switch, watching every device and starting on boot.",
  },
  {
    icon: "bell",
    title: "Phone notifications",
    body: "High-severity alerts through ntfy, email or a webhook, with quiet hours and rate limits.",
  },
  {
    icon: "sparkles",
    title: "Local AI triage",
    body: "A model on your own network adds a verdict and a reason to each alert. Advice only: it can never hide or downgrade one.",
  },
];

export type Limit = { title: string; body: string };

export const limits: Limit[] = [
  {
    title: "It can't see Wi-Fi traffic between your own devices",
    body: "Traffic between two devices on the same Wi-Fi access point never crosses a wire SentinelAI can watch. Traffic to and from the internet is still seen, but a laptop scanning your smart TV over Wi-Fi isn't.",
  },
  {
    title: "It may not keep up with a busy gigabit network",
    body: "Packet capture runs in Python. Its speed on a Raspberry Pi hasn't been measured yet, and on a saturated link it may miss packets.",
  },
  {
    title: "It misses slow attacks, very short floods, password guessing and anything inside the payload",
    body: "Slowloris sends almost no traffic, by design, and was missed completely. Password guessing over FTP and SSH looks like ordinary logins. Heartbleed and web attacks such as SQL injection live inside the traffic's contents, which SentinelAI doesn't read. All were 0% in testing. And a flood that stops within a second isn't reported, so that normal bursts of connections don't raise alarms.",
  },
  {
    title: "It detects, it doesn't block",
    body: "SentinelAI tells you what's happening. It never drops traffic, so a false alarm can't take your internet down.",
  },
];

export type Faq = { q: string; a: string };

export const faqs: Faq[] = [
  {
    q: "How is this different from Pi-hole?",
    a: "Pi-hole blocks ads and trackers by refusing DNS lookups for known domains. SentinelAI doesn't block anything: it watches traffic for attack patterns such as scans, floods and sweeps. They do different jobs and run happily side by side.",
  },
  {
    q: "Why not Suricata or Zeek?",
    a: "Suricata matches traffic against thousands of known attack signatures and reads packet contents. Zeek turns traffic into detailed logs for analysts. Both are mature and more thorough. SentinelAI is smaller: a few readable rules, a dashboard that explains each alert, and results published with their misses. If you need an enterprise IDS, use Suricata.",
  },
  {
    q: "What hardware do I need?",
    a: "A Mac or Linux machine with Docker. A Raspberry Pi 4 or 5 is planned as the recommended setup, but its installer isn't built yet, so it isn't supported today.",
  },
  {
    q: "How do I see my whole network, not just one computer?",
    a: "On its own, SentinelAI sees the traffic of the machine it runs on. To see every device, give it a copy of the traffic: a managed switch with port mirroring (about R350–R1,000) is the simplest and safest; a Raspberry Pi set up as a bridge between your router and your network sees everything but becomes a single point of failure; some routers can capture traffic themselves.",
  },
  {
    q: "Can I check it from my phone?",
    a: "Yes. Set a password, set DASHBOARD_BIND=0.0.0.0, and open the dashboard at your computer's address. Away from home, use Tailscale, a free private network between your own devices, rather than opening a port on your router. The README has the steps.",
  },
  {
    q: "Is it ready to rely on?",
    a: "Not yet. It's an early release, a learning and home-lab tool rather than a replacement for a professional security product. The numbers on this page are honest, including where it fails.",
  },
  {
    q: "Is it legal to use?",
    a: "Only monitor networks you own or have explicit permission to monitor. Capturing other people's traffic without consent is illegal in many countries.",
  },
];

export const install = {
  // Not built yet: shown as "Planned", with no install steps.
  pi: {
    title: "Raspberry Pi",
    body: "A Raspberry Pi 4 or 5 on a mirror port of your switch, watching every device and starting on boot.",
  },
  source: {
    title: "From source",
    body: "On a Mac or Linux machine with Docker and make. The demo simulates attacks, so you can see detection working in two minutes.",
    commands: ["git clone https://github.com/smngvlkz/sentinel.git", "cd sentinel", "make demo   # then open http://localhost:3001"],
    next: "To watch your real network instead, run make setup, set CAPTURE_INTERFACE in .env, then make up and make capture.",
  },
};
