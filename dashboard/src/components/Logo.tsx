/**
 * SentinelAI mark: an isometric cube drawn as a network, with a node at
 * each corner and a solid sentinel node at the centre where the edges meet.
 */
export default function Logo({ className = "size-6" }: { className?: string }) {
  const corners: [number, number][] = [
    [12, 2.75],
    [20.25, 7.5],
    [20.25, 16.5],
    [12, 21.25],
    [3.75, 16.5],
    [3.75, 7.5],
  ];

  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinejoin="round" className={className} aria-hidden>
      <polygon points={corners.map((p) => p.join(",")).join(" ")} />
      <path d="M12 12 3.75 7.5M12 12l8.25-4.5M12 12v9.25" />
      {corners.map(([x, y]) => (
        <circle key={`${x},${y}`} cx={x} cy={y} r={1.1} fill="var(--bg)" />
      ))}
      <circle cx={12} cy={12} r={2.5} fill="currentColor" stroke="none" />
    </svg>
  );
}
