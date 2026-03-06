export function formatThreatType(raw: string): string {
  return raw.replace(/_/g, " ");
}
