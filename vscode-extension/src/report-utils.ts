/** The extension is packaged separately from the ESM CLI report runtime. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]!));
}

export function reportSeverity(value: string): string {
  return ['critical', 'high', 'medium', 'low'].includes(value) ? value : 'medium';
}
