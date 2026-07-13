/**
 * escapeText.ts
 * CRITICAL SECURITY UTILITY — always use this before rendering any user input.
 * Never use innerHTML or dangerouslySetInnerHTML with untrusted data.
 */

const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
}

/**
 * Escapes a string for safe rendering as text content.
 * Strips null bytes and control characters as well.
 */
export function escapeText(input: unknown): string {
  if (input === null || input === undefined) return ''
  const str = String(input)
  // Strip null bytes and dangerous control chars (except tab/newline/cr)
  const stripped = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  return stripped.replace(/[&<>"'`=/]/g, (char) => HTML_ESCAPE_MAP[char] ?? char)
}

/**
 * Truncates a string and escapes it — safe for display in badges/labels.
 */
export function escapeAndTruncate(input: unknown, maxLen = 120): string {
  const escaped = escapeText(input)
  if (escaped.length <= maxLen) return escaped
  return escaped.slice(0, maxLen) + '…'
}

/**
 * Removes all characters that could execute in any context.
 * Use for forensic export sanitization.
 */
export function sanitizeForExport(input: unknown): string {
  if (input === null || input === undefined) return ''
  const str = String(input)
  return str
    .replace(/[\x00-\x1F\x7F]/g, ' ')   // control chars → space
    .replace(/[<>]/g, (c) => (c === '<' ? '‹' : '›'))  // angle brackets → guillemets
    .replace(/javascript:/gi, 'javascript​:')  // ZWJ break
    .replace(/data:/gi, 'data​:')
    .replace(/vbscript:/gi, 'vbscript​:')
    .trim()
}
