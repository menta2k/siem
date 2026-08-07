/**
 * Copies text to the clipboard, reporting whether it worked.
 *
 * `navigator.clipboard` is SECURE-CONTEXT ONLY, exactly like `crypto.randomUUID`. Served
 * over plain HTTP on anything but localhost it is undefined, so a copy button built on it
 * alone silently does nothing — and this one is showing a credential that is displayed
 * once and cannot be recovered. Losing it to a dead button means rotating again.
 *
 * The fallback is the old `execCommand('copy')` path, which has no such restriction.
 * Returning false rather than throwing lets the caller keep the token on screen and tell
 * the user to select it by hand, which is the only honest outcome when both fail.
 */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Permission denied or a non-secure context that still exposes the API; fall
      // through to the legacy path rather than giving up.
    }
  }

  if (typeof document === 'undefined') return false

  const area = document.createElement('textarea')
  area.value = text
  // Kept out of view but still focusable — a hidden element cannot be selected, and
  // an on-screen one would make the page jump.
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.top = '-1000px'
  area.style.opacity = '0'

  document.body.appendChild(area)
  try {
    area.select()
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    document.body.removeChild(area)
  }
}
