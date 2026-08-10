import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import {
  BROWSER_DEFAULT,
  formatDateTime,
  formatTimeOfDay,
  isValidTimeZone,
  resolveTimeZone,
  type HourFormat,
  type TimeFormat,
} from '@/lib/datetime'

/**
 * Where the preference is kept.
 *
 * localStorage, deliberately. This is a DISPLAY choice belonging to the person reading
 * the screen, not to the tenant: an operator in Sofia and an auditor reconciling against
 * UTC log exports are both right, and a server-side setting would force one of them to
 * do arithmetic in their head on every timestamp.
 *
 * Nothing sensitive is stored — a zone name and a boolean's worth of format — so this
 * carries none of the risk that keeps the access token out of storage (see the auth
 * store, which explains why THAT lives in memory only).
 */
const STORAGE_KEY = 'siem.preferences.time'

/** Display preferences, persisted locally and applied to every timestamp shown. */
export const usePreferencesStore = defineStore('preferences', () => {
  const stored = load()

  const timeZone = ref<string>(stored.timeZone)
  const hourFormat = ref<HourFormat>(stored.hourFormat)

  const format = computed<TimeFormat>(() => ({
    timeZone: timeZone.value,
    hourFormat: hourFormat.value,
  }))

  /** The zone actually in effect, named so the console can label what it is showing. */
  const activeTimeZone = computed(() => resolveTimeZone(format.value))

  /** True while the console is following the browser rather than an explicit choice. */
  const followsBrowser = computed(() => timeZone.value === '')

  // Persisted on change rather than behind a save button: the picker applies
  // immediately, and a preference that reverts on reload reads as the setting not
  // having worked.
  //
  // SYNCHRONOUS flush, deliberately. The default queues the write to the next tick, so
  // a reload in the moment right after the click — which is exactly when someone
  // changes a display setting and refreshes to check it took — would restore the old
  // value and look like the control does nothing.
  watch(format, (value) => save(value), { deep: true, flush: 'sync' })

  function setTimeZone(zone: string): void {
    // An unknown zone would throw inside Intl on every render — one bad value in
    // storage would otherwise blank every timestamp in the console.
    timeZone.value = isValidTimeZone(zone) ? zone : ''
  }

  function setHourFormat(value: HourFormat): void {
    hourFormat.value = value
  }

  /** Restores the browser's own zone and locale conventions. */
  function reset(): void {
    timeZone.value = BROWSER_DEFAULT.timeZone
    hourFormat.value = BROWSER_DEFAULT.hourFormat
  }

  /**
   * Renders a full date and time under the current preference.
   *
   * Exposed from the store so a component formats a timestamp without also having to
   * remember to read the preference — the one thing that, if forgotten, puts a second
   * clock on the screen.
   */
  function dateTime(value: string | number | Date | null | undefined, placeholder = '—'): string {
    return formatDateTime(value, format.value, placeholder)
  }

  /** Renders the time of day only, under the current preference. */
  function timeOfDay(value: string | number | Date | null | undefined, placeholder = '—'): string {
    return formatTimeOfDay(value, format.value, placeholder)
  }

  return {
    timeZone,
    hourFormat,
    format,
    activeTimeZone,
    followsBrowser,
    setTimeZone,
    setHourFormat,
    reset,
    dateTime,
    timeOfDay,
  }
})

/** Reads the stored preference, falling back to the browser's own conventions. */
function load(): TimeFormat {
  if (typeof localStorage === 'undefined') return { ...BROWSER_DEFAULT }

  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return { ...BROWSER_DEFAULT }

    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) return { ...BROWSER_DEFAULT }

    // Validated field by field rather than trusted: storage is editable by anyone at
    // the keyboard, and an invalid zone reaching Intl throws on every render.
    const candidate = parsed as Partial<TimeFormat>
    const zone = typeof candidate.timeZone === 'string' ? candidate.timeZone : ''
    const hours = candidate.hourFormat
    return {
      timeZone: isValidTimeZone(zone) ? zone : '',
      hourFormat: hours === '12' || hours === '24' ? hours : 'auto',
    }
  } catch {
    // Malformed JSON, or storage disabled entirely (private mode, or a policy).
    // Neither is a reason to fail: the console simply follows the browser.
    return { ...BROWSER_DEFAULT }
  }
}

function save(format: TimeFormat): void {
  if (typeof localStorage === 'undefined') return
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(format))
  } catch {
    // Storage full or blocked. The preference still applies for this session, which is
    // strictly better than refusing to change the display at all.
  }
}
