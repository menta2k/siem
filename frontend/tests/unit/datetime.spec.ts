import { describe, expect, it } from 'vitest'

import {
  BROWSER_DEFAULT,
  formatDateTime,
  formatTimeOfDay,
  isValidTimeZone,
  resolveTimeZone,
} from '@/lib/datetime'

// A fixed instant: 2026-08-10T14:30:45Z. Sofia is UTC+3 in August, so the same moment
// is 17:30:45 there — the offset is what a timezone preference is FOR.
const INSTANT = '2026-08-10T14:30:45.000Z'

describe('formatDateTime', () => {
  it('renders the instant in the chosen zone', () => {
    const utc = formatDateTime(INSTANT, { timeZone: 'UTC', hourFormat: '24' })
    const sofia = formatDateTime(INSTANT, { timeZone: 'Europe/Sofia', hourFormat: '24' })

    expect(utc).toContain('14:30:45')
    expect(sofia).toContain('17:30:45')
  })

  it('honours the hour format', () => {
    const twentyFour = formatDateTime(INSTANT, { timeZone: 'UTC', hourFormat: '24' })
    const twelve = formatDateTime(INSTANT, { timeZone: 'UTC', hourFormat: '12' })

    expect(twentyFour).toContain('14:30:45')
    expect(twentyFour).not.toMatch(/[AP]M/i)
    expect(twelve).toContain('02:30:45')
    expect(twelve).toMatch(/PM/i)
  })

  // The same instant, three ways to show it. None of them changes what was stored.
  it('shows one instant differently without changing it', () => {
    const stored = new Date(INSTANT).toISOString()

    formatDateTime(INSTANT, { timeZone: 'Asia/Tokyo', hourFormat: '12' })

    expect(new Date(INSTANT).toISOString()).toBe(stored)
  })

  // "Invalid Date" in a table reads as a broken console; "—" reads as an absent value,
  // which is what it is.
  it('returns the placeholder for anything that is not a moment', () => {
    for (const value of [null, undefined, '', 'not a date']) {
      expect(formatDateTime(value, BROWSER_DEFAULT)).toBe('—')
    }
  })

  it('accepts a caller-supplied placeholder', () => {
    expect(formatDateTime(null, BROWSER_DEFAULT, 'Never')).toBe('Never')
  })

  // A bad zone would throw inside Intl on every render. The timestamp must survive.
  it('falls back to the browser rendering for an invalid zone', () => {
    const rendered = formatDateTime(INSTANT, { timeZone: 'Mars/Olympus', hourFormat: '24' })

    expect(rendered).not.toBe('—')
    expect(rendered.length).toBeGreaterThan(0)
  })

  it('accepts a Date, a string and an epoch alike', () => {
    const format = { timeZone: 'UTC', hourFormat: '24' } as const
    const fromString = formatDateTime(INSTANT, format)

    expect(formatDateTime(new Date(INSTANT), format)).toBe(fromString)
    expect(formatDateTime(new Date(INSTANT).getTime(), format)).toBe(fromString)
  })
})

describe('formatTimeOfDay', () => {
  it('renders the time without the date', () => {
    const rendered = formatTimeOfDay(INSTANT, { timeZone: 'UTC', hourFormat: '24' })

    expect(rendered).toContain('14:30:45')
    expect(rendered).not.toContain('2026')
  })

  it('returns the placeholder for a missing value', () => {
    expect(formatTimeOfDay(null, BROWSER_DEFAULT)).toBe('—')
  })
})

describe('resolveTimeZone', () => {
  // A timestamp with no zone beside it is ambiguous exactly when it matters most, so the
  // console has to be able to NAME the zone it is rendering in.
  it('names the explicit zone', () => {
    expect(resolveTimeZone({ timeZone: 'Europe/Sofia', hourFormat: 'auto' })).toBe('Europe/Sofia')
  })

  it('names the browser zone when none is chosen', () => {
    expect(resolveTimeZone(BROWSER_DEFAULT)).toBe(
      Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
    )
  })
})

describe('isValidTimeZone', () => {
  it('accepts real zones and the browser default', () => {
    expect(isValidTimeZone('UTC')).toBe(true)
    expect(isValidTimeZone('Europe/Sofia')).toBe(true)
    expect(isValidTimeZone('')).toBe(true)
  })

  it('rejects anything Intl cannot use', () => {
    expect(isValidTimeZone('Mars/Olympus')).toBe(false)
    expect(isValidTimeZone('nonsense')).toBe(false)
  })
})
