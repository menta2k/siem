import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { usePreferencesStore } from '@/stores/preferences'

const STORAGE_KEY = 'siem.preferences.time'
const INSTANT = '2026-08-10T14:30:45.000Z'

beforeEach(() => {
  localStorage.clear()
  setActivePinia(createPinia())
})

afterEach(() => {
  localStorage.clear()
})

describe('preferences store', () => {
  // Nothing may change appearance until someone asks for it: the default is whatever
  // the analyst's own machine already does.
  it('follows the browser until a choice is made', () => {
    const prefs = usePreferencesStore()

    expect(prefs.timeZone).toBe('')
    expect(prefs.hourFormat).toBe('auto')
    expect(prefs.followsBrowser).toBe(true)
  })

  it('applies the chosen zone and hour format to a timestamp', () => {
    const prefs = usePreferencesStore()

    prefs.setTimeZone('UTC')
    prefs.setHourFormat('24')
    expect(prefs.dateTime(INSTANT)).toContain('14:30:45')

    prefs.setTimeZone('Europe/Sofia')
    expect(prefs.dateTime(INSTANT)).toContain('17:30:45')

    prefs.setHourFormat('12')
    expect(prefs.dateTime(INSTANT)).toMatch(/05:30:45.*PM/i)
  })

  // A preference that reverts on reload reads as the setting not having worked.
  it('persists a choice and restores it', () => {
    const first = usePreferencesStore()
    first.setTimeZone('Asia/Tokyo')
    first.setHourFormat('24')

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}')).toEqual({
      timeZone: 'Asia/Tokyo',
      hourFormat: '24',
    })

    // A fresh store, as a page reload would build.
    setActivePinia(createPinia())
    const restored = usePreferencesStore()

    expect(restored.timeZone).toBe('Asia/Tokyo')
    expect(restored.activeTimeZone).toBe('Asia/Tokyo')
  })

  // Storage is editable by anyone at the keyboard, and a bad zone reaching Intl throws
  // on EVERY render — one junk value would otherwise blank every timestamp shown.
  it('ignores a stored value it cannot use', () => {
    for (const junk of [
      '{"timeZone":"Mars/Olympus","hourFormat":"24"}',
      '{"timeZone":42,"hourFormat":"nonsense"}',
      'not json at all',
      '[]',
    ]) {
      localStorage.setItem(STORAGE_KEY, junk)
      setActivePinia(createPinia())
      const prefs = usePreferencesStore()

      expect(prefs.timeZone).toBe('')
      expect(prefs.dateTime(INSTANT)).not.toBe('—')
    }
  })

  it('refuses an invalid zone at the setter too', () => {
    const prefs = usePreferencesStore()

    prefs.setTimeZone('Europe/Sofia')
    prefs.setTimeZone('Mars/Olympus')

    expect(prefs.timeZone).toBe('')
  })

  it('resets to the browser default', () => {
    const prefs = usePreferencesStore()
    prefs.setTimeZone('UTC')
    prefs.setHourFormat('12')

    prefs.reset()

    expect(prefs.timeZone).toBe('')
    expect(prefs.hourFormat).toBe('auto')
    expect(prefs.followsBrowser).toBe(true)
  })

  it('names the zone in effect so the console can label it', () => {
    const prefs = usePreferencesStore()
    prefs.setTimeZone('America/New_York')

    expect(prefs.activeTimeZone).toBe('America/New_York')
  })

  it('renders a missing timestamp as the placeholder the caller asked for', () => {
    const prefs = usePreferencesStore()

    expect(prefs.dateTime(null)).toBe('—')
    expect(prefs.dateTime(undefined, 'Never')).toBe('Never')
  })
})
