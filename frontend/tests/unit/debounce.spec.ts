import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { debounce } from '@/lib/debounce'

beforeEach(() => vi.useFakeTimers())
afterEach(() => vi.useRealTimers())

describe('debounce', () => {
  // THE POINT. A filter box that queries on every keystroke sends one request per
  // character and renders whichever reply lands last — which is not necessarily the one
  // for what the user finally typed.
  it('runs once for a burst of calls', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced()
    debounced()
    debounced()
    vi.advanceTimersByTime(300)

    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('does not run before the delay elapses', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced()
    vi.advanceTimersByTime(299)
    expect(fn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  // Each keystroke restarts the clock, so the query waits for a pause in typing rather
  // than firing mid-word on a partial IP address that matches nothing.
  it('restarts the delay on each call', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced()
    vi.advanceTimersByTime(200)
    debounced()
    vi.advanceTimersByTime(200)
    expect(fn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(100)
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('passes the latest arguments through', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced('first')
    debounced('second')
    vi.advanceTimersByTime(300)

    expect(fn).toHaveBeenCalledWith('second')
  })

  // A later burst must fire again rather than be swallowed by the first.
  it('runs again for a separate burst', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced()
    vi.advanceTimersByTime(300)
    debounced()
    vi.advanceTimersByTime(300)

    expect(fn).toHaveBeenCalledTimes(2)
  })

  // Leaving the page mid-delay must not fire the query into a torn-down component.
  it('can be cancelled before it fires', () => {
    const fn = vi.fn()
    const debounced = debounce(fn, 300)

    debounced()
    debounced.cancel()
    vi.advanceTimersByTime(300)

    expect(fn).not.toHaveBeenCalled()
  })
})
