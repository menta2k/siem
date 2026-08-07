import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const post = vi.fn()
vi.mock('@/api/client', () => ({
  api: { POST: (...args: unknown[]) => post(...args) },
  toDisplayMessage: (err: unknown) => String(err),
}))

import { useSearchStore } from '@/stores/search'

const row = (eventId: string) => ({ eventId, vendor: 'VENDOR_F5', verdict: 'VERDICT_BLOCKED' })

/** A reply that resolves only when the returned trigger is called. */
function deferred(items: unknown[], nextCursor = '') {
  let release!: () => void
  const promise = new Promise((resolve) => {
    release = () => resolve({ data: { items, page: { nextCursor, total: String(items.length) } } })
  })
  return { promise, release }
}

beforeEach(() => {
  setActivePinia(createPinia())
  post.mockReset()
})

describe('overlapping searches', () => {
  // THE BUG THIS FIXES. search() cleared the list synchronously and fetchPage() APPENDED,
  // so two searches in flight at once both cleared and then both appended — and a single
  // matching event rendered as two identical rows. It looked like duplicate data in
  // ClickHouse; the API had returned total:1 the whole time.
  it('does not duplicate rows when two searches overlap', async () => {
    const first = deferred([row('a')])
    const second = deferred([row('a')])
    post.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    const store = useSearchStore()
    const a = store.search()
    const b = store.search()
    first.release()
    second.release()
    await Promise.all([a, b])

    expect(store.items).toHaveLength(1)
    expect(store.items.map((i) => i.eventId)).toEqual(['a'])
  })

  // The reply to a search the user has already replaced must not land. Out-of-order
  // arrival would otherwise show results for the PREVIOUS filter under the current one —
  // silently wrong rather than visibly broken.
  it('discards a superseded response', async () => {
    const stale = deferred([row('stale')])
    const fresh = deferred([row('fresh')])
    post.mockReturnValueOnce(stale.promise).mockReturnValueOnce(fresh.promise)

    const store = useSearchStore()
    const a = store.search()
    const b = store.search()
    fresh.release()
    await b
    stale.release()
    await a

    expect(store.items.map((i) => i.eventId)).toEqual(['fresh'])
  })

  // Paging must still ACCUMULATE — the guard has to distinguish a superseded search from
  // a legitimate next page, or the table resets to one page and "load more" does nothing.
  it('still appends when loading the next page', async () => {
    post.mockResolvedValueOnce({
      data: { items: [row('a')], page: { nextCursor: 'c1', total: '2' } },
    })
    const store = useSearchStore()
    await store.search()

    post.mockResolvedValueOnce({ data: { items: [row('b')], page: { nextCursor: '', total: '2' } } })
    await store.loadMore()

    expect(store.items.map((i) => i.eventId)).toEqual(['a', 'b'])
  })

  // A fresh search after paging must clear the accumulated pages rather than add to them.
  it('replaces accumulated pages on a new search', async () => {
    post.mockResolvedValueOnce({
      data: { items: [row('a')], page: { nextCursor: 'c1', total: '2' } },
    })
    const store = useSearchStore()
    await store.search()

    post.mockResolvedValueOnce({ data: { items: [row('b')], page: { nextCursor: '', total: '2' } } })
    await store.loadMore()

    post.mockResolvedValueOnce({ data: { items: [row('z')], page: { nextCursor: '', total: '1' } } })
    await store.search()

    expect(store.items.map((i) => i.eventId)).toEqual(['z'])
  })

  // A page that arrives after the user has started a new search must not append onto it.
  it('discards a page superseded by a new search', async () => {
    post.mockResolvedValueOnce({
      data: { items: [row('a')], page: { nextCursor: 'c1', total: '2' } },
    })
    const store = useSearchStore()
    await store.search()

    const page = deferred([row('b')])
    post.mockReturnValueOnce(page.promise)
    const paging = store.loadMore()

    post.mockResolvedValueOnce({ data: { items: [row('z')], page: { nextCursor: '', total: '1' } } })
    await store.search()
    page.release()
    await paging

    expect(store.items.map((i) => i.eventId)).toEqual(['z'])
  })
})
