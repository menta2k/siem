import { describe, expect, it } from 'vitest'
import { cleanRules, describeRule, isComplete, overlyBroad } from '@/lib/ingest-filters'

describe('describeRule', () => {
  // The whole reason this function exists. A matched event is stored nowhere, so a rule
  // that is subtly wider than intended deletes traffic with no copy to recover from —
  // reading back what it MEANS is the only check available before the data is gone.
  it('reads back the rule as a sentence', () => {
    expect(describeRule({ field: 'request_host', op: 'equals', values: ['assets.example.com'] })).toBe(
      'Drop events where the hostname is exactly "assets.example.com".',
    )
  })

  it('lists several values as alternatives, not as a set that must all match', () => {
    expect(describeRule({ field: 'request_path', op: 'suffix', values: ['.png', '.jpg', '.css'] })).toBe(
      'Drop events where the URL path ends with ".png", ".jpg" or ".css".',
    )
  })

  // An incomplete rule must not read like a working one, or an operator saves a form
  // believing it filters something it does not.
  it('says plainly when a rule is incomplete', () => {
    for (const rule of [
      { field: 'request_host', op: 'equals', values: [] },
      { field: 'request_host', op: '', values: ['x'] },
      { field: '', op: 'equals', values: ['x'] },
      { field: 'request_host', op: 'equals', values: ['   '] },
    ]) {
      expect(describeRule(rule)).toMatch(/Incomplete/)
    }
  })

  // Quoting matters: a trailing space or an empty value is invisible otherwise, and this
  // sentence is the last thing read before traffic starts disappearing.
  it('quotes values so whitespace is visible', () => {
    expect(describeRule({ field: 'request_path', op: 'prefix', values: ['/static '] })).toContain(
      '"/static "',
    )
  })
})

describe('isComplete', () => {
  it('requires both selectors and a non-blank value', () => {
    expect(isComplete({ field: 'request_host', op: 'equals', values: ['a'] })).toBe(true)
    expect(isComplete({ field: 'request_host', op: 'equals', values: [' '] })).toBe(false)
    expect(isComplete({ field: 'request_host', op: '', values: ['a'] })).toBe(false)
    expect(isComplete({})).toBe(false)
  })
})

describe('cleanRules', () => {
  // A half-finished row left on screen must not turn the whole save into a validation
  // error the operator has to decode.
  it('drops incomplete rules rather than sending them', () => {
    const cleaned = cleanRules([
      { field: 'request_host', op: 'equals', values: ['a.example.com'] },
      { field: 'request_path', op: 'suffix', values: [] },
    ])
    expect(cleaned).toHaveLength(1)
  })

  it('trims values and removes blank ones', () => {
    const cleaned = cleanRules([{ field: 'request_path', op: 'suffix', values: ['  .png  ', '', ' '] }])
    expect(cleaned[0]?.values).toEqual(['.png'])
  })

  // Clearing every rule must produce an empty list, which is how filtering is turned off.
  it('returns an empty list when nothing is complete', () => {
    expect(cleanRules([{ field: '', op: '', values: [] }])).toEqual([])
  })
})

describe('overlyBroad', () => {
  // These are legal and occasionally intended, but far more often a mistake — and the
  // consequence cannot be undone, so it is worth saying before the save rather than
  // diagnosing afterwards from a volume graph.
  it('flags a rule that matches every path', () => {
    expect(overlyBroad({ field: 'request_path', op: 'prefix', values: ['/'] })).toBe(true)
    expect(overlyBroad({ field: 'request_path', op: 'contains', values: ['/'] })).toBe(true)
  })

  it('does not flag ordinary rules', () => {
    expect(overlyBroad({ field: 'request_path', op: 'suffix', values: ['.png'] })).toBe(false)
    expect(overlyBroad({ field: 'request_host', op: 'equals', values: ['assets.example.com'] })).toBe(
      false,
    )
    expect(overlyBroad({ field: 'request_path', op: 'prefix', values: ['/static/'] })).toBe(false)
  })

  it('does not flag an incomplete rule, which drops nothing anyway', () => {
    expect(overlyBroad({ field: 'request_path', op: 'prefix', values: [] })).toBe(false)
  })
})
