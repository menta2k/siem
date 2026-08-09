import { describe, expect, it } from 'vitest'

import { formatPayload } from '@/lib/json-format'

describe('formatPayload', () => {
  it('indents a minified vendor record', () => {
    const { text, pretty } = formatPayload('{"RayID":"8f2","Action":"block","Score":42}')

    expect(pretty).toBe(true)
    expect(text).toBe(
      ['{', '  "RayID": "8f2",', '  "Action": "block",', '  "Score": 42', '}'].join('\n'),
    )
  })

  it('indents nested objects and arrays', () => {
    const { text, pretty } = formatPayload('{"rules":[{"id":"a"}]}')

    expect(pretty).toBe(true)
    expect(text).toBe(
      ['{', '  "rules": [', '    {', '      "id": "a"', '    }', '  ]', '}'].join('\n'),
    )
  })

  // A payload that is not JSON is still evidence. Showing it as sent beats hiding it
  // behind a parse error the analyst can do nothing about.
  it('returns non-JSON verbatim', () => {
    const raw = 'GET /login 403 blocked by rule 12'
    const { text, pretty } = formatPayload(raw)

    expect(pretty).toBe(false)
    expect(text).toBe(raw)
  })

  it('returns a truncated record verbatim', () => {
    const raw = '{"RayID":"8f2","Action":"blo'

    expect(formatPayload(raw)).toEqual({ text: raw, pretty: false })
  })

  // Vendor text can be valid JSON without being an object — indenting it would only add
  // quotes around a line the analyst can already read.
  it('leaves bare scalars alone', () => {
    expect(formatPayload('"just a string"')).toEqual({ text: '"just a string"', pretty: false })
    expect(formatPayload('42')).toEqual({ text: '42', pretty: false })
    expect(formatPayload('null')).toEqual({ text: 'null', pretty: false })
  })

  it('treats a missing or empty payload as nothing to format', () => {
    expect(formatPayload(undefined)).toEqual({ text: '', pretty: false })
    expect(formatPayload(null)).toEqual({ text: '', pretty: false })
    expect(formatPayload('   ')).toEqual({ text: '   ', pretty: false })
  })

  // Parsing a multi-megabyte record blocks the main thread with the dialog already open.
  it('skips formatting beyond the size cap', () => {
    const huge = `{"pad":"${'x'.repeat(512 * 1024)}"}`

    expect(formatPayload(huge)).toEqual({ text: huge, pretty: false })
  })

  // The output is text either way. Markup in a value survives as the characters the
  // vendor sent, which is what the caller renders through interpolation.
  it('keeps markup in values as text', () => {
    const { text, pretty } = formatPayload('{"ua":"<script>alert(1)</script>"}')

    expect(pretty).toBe(true)
    expect(text).toContain('"ua": "<script>alert(1)</script>"')
  })
})
