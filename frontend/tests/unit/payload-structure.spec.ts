import { describe, expect, it } from 'vitest'
import { structurePayload, unescapeValue } from '@/lib/payload-structure'

/**
 * The F5 shape these exist for, trimmed from a real blocked request. It is syslog, not
 * JSON: a priority, a BSD timestamp, a host, a tag, then key="value" pairs on one line —
 * with an entire HTTP request escaped inside one of them. The old viewer ran JSON.parse
 * on this, failed, and printed all 2.7 KB as a single unbroken line.
 */
const F5_BLOCKED =
  '<130>Aug 16 08:52:52 saruman.ipmi.verax.net ASM:unit_hostname="saruman.ipmi.verax.net",' +
  'management_ip_address="10.1.112.124",management_ip_address_2="N/A",' +
  'policy_name="/Common/jobs_bg_ASP1",' +
  'violations="Illegal request length,Illegal URL length,Illegal file type",' +
  'support_id="2773644993996159367",request_status="blocked",response_code="0",' +
  'ip_client="104.22.104.225",method="GET",protocol="HTTPS",query_string="",' +
  'severity="Critical",attack_type="Buffer Overflow,Forceful Browsing",geo_location="US",' +
  'username="N/A",violation_rating="3",staged_sig_ids="",' +
  'uri="/Tutorial/Oracle/Catalog.htm",' +
  'request="GET /Tutorial/Oracle/Catalog.htm HTTP/1.1\\r\\nHost: www.jobs.bg\\r\\n' +
  'user-agent: Mozilla/5.0 (compatible; bingbot/2.0)\\r\\ncf-visitor: {"scheme":"https"}\\r\\n\\r\\n",' +
  'response="Response logging disabled"'

function fieldsOf(raw: string): Map<string, string> {
  return new Map(structurePayload(raw).fields.map((f) => [f.path, f.value]))
}

describe('structurePayload — F5 syslog', () => {
  it('reads a key/value record as fields rather than one line', () => {
    const result = structurePayload(F5_BLOCKED)

    expect(result.shape).toBe('fields')
    expect(result.fields.length).toBeGreaterThan(15)
    expect(fieldsOf(F5_BLOCKED).get('request_status')).toBe('blocked')
    expect(fieldsOf(F5_BLOCKED).get('ip_client')).toBe('104.22.104.225')
  })

  // The delivery envelope and the request are different facts. Read as one, a relay's
  // clock becomes the event's — and <130> versus <134> is the difference between an
  // appliance shouting and an appliance chatting.
  it('decodes the syslog envelope, priority included', () => {
    const envelope = new Map(structurePayload(F5_BLOCKED).envelope.map((f) => [f.path, f.value]))

    expect(envelope.get('priority')).toBe('local0.crit (130)')
    expect(envelope.get('host')).toBe('saruman.ipmi.verax.net')
    expect(envelope.get('tag')).toBe('ASM')
    expect(envelope.get('timestamp')).toBe('Aug 16 08:52:52')
  })

  // The whole reason a blocked F5 record is opened. Three violations packed into one
  // comma-separated value are three findings, and reading them as one sentence is how a
  // "file type" violation gets missed behind a "request length" one.
  it('splits the violation set into its parts', () => {
    const violations = structurePayload(F5_BLOCKED).fields.find((f) => f.path === 'violations')

    expect(violations?.kind).toBe('list')
    expect(violations?.items).toEqual([
      'Illegal request length',
      'Illegal URL length',
      'Illegal file type',
    ])
  })

  // A comma is not a list marker. An x-forwarded-for chain and a user agent both contain
  // commas, and chopping either into chips destroys the value.
  it('does not split a value that merely contains commas', () => {
    const ua = structurePayload(
      'a="1",b="2",user_agent="Mozilla/5.0 (compatible; bingbot/2.0, like Gecko)"',
    ).fields.find((f) => f.path === 'user_agent')

    expect(ua?.kind).toBe('text')
    expect(ua?.items).toBeUndefined()
  })

  // The request is a document inside a field. F5 writes its CRLFs as the two characters
  // backslash-n, so left escaped it renders as one line with \r\n sprinkled through it.
  it('unfolds the escaped HTTP request into lines', () => {
    const request = structurePayload(F5_BLOCKED).fields.find((f) => f.path === 'request')

    expect(request?.kind).toBe('block')
    expect(request?.value.split('\n')[0]).toBe('GET /Tutorial/Oracle/Catalog.htm HTTP/1.1')
    expect(request?.value).toContain('Host: www.jobs.bg')
    // The escape sequences themselves must be gone, not merely rendered.
    expect(request?.value).not.toContain('\\r\\n')
  })

  // Two thirds of an F5 record is padding. Counting it is what lets the viewer say
  // "showing 15 of 50" instead of quietly dropping fields.
  it('counts the fields the vendor had nothing to say about', () => {
    const result = structurePayload(F5_BLOCKED)
    const empties = result.fields.filter((f) => f.kind === 'empty').map((f) => f.path)

    // N/A, an empty string, and an empty staged list all mean the same thing.
    expect(empties).toContain('management_ip_address_2')
    expect(empties).toContain('username')
    expect(empties).toContain('query_string')
    expect(empties).toContain('staged_sig_ids')
    expect(result.emptyCount).toBe(empties.length)
  })

  // F5 sends some keys twice by design. Last-one-wins would silently hide the first.
  it('keeps a repeated key instead of overwriting it', () => {
    const paths = structurePayload('a="1",b="2",a="3"').fields.map((f) => f.path)
    expect(paths).toEqual(['a', 'b', 'a (2)'])
  })

  // A prose log line that happens to contain one quoted pair is not a structured record,
  // and rendering it as a one-row table would hide the line it came from.
  it('leaves a line with too few pairs as text', () => {
    const result = structurePayload('connection closed by peer host="1.2.3.4"')
    expect(result.shape).toBe('text')
    expect(result.fields).toEqual([])
  })
})

describe('structurePayload — JSON records', () => {
  // Cloudflare and nginx ship NDJSON. Flattening gives the same filterable field list as
  // the syslog path, so one viewer serves every vendor.
  it('flattens a nested record into dotted paths', () => {
    const result = structurePayload(
      '{"RayID":"8f2","Action":"block","Client":{"IP":"1.2.3.4","ASN":13335},"Rules":[{"id":"a"}]}',
    )

    expect(result.shape).toBe('json')
    const fields = fieldsOf(
      '{"RayID":"8f2","Action":"block","Client":{"IP":"1.2.3.4","ASN":13335},"Rules":[{"id":"a"}]}',
    )
    expect(fields.get('Client.IP')).toBe('1.2.3.4')
    expect(fields.get('Client.ASN')).toBe('13335')
    expect(fields.get('Rules[0].id')).toBe('a')
  })

  // An empty list is a fact — "the vendor matched no rules" — and dropping the row makes
  // it indistinguishable from a field that was never sent.
  it('keeps an empty object or array as an empty field', () => {
    const result = structurePayload('{"Rules":[],"Meta":{}}')
    expect(result.fields.map((f) => [f.path, f.value, f.kind])).toEqual([
      ['Rules', '[]', 'empty'],
      ['Meta', '{}', 'empty'],
    ])
  })

  // Vendors nest JSON inside a string field routinely. Left alone the analyst reads the
  // escaped form.
  it('re-indents JSON that arrived inside a string', () => {
    const nested = structurePayload('{"cf":"{\\"scheme\\":\\"https\\"}"}').fields[0]

    expect(nested?.kind).toBe('json')
    expect(nested?.value).toBe('{\n  "scheme": "https"\n}')
  })

  it('falls back to text for a bare JSON scalar', () => {
    expect(structurePayload('"just a string"').shape).toBe('text')
    expect(structurePayload('42').shape).toBe('text')
    expect(structurePayload('null').shape).toBe('text')
  })
})

describe('structurePayload — safety and limits', () => {
  // The payload is attacker-controlled. Structuring must never turn it into markup: the
  // value stays the characters the vendor sent, and the caller interpolates it.
  it('carries markup through as text, unchanged', () => {
    const field = structurePayload('{"ua":"<script>alert(1)</script>"}').fields[0]
    expect(field?.value).toBe('<script>alert(1)</script>')
  })

  // Parsing a multi-megabyte record blocks the main thread while the dialog is already
  // open — a freeze on exactly the payloads that were slowest to arrive.
  it('does not parse a payload past the size cap', () => {
    const huge = `{"a":"${'x'.repeat(600 * 1024)}"}`
    const result = structurePayload(huge)

    expect(result.shape).toBe('text')
    expect(result.raw).toBe(huge)
  })

  it('reports nothing to show for an absent payload', () => {
    for (const empty of [undefined, null, '', '   ']) {
      const result = structurePayload(empty)
      expect(result.shape).toBe('text')
      expect(result.fields).toEqual([])
    }
  })

  // The raw bytes are the evidence. Whatever the structured view decides, the original
  // has to survive it intact.
  it('always keeps the payload exactly as received', () => {
    expect(structurePayload(F5_BLOCKED).raw).toBe(F5_BLOCKED)
    expect(structurePayload('{"a":1}').raw).toBe('{"a":1}')
  })
})

describe('unescapeValue', () => {
  it('undoes the escaping a vendor applied to fit one line', () => {
    expect(unescapeValue('a\\r\\nb\\tc\\"d\\\\e')).toBe('a\r\nb\tc"d\\e')
  })

  // Eating a backslash this function does not recognise would change the evidence — a
  // Windows path in a request body is not an escape sequence.
  it('leaves an unknown escape exactly as written', () => {
    expect(unescapeValue('C:\\Users\\admin')).toBe('C:\\Users\\admin')
  })
})
