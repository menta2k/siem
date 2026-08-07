import { afterEach, describe, expect, it, vi } from 'vitest'

import { copyText } from '@/lib/clipboard'
import { generateFeedToken } from '@/lib/tokens'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('generateFeedToken', () => {
  // 32 bytes base64url-unpadded is 43 characters — the same shape the server's
  // auth.GenerateFeedToken produces, so a token minted here is indistinguishable.
  it('matches the server token format', () => {
    const token = generateFeedToken()

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(token).not.toContain('=')
    expect(token).not.toContain('+')
    expect(token).not.toContain('/')
  })

  it('does not repeat itself', () => {
    const tokens = new Set(Array.from({ length: 500 }, () => generateFeedToken()))
    expect(tokens.size).toBe(500)
  })

  // The important one. Math.random is not an acceptable source for a credential, so a
  // browser without Web Crypto must get an error rather than a guessable token that the
  // platform then accepts as if it were strong.
  it('refuses to mint a token without a secure random source', () => {
    vi.stubGlobal('crypto', undefined)

    expect(() => generateFeedToken()).toThrow(/cannot generate a secure token/i)
  })
})

describe('copyText', () => {
  it('uses the async clipboard when it is available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })

    await expect(copyText('a-token')).resolves.toBe(true)
    expect(writeText).toHaveBeenCalledWith('a-token')
  })

  // navigator.clipboard is secure-context only, exactly like crypto.randomUUID. This is
  // the path a plain-HTTP deployment actually takes, and the token it is copying is
  // shown once — a silently dead button costs the operator another rotation.
  it('falls back to execCommand when the clipboard API is absent', async () => {
    vi.stubGlobal('navigator', {})
    const exec = vi.fn().mockReturnValue(true)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(document as any).execCommand = exec

    await expect(copyText('a-token')).resolves.toBe(true)
    expect(exec).toHaveBeenCalledWith('copy')
  })

  it('reports failure rather than throwing when neither path works', async () => {
    vi.stubGlobal('navigator', {})
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(document as any).execCommand = () => {
      throw new Error('blocked')
    }

    await expect(copyText('a-token')).resolves.toBe(false)
  })

  it('leaves no stray element behind', async () => {
    vi.stubGlobal('navigator', {})
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(document as any).execCommand = () => true

    await copyText('a-token')
    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })
})
