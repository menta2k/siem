// The single doorway between the SPA and the backend.
//
// Types come from `schema.d.ts`, which is generated from `backend/api/openapi.yaml`
// by `make api`. Nothing in this directory is hand-written except this wrapper, and
// CI fails if the generated file drifts from the published contract.
import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'

/** Stable error codes the backend guarantees. Clients branch on these, never on text. */
export const ErrorCode = {
  Unauthenticated: 'UNAUTHENTICATED',
  MfaRequired: 'MFA_REQUIRED',
  PermissionDenied: 'PERMISSION_DENIED',
  TenantSuspended: 'TENANT_SUSPENDED',
  ValidationFailed: 'VALIDATION_FAILED',
  TimeRangeRequired: 'TIME_RANGE_REQUIRED',
  TimeRangeTooLarge: 'TIME_RANGE_TOO_LARGE',
  ResultLimitExceeded: 'RESULT_LIMIT_EXCEEDED',
  QueryTimeout: 'QUERY_TIMEOUT',
  CursorInvalid: 'CURSOR_INVALID',
  NotFound: 'NOT_FOUND',
  Conflict: 'CONFLICT',
  RateLimited: 'RATE_LIMITED',
  Internal: 'INTERNAL',
} as const

export type ErrorCodeValue = (typeof ErrorCode)[keyof typeof ErrorCode]

/** The error envelope every non-2xx response carries. */
export interface ApiError {
  code: string
  message: string
  details?: Array<{ field?: string; issue?: string }>
  trace_id?: string
}

/**
 * A failed request, carrying the backend's envelope.
 *
 * `message` is safe to show a user — the backend guarantees it leaks no internals.
 * `traceId` is what an operator needs to find the matching server-side log line, so
 * it is surfaced in the UI rather than swallowed.
 */
export class ApiRequestError extends Error {
  readonly code: string
  readonly status: number
  readonly traceId?: string
  readonly details: Array<{ field?: string; issue?: string }>

  constructor(status: number, error: ApiError) {
    super(error.message || 'The request failed')
    this.name = 'ApiRequestError'
    this.code = error.code || ErrorCode.Internal
    this.status = status
    this.traceId = error.trace_id
    this.details = error.details ?? []
  }

  /** True when re-authenticating could resolve this. */
  get isAuthFailure(): boolean {
    return this.code === ErrorCode.Unauthenticated || this.code === ErrorCode.MfaRequired
  }

  /** Field-level messages, for binding validation errors back onto form inputs. */
  fieldErrors(): Record<string, string> {
    return this.details.reduce<Record<string, string>>((acc, d) => {
      if (d.field && d.issue) acc[d.field] = d.issue
      return acc
    }, {})
  }
}

/** Supplies the current access token. Set by the auth store to avoid a circular import. */
type TokenProvider = () => string | null
let tokenProvider: TokenProvider = () => null

/** Called when the backend rejects our credentials, so the app can return to login. */
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler = () => {}

export function configureAuth(provider: TokenProvider, handler: UnauthorizedHandler): void {
  tokenProvider = provider
  onUnauthorized = handler
}

/**
 * Generates a trace id, without requiring a secure context.
 *
 * `crypto.randomUUID` exists ONLY in a secure context — HTTPS, or localhost. Served
 * over plain HTTP on any other host it is `undefined`, and because this runs in the
 * request middleware, every single API call throws before it is sent. That includes
 * the login request, so the whole console is unusable rather than merely untraced.
 *
 * `crypto.getRandomValues` carries no such restriction, so the fallback is still a
 * real random v4 UUID rather than a degraded one. `Math.random` is the last resort for
 * an environment with no Web Crypto at all; a trace id correlates a request with a log
 * line and is never a security token, so that is an acceptable floor.
 */
function traceId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }

  const bytes = new Uint8Array(16)
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = Math.floor(Math.random() * 256)
  }

  // RFC 4122: version 4 in the high nibble of byte 6, variant 10xx in byte 8. Read into
  // locals first — under noUncheckedIndexedAccess an indexed read is possibly undefined,
  // even on a fixed-length Uint8Array the line above just filled.
  const versionByte = bytes[6] ?? 0
  const variantByte = bytes[8] ?? 0
  bytes[6] = (versionByte & 0x0f) | 0x40
  bytes[8] = (variantByte & 0x3f) | 0x80

  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-')
}

/** Attaches the bearer token and a trace id to every request. */
const authMiddleware: Middleware = {
  onRequest({ request }) {
    const token = tokenProvider()
    if (token) request.headers.set('Authorization', `Bearer ${token}`)
    // Correlates this request with its server-side log line.
    request.headers.set('X-Trace-Id', traceId())
    return request
  },
}

// Exported for tests only; not part of the client's public surface.
export const __traceId = traceId

/** Converts a non-2xx response into a typed error rather than a silent undefined. */
const errorMiddleware: Middleware = {
  async onResponse({ response }) {
    if (response.ok) return response

    let envelope: ApiError = { code: ErrorCode.Internal, message: 'The request failed' }
    try {
      const body = (await response.clone().json()) as Partial<ApiError>
      if (body && typeof body.code === 'string') envelope = body as ApiError
    } catch {
      // A non-JSON body (a proxy error page, say) keeps the generic envelope above.
      // Never surface raw HTML to the user.
    }

    if (response.status === 401) onUnauthorized()
    throw new ApiRequestError(response.status, envelope)
  },
}

export const api = createClient<paths>({ baseUrl: '/' })
api.use(authMiddleware)
api.use(errorMiddleware)

/**
 * Normalizes anything thrown into a displayable message.
 *
 * Used by every catch site, so an unexpected throw still produces something a user
 * can act on instead of "[object Object]".
 */
export function toDisplayMessage(err: unknown): string {
  if (err instanceof ApiRequestError) return err.message
  if (err instanceof Error) return err.message
  return 'An unexpected error occurred'
}
