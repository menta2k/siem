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

/**
 * Exchanges the refresh cookie for a new access token. Set by the auth store.
 *
 * Must be deduplicated by the store: refresh tokens rotate, so two concurrent exchanges
 * would have the second present a token the first already burned.
 */
type SessionRefresher = () => Promise<boolean>
let refreshSession: SessionRefresher = async () => false

export function configureAuth(
  provider: TokenProvider,
  handler: UnauthorizedHandler,
  refresher?: SessionRefresher,
): void {
  tokenProvider = provider
  onUnauthorized = handler
  if (refresher) refreshSession = refresher
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

/**
 * Requests still awaiting a response, keyed by openapi-fetch's per-call id.
 *
 * These are clones taken before the request is dispatched, so a 401 can be replayed
 * after a silent token refresh. The clone has to happen up front: once fetch is reading
 * the body its stream is locked, and a POST could no longer be replayed afterwards.
 */
const replayable = new Map<string, Request>()

/** Attaches the bearer token and a trace id to every request. */
const authMiddleware: Middleware = {
  onRequest({ request, id }) {
    const token = tokenProvider()
    if (token) request.headers.set('Authorization', `Bearer ${token}`)
    // Correlates this request with its server-side log line.
    request.headers.set('X-Trace-Id', traceId())
    replayable.set(id, request.clone())
    return request
  },
}

// Exported for tests only; not part of the client's public surface.
export const __traceId = traceId

/** Reads the backend's error envelope, falling back to a safe generic one. */
async function envelopeOf(response: Response): Promise<ApiError> {
  try {
    const body = (await response.clone().json()) as Partial<ApiError>
    if (body && typeof body.code === 'string') return body as ApiError
  } catch {
    // A non-JSON body (a proxy error page, say) keeps the generic envelope below.
    // Never surface raw HTML to the user.
  }
  return { code: ErrorCode.Internal, message: 'The request failed' }
}

/**
 * True when this failure is an expired access token that a refresh could fix.
 *
 * The auth routes are excluded deliberately. /auth/refresh answering 401 means the
 * refresh credential itself is finished, and retrying it would recurse; /auth/logout
 * answering 401 must not quietly mint a new session for someone on their way out.
 */
function isExpiredAccessToken(response: Response, envelope: ApiError, schemaPath: string): boolean {
  return (
    response.status === 401 &&
    envelope.code === ErrorCode.Unauthenticated &&
    !schemaPath.startsWith('/api/v1/auth/')
  )
}

/** Replays a request once with whatever token the refresh produced. */
async function replayWithFreshToken(request: Request): Promise<Response | null> {
  if (!(await refreshSession())) return null

  const token = tokenProvider()
  if (!token) return null

  const headers = new Headers(request.headers)
  headers.set('Authorization', `Bearer ${token}`)
  // A replay is a new attempt on the wire and gets its own id, so the server-side logs
  // show two distinct requests rather than one that mysteriously answered twice.
  headers.set('X-Trace-Id', traceId())
  try {
    // Deliberately raw fetch: the headers above are already what the middleware would
    // have added, and going back through the client would re-enter this same handler.
    return await fetch(new Request(request, { headers }))
  } catch {
    // A network failure on the replay is reported as the original 401 by the caller.
    return null
  }
}

/**
 * Converts a non-2xx response into a typed error rather than a silent undefined, and
 * transparently renews an expired access token first.
 *
 * THE BUG THIS FIXES. Access tokens last 15 minutes; the refresh cookie lasts a week.
 * Nothing but the page-load restore() ever spent that cookie, so leaving a tab idle past
 * the access token's lifetime meant the next call — a search, a dashboard poll, anything
 * — came back "the access token is not valid" and the 401 handler below tore the session
 * down. Pressing F5 fixed it because that is the one path that did exchange the cookie.
 * Doing the exchange here makes the console survive its own token lifetime.
 */
const errorMiddleware: Middleware = {
  async onResponse({ response, id, schemaPath }) {
    const original = replayable.get(id)
    replayable.delete(id)
    if (response.ok) return response

    let current = response
    let envelope = await envelopeOf(current)

    if (original && isExpiredAccessToken(current, envelope, schemaPath)) {
      const replayed = await replayWithFreshToken(original)
      if (replayed) {
        if (replayed.ok) return replayed
        current = replayed
        envelope = await envelopeOf(current)
      }
    }

    // Only now — after a refresh has been tried and failed — is the session really over.
    if (current.status === 401) onUnauthorized()
    throw new ApiRequestError(current.status, envelope)
  },
  onError({ id }) {
    replayable.delete(id)
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
