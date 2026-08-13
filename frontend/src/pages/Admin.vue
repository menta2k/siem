<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type { components } from '@/api/schema'
import IngestFilterRules from '@/components/IngestFilterRules.vue'
import { cleanRules, type IngestFilterRule } from '@/lib/ingest-filters'
import { usePreferencesStore } from '@/stores/preferences'

const prefs = usePreferencesStore()

type UserProfile = components['schemas']['UserProfile']
type TenantSettings = components['schemas']['TenantSettings']
type CorrelationSettings = components['schemas']['CorrelationSettings']

const auth = useAuthStore()

const tab = ref<'users' | 'retention' | 'correlation'>('users')
const errorMessage = ref('')
const notice = ref('')
const loading = ref(false)

const users = ref<UserProfile[]>([])
const tenant = ref<TenantSettings | null>(null)
const correlation = ref<CorrelationSettings | null>(null)

const roles = ['admin', 'analyst', 'auditor', 'ingest_only']

const newUser = ref({ email: '', role: 'analyst' })
const savingUser = ref(false)

// Editable copies, so a failed save leaves the form as the operator left it rather
// than snapping back to the server's values mid-edit.
const retentionForm = ref({
  rawRetentionDays: 30,
  correlatedRetentionDays: 90,
  alertRetentionDays: 365,
  redactedFields: [] as string[],
  scoreConflictThreshold: 0.8,
})

const correlationForm = ref({ correlationWindowMs: 5000, latenessBoundMs: 900_000 })
const savingSettings = ref(false)

// Held separately from the retention form and never pre-filled: the API does not return
// the token, by design, so there is nothing to populate it with. An empty box means
// "leave it alone", which is also why saving retention cannot blank it.
const cloudflareToken = ref('')
const savingToken = ref(false)

const ingestFilters = ref<IngestFilterRule[]>([])
const savingFilters = ref(false)

const redactableFields = ['user_agent', 'request_query', 'client_ip', 'verdict_reason']

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const [u, t, c] = await Promise.all([
      api.GET('/api/v1/admin/users', {}),
      api.GET('/api/v1/admin/tenant', {}),
      api.GET('/api/v1/admin/correlation-settings', {}),
    ])

    users.value = u.data?.users ?? []
    tenant.value = t.data ?? null
    correlation.value = c.data ?? null

    if (t.data) {
      retentionForm.value = {
        rawRetentionDays: t.data.rawRetentionDays ?? 30,
        correlatedRetentionDays: t.data.correlatedRetentionDays ?? 90,
        alertRetentionDays: t.data.alertRetentionDays ?? 365,
        redactedFields: t.data.redactedFields ?? [],
        scoreConflictThreshold: t.data.scoreConflictThreshold ?? 0.8,
      }
      ingestFilters.value = (t.data.ingestFilters ?? []).map((rule) => ({
        ...rule,
        values: [...(rule.values ?? [])],
      }))
    }
    if (c.data) {
      correlationForm.value = {
        correlationWindowMs: c.data.correlationWindowMs ?? 5000,
        latenessBoundMs: c.data.latenessBoundMs ?? 900_000,
      }
    }
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

/**
 * The setup link most recently issued, held only for as long as this page is open.
 *
 * Never persisted. The server stores a hash and returns the token exactly once, so this
 * is the only copy — and putting it in localStorage would leave a live credential in the
 * browser of whoever last used the admin page.
 */
const issuedInvite = ref<{ email: string; url: string; expiresAt: string } | null>(null)
const invitingUserId = ref('')
const linkCopied = ref(false)

/**
 * Account status, rendered for an operator rather than for the database.
 *
 * "Awaiting setup" is the one that matters: it says the account cannot sign in yet and
 * why, which "invited" alone in a table cell does not.
 */
function statusLabel(status: string | undefined): string {
  switch (status) {
    case 'invited':
      return 'Awaiting setup'
    case 'disabled':
      return 'Disabled'
    case 'active':
      return 'Active'
    default:
      return status ?? 'Unknown'
  }
}

function statusColor(status: string | undefined): string {
  switch (status) {
    case 'active':
      return 'success'
    case 'invited':
      return 'info'
    default:
      return 'warning'
  }
}

/** Turns a setup token into the link an admin sends on. */
function inviteUrl(token: string): string {
  return `${window.location.origin}/invite?token=${encodeURIComponent(token)}`
}

async function createUser(): Promise<void> {
  savingUser.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    const { data } = await api.POST('/api/v1/admin/users', {
      body: { email: newUser.value.email, role: newUser.value.role, password: '' },
    })
    const created = newUser.value.email
    newUser.value = { email: '', role: 'analyst' }
    await load()

    // Issued immediately, as the second half of one operation the admin thinks of as
    // "add a colleague". Creating without inviting leaves an account nobody can use.
    if (data?.userId) {
      await issueInvite(data.userId)
    } else {
      notice.value = `Created ${created}. Use "Invite" to generate their setup link.`
    }
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingUser.value = false
  }
}

/**
 * Mints a one-time setup link.
 *
 * Re-issuable on purpose: the token cannot be looked up afterwards, so "resend" means
 * "mint a new one", and doing so invalidates whatever came before it.
 */
async function issueInvite(userId: string): Promise<void> {
  invitingUserId.value = userId
  errorMessage.value = ''
  notice.value = ''
  linkCopied.value = false
  try {
    const { data } = await api.POST('/api/v1/admin/users/{userId}/invite', {
      params: { path: { userId } },
      body: { userId },
    })
    if (!data?.setupToken) {
      errorMessage.value = 'The server returned no setup token.'
      return
    }
    issuedInvite.value = {
      email: data.email ?? '',
      url: inviteUrl(data.setupToken),
      expiresAt: prefs.dateTime(data.expiresAt, 'unknown'),
    }
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    invitingUserId.value = ''
  }
}

async function copyInviteLink(): Promise<void> {
  if (!issuedInvite.value) return
  try {
    await navigator.clipboard.writeText(issuedInvite.value.url)
    linkCopied.value = true
  } catch {
    // Clipboard access is denied outside a secure context, which is exactly where a
    // self-hosted console often runs. The link is on screen and selectable, so this is
    // a missing convenience rather than a failure worth an error banner.
    linkCopied.value = false
  }
}

/** Hides the link once it has been passed on. */
function dismissInvite(): void {
  issuedInvite.value = null
  linkCopied.value = false
}

/**
 * Permanent erasure, behind a typed confirmation.
 *
 * Distinct from Disable, which is reversible and stays the right default for someone
 * leaving. This destroys the row: the address becomes reusable and nothing brings the
 * account back. The audit trail is untouched — entries carry the actor's email as well
 * as their id, so their history stays attributable afterwards.
 *
 * The dialog asks for the address rather than offering a bare "are you sure", because a
 * confirm button is answered reflexively while retyping an address cannot be. The server
 * re-checks the same match; this is the affordance, not the enforcement.
 */
const eraseTarget = ref<UserProfile | null>(null)
const eraseConfirmation = ref('')
const erasing = ref(false)

const eraseMatches = computed(
  () =>
    eraseTarget.value !== null &&
    eraseConfirmation.value.trim().toLowerCase() === (eraseTarget.value.email ?? '').toLowerCase(),
)

function askToErase(user: UserProfile): void {
  eraseTarget.value = user
  eraseConfirmation.value = ''
}

function cancelErase(): void {
  eraseTarget.value = null
  eraseConfirmation.value = ''
}

async function confirmErase(): Promise<void> {
  const target = eraseTarget.value
  if (!target || !eraseMatches.value) return

  erasing.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    await api.DELETE('/api/v1/admin/users/{userId}/permanent', {
      params: {
        path: { userId: target.userId ?? '' },
        query: { confirmEmail: eraseConfirmation.value.trim() },
      },
    })
    notice.value = `Permanently erased ${target.email}. Their audit history is kept.`
    cancelErase()
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    erasing.value = false
  }
}

async function updateUser(user: UserProfile, changes: Record<string, unknown>): Promise<void> {
  errorMessage.value = ''
  try {
    await api.PATCH('/api/v1/admin/users/{userId}', {
      params: { path: { userId: user.userId ?? '' } },
      body: { userId: user.userId, ...changes },
    })
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  }
}

/**
 * Saves the filter rules alone.
 *
 * Sent as its own request rather than folded into the retention form: a PATCH omitting a
 * field leaves it untouched server-side, so keeping them separate means saving filters can
 * never disturb a redaction policy the operator was not editing.
 */
async function saveFilters(): Promise<void> {
  savingFilters.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    const cleaned = cleanRules(ingestFilters.value)
    await api.PATCH('/api/v1/admin/tenant', { body: { ingestFilters: cleaned } })
    notice.value = cleaned.length
      ? `Saved ${cleaned.length} ingest ${cleaned.length === 1 ? 'filter' : 'filters'}. Matching events will no longer be stored.`
      : 'Ingest filters cleared. Every event will be stored.'
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingFilters.value = false
  }
}

async function saveRetention(): Promise<void> {
  savingSettings.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    await api.PATCH('/api/v1/admin/tenant', { body: retentionForm.value })
    notice.value = 'Retention and redaction saved.'
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingSettings.value = false
  }
}

/**
 * Stores or clears the Cloudflare API token.
 *
 * Sent on its own rather than with the retention form, so a token cannot be changed by
 * an operator who only meant to edit a retention day count — and so clearing it is a
 * deliberate act rather than a side effect of an empty field.
 */
async function saveCloudflareToken(token: string): Promise<void> {
  savingToken.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    await api.PATCH('/api/v1/admin/tenant', { body: { cloudflareApiToken: token } })
    // The API verifies the token against Cloudflare before storing it, so reaching here
    // means it actually works — and the refresh picks a changed token up within a minute
    // rather than at the next hourly pass.
    notice.value = token
      ? 'Cloudflare token verified and saved. Rule names appear within a minute.'
      : 'Cloudflare token cleared. Rules will show their ids only.'
    cloudflareToken.value = ''
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingToken.value = false
  }
}

async function saveCorrelation(): Promise<void> {
  savingSettings.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    await api.PATCH('/api/v1/admin/correlation-settings', { body: correlationForm.value })
    notice.value = 'Correlation settings saved. They take effect within a minute.'
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingSettings.value = false
  }
}

/**
 * Redaction is applied at INGEST, so it only affects data written from now on.
 *
 * Saying so matters: an operator who adds a field expecting historical data to be
 * masked would otherwise believe the platform had already scrubbed it.
 */
const redactionWarning = computed(() => {
  const stored = tenant.value?.redactedFields ?? []
  const added = retentionForm.value.redactedFields.filter((f) => !stored.includes(f))
  return added.length
    ? `Masking applies to newly ingested events only. Existing ${added.join(', ')} values stay as they were stored.`
    : ''
})

const canManage = computed(() => auth.can.manageUsers)
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>
    <v-alert v-if="notice" type="success" variant="tonal" class="mb-4" closable>
      {{ notice }}
    </v-alert>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <v-tabs v-model="tab" class="mb-4">
      <v-tab value="users">Users</v-tab>
      <v-tab value="retention">Retention &amp; redaction</v-tab>
      <v-tab value="correlation">Correlation</v-tab>
      <v-tab value="filters">Ingest filters</v-tab>
      <v-tab value="integrations">Integrations</v-tab>
    </v-tabs>

    <v-window v-model="tab">
      <v-window-item value="users">
        <!-- Permanent erasure. The address must be retyped: a confirm button gets
             answered reflexively, retyping an address does not. -->
        <v-dialog :model-value="eraseTarget !== null" max-width="520" persistent>
          <v-card v-if="eraseTarget">
            <v-card-title class="text-subtitle-1">Permanently delete this account?</v-card-title>
            <v-card-text>
              <v-alert type="error" variant="tonal" density="compact" class="mb-4">
                This cannot be undone. The account is removed rather than disabled, and the address
                becomes available again.
              </v-alert>
              <div class="text-body-2 mb-4">
                Their audit history is kept and stays attributable to
                <strong>{{ eraseTarget.email }}</strong
                >. Deleting a user never rewrites the record of what they did.
              </div>
              <div class="text-caption text-medium-emphasis mb-1">
                Type <strong>{{ eraseTarget.email }}</strong> to confirm.
              </div>
              <v-text-field
                v-model="eraseConfirmation"
                density="compact"
                variant="outlined"
                autocomplete="off"
                hide-details
                @keyup.enter="confirmErase"
              />
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn variant="text" :disabled="erasing" @click="cancelErase">Cancel</v-btn>
              <v-btn
                color="error"
                variant="flat"
                :loading="erasing"
                :disabled="!eraseMatches"
                @click="confirmErase"
              >
                Delete permanently
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>

        <!-- Shown once, and only here. The server keeps a hash, so this is the single
             copy of the token that will ever exist. -->
        <v-alert
          v-if="issuedInvite"
          type="info"
          variant="tonal"
          class="mb-4"
          closable
          @click:close="dismissInvite"
        >
          <div class="text-subtitle-2 mb-1">Setup link for {{ issuedInvite.email }}</div>
          <div class="text-caption mb-2">
            Send this to them over a channel you trust. It works once, expires
            {{ issuedInvite.expiresAt }}, and cannot be shown again — issue a new one if it is lost.
          </div>
          <!-- Interpolated into a code block, never rendered as markup or as a link the
               admin might follow themselves and burn. -->
          <code class="text-caption d-block text-break mb-2">{{ issuedInvite.url }}</code>
          <v-btn size="small" variant="tonal" @click="copyInviteLink">
            {{ linkCopied ? 'Copied' : 'Copy link' }}
          </v-btn>
        </v-alert>

        <v-card v-if="canManage" class="mb-4">
          <v-card-title class="text-subtitle-1">Add a user</v-card-title>
          <v-card-text class="d-flex flex-wrap align-center ga-3">
            <v-text-field
              v-model="newUser.email"
              label="Email"
              type="email"
              density="compact"
              variant="outlined"
              hide-details
              style="max-width: 300px"
            />
            <v-select
              v-model="newUser.role"
              :items="roles"
              label="Role"
              density="compact"
              variant="outlined"
              hide-details
              style="max-width: 180px"
            />
            <v-btn
              color="primary"
              :loading="savingUser"
              :disabled="!newUser.email"
              @click="createUser"
            >
              Create
            </v-btn>
          </v-card-text>
        </v-card>

        <v-card>
          <v-table density="compact">
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA</th>
                <th>Last login</th>
                <th />
              </tr>
            </thead>
            <tbody>
              <tr v-for="user in users" :key="user.userId">
                <td>{{ user.email }}</td>
                <td>
                  <v-select
                    v-if="canManage"
                    :model-value="user.role"
                    :items="roles"
                    density="compact"
                    variant="plain"
                    hide-details
                    style="max-width: 160px"
                    @update:model-value="updateUser(user, { role: $event })"
                  />
                  <span v-else>{{ user.role }}</span>
                </td>
                <td>
                  <v-chip :color="statusColor(user.status)" size="x-small" variant="tonal">
                    {{ statusLabel(user.status) }}
                  </v-chip>
                </td>
                <td>
                  <v-chip
                    :color="user.mfaEnabled ? 'success' : 'warning'"
                    size="x-small"
                    variant="tonal"
                  >
                    {{ user.mfaEnabled ? 'Enrolled' : 'Not enrolled' }}
                  </v-chip>
                </td>
                <td>
                  {{ prefs.dateTime(user.lastLoginAt, 'Never') }}
                </td>
                <td class="text-no-wrap">
                  <!-- "Invite" for an account awaiting setup, "Send reset link" for one
                       already in use. Same call either way; the wording is what stops an
                       admin from thinking they are about to lock a colleague out. -->
                  <v-btn
                    v-if="canManage && user.status !== 'disabled'"
                    size="x-small"
                    variant="text"
                    :loading="invitingUserId === user.userId"
                    @click="issueInvite(user.userId ?? '')"
                  >
                    {{ user.status === 'invited' ? 'Invite' : 'Send reset link' }}
                  </v-btn>
                  <v-btn
                    v-if="canManage"
                    size="x-small"
                    variant="text"
                    @click="updateUser(user, { resetMfa: true })"
                  >
                    Reset MFA
                  </v-btn>
                  <v-btn
                    v-if="canManage && user.status !== 'disabled'"
                    size="x-small"
                    variant="text"
                    @click="updateUser(user, { status: 'disabled' })"
                  >
                    Disable
                  </v-btn>
                  <v-btn
                    v-if="canManage && user.status === 'disabled'"
                    size="x-small"
                    variant="text"
                    @click="updateUser(user, { status: 'active' })"
                  >
                    Enable
                  </v-btn>
                  <!-- Coloured as the destructive action it is, and the only one on this
                       row that cannot be undone. -->
                  <v-btn
                    v-if="canManage"
                    size="x-small"
                    variant="text"
                    color="error"
                    @click="askToErase(user)"
                  >
                    Delete
                  </v-btn>
                </td>
              </tr>
            </tbody>
          </v-table>
        </v-card>
      </v-window-item>

      <v-window-item value="retention">
        <v-card>
          <v-card-text>
            <v-row dense>
              <v-col cols="12" md="4">
                <v-text-field
                  v-model.number="retentionForm.rawRetentionDays"
                  label="Raw events (days)"
                  type="number"
                  density="compact"
                  variant="outlined"
                  :disabled="!canManage"
                />
              </v-col>
              <v-col cols="12" md="4">
                <v-text-field
                  v-model.number="retentionForm.correlatedRetentionDays"
                  label="Correlated records (days)"
                  type="number"
                  density="compact"
                  variant="outlined"
                  :disabled="!canManage"
                />
              </v-col>
              <v-col cols="12" md="4">
                <v-text-field
                  v-model.number="retentionForm.alertRetentionDays"
                  label="Alerts (days)"
                  type="number"
                  density="compact"
                  variant="outlined"
                  :disabled="!canManage"
                />
              </v-col>
            </v-row>

            <v-select
              v-model="retentionForm.redactedFields"
              :items="redactableFields"
              label="Redacted fields"
              hint="Masked at ingest, so the value is never stored in readable form."
              persistent-hint
              multiple
              chips
              closable-chips
              density="compact"
              variant="outlined"
              class="mb-3"
              :disabled="!canManage"
            />

            <v-alert
              v-if="redactionWarning"
              type="info"
              variant="tonal"
              density="compact"
              class="mb-3"
            >
              {{ redactionWarning }}
            </v-alert>

            <v-text-field
              v-model.number="retentionForm.scoreConflictThreshold"
              label="Score conflict threshold"
              type="number"
              step="0.05"
              hint="Bot score at or above which an allowed request is reported as a conflict."
              persistent-hint
              density="compact"
              variant="outlined"
              :disabled="!canManage"
            />

            <v-btn
              v-if="canManage"
              color="primary"
              class="mt-4"
              :loading="savingSettings"
              @click="saveRetention"
            >
              Save
            </v-btn>
          </v-card-text>
        </v-card>
      </v-window-item>

      <v-window-item value="correlation">
        <v-card>
          <v-card-text>
            <v-row dense>
              <v-col cols="12" md="6">
                <v-text-field
                  v-model.number="correlationForm.correlationWindowMs"
                  label="Correlation window (ms)"
                  type="number"
                  hint="How far apart two events may be and still describe one request."
                  persistent-hint
                  density="compact"
                  variant="outlined"
                  :disabled="!canManage"
                />
              </v-col>
              <v-col cols="12" md="6">
                <v-text-field
                  v-model.number="correlationForm.latenessBoundMs"
                  label="Lateness bound (ms)"
                  type="number"
                  hint="How late an event may arrive and still amend an existing record."
                  persistent-hint
                  density="compact"
                  variant="outlined"
                  :disabled="!canManage"
                />
              </v-col>
            </v-row>

            <v-alert type="info" variant="tonal" density="compact" class="mt-3">
              Widening the window raises the join rate and the false-join rate together. A tenant
              behind heavy NAT needs different tuning from one that is not.
            </v-alert>

            <v-btn
              v-if="canManage"
              color="primary"
              class="mt-4"
              :loading="savingSettings"
              @click="saveCorrelation"
            >
              Save
            </v-btn>
          </v-card-text>
        </v-card>
      </v-window-item>

      <v-window-item value="filters">
        <IngestFilterRules
          v-model="ingestFilters"
          :saving="savingFilters"
          :disabled="!canManage"
          @save="saveFilters"
        />
      </v-window-item>

      <v-window-item value="integrations">
        <v-card>
          <v-card-title class="text-subtitle-1">Cloudflare rule names</v-card-title>
          <v-card-text>
            <p class="text-body-2 mb-3">
              Logpush reports the rule that matched as an id and nothing else. With a read-only API
              token the platform fetches the rule names from your zones, so the console can show
              what a rule actually is instead of a bare identifier.
            </p>

            <v-alert
              :type="tenant?.cloudflareTokenConfigured ? 'success' : 'info'"
              variant="tonal"
              density="compact"
              class="mb-3"
            >
              <template v-if="tenant?.cloudflareTokenConfigured">
                A token is configured. Rule names refresh hourly.
              </template>
              <template v-else> No token configured — rules show their ids only. </template>
            </v-alert>

            <!--
              Never pre-filled, and the API never returns it. A settings screen that echoes
              a credential turns every screenshot and browser cache into a leak, so the box
              is write-only: empty means "leave the current token alone".
            -->
            <v-text-field
              v-model="cloudflareToken"
              label="Cloudflare API token"
              type="password"
              autocomplete="off"
              hint="Needs Zone WAF Read. Verified against Cloudflare before it is stored, and kept in the secret store rather than the database."
              persistent-hint
              density="compact"
              variant="outlined"
              :disabled="!canManage"
            />

            <div class="d-flex ga-2 mt-4">
              <v-btn
                v-if="canManage"
                color="primary"
                :loading="savingToken"
                :disabled="!cloudflareToken"
                @click="saveCloudflareToken(cloudflareToken)"
              >
                Save token
              </v-btn>
              <v-btn
                v-if="canManage && tenant?.cloudflareTokenConfigured"
                variant="tonal"
                :loading="savingToken"
                @click="saveCloudflareToken('')"
              >
                Remove token
              </v-btn>
            </div>
          </v-card-text>
        </v-card>
      </v-window-item>
    </v-window>
  </div>
</template>
