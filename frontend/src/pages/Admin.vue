<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type { components } from '@/api/schema'

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

const redactableFields = [
  'user_agent',
  'request_query',
  'client_ip',
  'verdict_reason',
]

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

async function createUser(): Promise<void> {
  savingUser.value = true
  errorMessage.value = ''
  notice.value = ''
  try {
    await api.POST('/api/v1/admin/users', {
      body: { email: newUser.value.email, role: newUser.value.role, password: '' },
    })
    // No password is shown: the server generates one and does not return it, because
    // a credential in a response is a credential in every proxy log along the way.
    notice.value = `Created ${newUser.value.email}. They must reset their password to sign in.`
    newUser.value = { email: '', role: 'analyst' }
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    savingUser.value = false
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
    </v-tabs>

    <v-window v-model="tab">
      <v-window-item value="users">
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
                  <v-chip
                    :color="user.mfaEnabled ? 'success' : 'warning'"
                    size="x-small"
                    variant="tonal"
                  >
                    {{ user.mfaEnabled ? 'Enrolled' : 'Not enrolled' }}
                  </v-chip>
                </td>
                <td>
                  {{ user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : 'Never' }}
                </td>
                <td class="text-no-wrap">
                  <v-btn
                    v-if="canManage"
                    size="x-small"
                    variant="text"
                    @click="updateUser(user, { resetMfa: true })"
                  >
                    Reset MFA
                  </v-btn>
                  <v-btn
                    v-if="canManage"
                    size="x-small"
                    variant="text"
                    @click="updateUser(user, { status: 'disabled' })"
                  >
                    Disable
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
              Widening the window raises the join rate and the false-join rate together.
              A tenant behind heavy NAT needs different tuning from one that is not.
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
    </v-window>
  </div>
</template>
