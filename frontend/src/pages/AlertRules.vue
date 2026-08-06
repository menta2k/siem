<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import type { components } from '@/api/schema'

type AlertRule = components['schemas']['AlertRule']
type RuleCondition = components['schemas']['RuleCondition']
type PreviewGroup = components['schemas']['PreviewGroup']
type Severity = NonNullable<AlertRule['severity']>
type Aggregate = NonNullable<RuleCondition['aggregate']>
type Comparator = NonNullable<RuleCondition['comparator']>

const auth = useAuthStore()

const rules = ref<AlertRule[]>([])
const loading = ref(false)
const errorMessage = ref('')

const dialog = ref(false)
const saving = ref(false)
const formError = ref('')
const editingId = ref<string | null>(null)

const previewing = ref(false)
const preview = ref<PreviewGroup[] | null>(null)
const previewError = ref('')

interface RuleForm {
  name: string
  severity: Severity
  enabled: boolean
  aggregate: Aggregate
  comparator: Comparator
  threshold: number
  windowSeconds: number
  cooldownSeconds: number
  groupBy: string[]
  onlyDisagreements: boolean
  minVendorCount: number
  webhookUrl: string
  webhookSecret: string
}

function emptyForm(): RuleForm {
  return {
    name: '',
    severity: 'SEVERITY_MEDIUM',
    enabled: true,
    aggregate: 'RULE_AGGREGATE_COUNT',
    comparator: 'RULE_COMPARATOR_GT',
    threshold: 10,
    windowSeconds: 300,
    // Defaults to three times the window: a cooldown equal to it re-fires the moment
    // the window rolls, which is technically valid and almost never what is wanted.
    cooldownSeconds: 900,
    groupBy: [],
    onlyDisagreements: false,
    minVendorCount: 0,
    webhookUrl: '',
    webhookSecret: '',
  }
}

const form = ref<RuleForm>(emptyForm())

const severityOptions: Array<{ title: string; value: Severity }> = [
  { title: 'Low', value: 'SEVERITY_LOW' },
  { title: 'Medium', value: 'SEVERITY_MEDIUM' },
  { title: 'High', value: 'SEVERITY_HIGH' },
  { title: 'Critical', value: 'SEVERITY_CRITICAL' },
]

const aggregateOptions: Array<{ title: string; value: Aggregate; hint: string }> = [
  {
    title: 'Count',
    value: 'RULE_AGGREGATE_COUNT',
    hint: 'Number of matching requests in the window.',
  },
  {
    title: 'Rate',
    value: 'RULE_AGGREGATE_RATE',
    hint: 'Share of all traffic, between 0 and 1. Use this when a spike during a traffic surge is normal.',
  },
  {
    title: 'Distinct client IPs',
    value: 'RULE_AGGREGATE_DISTINCT_IPS',
    hint: 'Separates one noisy client from a distributed attack.',
  },
]

const comparatorOptions: Array<{ title: string; value: Comparator }> = [
  { title: 'greater than', value: 'RULE_COMPARATOR_GT' },
  { title: 'at least', value: 'RULE_COMPARATOR_GTE' },
  { title: 'less than', value: 'RULE_COMPARATOR_LT' },
  { title: 'at most', value: 'RULE_COMPARATOR_LTE' },
]

const groupByOptions = [
  'request_host',
  'client_ip',
  'country',
  'disagreement_kind',
  'combined_outcome',
  'confidence',
]

const aggregateHint = computed(
  () => aggregateOptions.find((o) => o.value === form.value.aggregate)?.hint ?? '',
)

/** Mirrors the server rule: a cooldown shorter than the window produces duplicates. */
const cooldownTooShort = computed(
  () => form.value.cooldownSeconds < form.value.windowSeconds,
)

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const { data } = await api.GET('/api/v1/alert-rules', {})
    rules.value = data?.rules ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

function conditionFromForm(): RuleCondition {
  return {
    aggregate: form.value.aggregate,
    comparator: form.value.comparator,
    threshold: form.value.threshold,
    windowSeconds: form.value.windowSeconds,
    cooldownSeconds: form.value.cooldownSeconds,
    groupBy: form.value.groupBy,
    onlyDisagreements: form.value.onlyDisagreements,
    minVendorCount: form.value.minVendorCount || undefined,
  }
}

function openCreate(): void {
  editingId.value = null
  form.value = emptyForm()
  preview.value = null
  formError.value = ''
  dialog.value = true
}

function openEdit(rule: AlertRule): void {
  const condition = rule.condition ?? {}
  editingId.value = rule.ruleId ?? null
  form.value = {
    name: rule.name ?? '',
    severity: rule.severity ?? 'SEVERITY_MEDIUM',
    enabled: rule.enabled ?? true,
    aggregate: condition.aggregate ?? 'RULE_AGGREGATE_COUNT',
    comparator: condition.comparator ?? 'RULE_COMPARATOR_GT',
    threshold: condition.threshold ?? 10,
    windowSeconds: condition.windowSeconds ?? 300,
    cooldownSeconds: condition.cooldownSeconds ?? 900,
    groupBy: condition.groupBy ?? [],
    onlyDisagreements: condition.onlyDisagreements ?? false,
    minVendorCount: condition.minVendorCount ?? 0,
    webhookUrl: rule.webhookUrl ?? '',
    // Never populated from the server — the secret is not returned. Left blank so an
    // edit that does not touch it keeps the stored key.
    webhookSecret: '',
  }
  preview.value = null
  formError.value = ''
  dialog.value = true
}

/**
 * Dry-runs the condition without saving.
 *
 * The failure mode of an untested alerting rule is silence: it sits enabled, never
 * trips, and nobody notices until the incident it was written for goes unreported.
 */
async function runPreview(): Promise<void> {
  previewing.value = true
  previewError.value = ''
  preview.value = null
  try {
    const { data } = await api.POST('/api/v1/alert-rules/{ruleId}/preview', {
      params: { path: { ruleId: editingId.value ?? '00000000-0000-0000-0000-000000000000' } },
      body: { ruleId: editingId.value ?? '', condition: conditionFromForm() },
    })
    preview.value = data?.groups ?? []
  } catch (err) {
    previewError.value = toDisplayMessage(err)
  } finally {
    previewing.value = false
  }
}

async function save(): Promise<void> {
  saving.value = true
  formError.value = ''
  try {
    if (editingId.value) {
      await api.PATCH('/api/v1/alert-rules/{ruleId}', {
        params: { path: { ruleId: editingId.value } },
        body: {
          ruleId: editingId.value,
          name: form.value.name,
          severity: form.value.severity,
          enabled: form.value.enabled,
          condition: conditionFromForm(),
          webhookUrl: form.value.webhookUrl,
          // Only sent when the operator typed a new one, so an unrelated edit does
          // not clear the configured signing key.
          ...(form.value.webhookSecret ? { webhookSecret: form.value.webhookSecret } : {}),
        },
      })
    } else {
      await api.POST('/api/v1/alert-rules', {
        body: {
          name: form.value.name,
          severity: form.value.severity,
          enabled: form.value.enabled,
          condition: conditionFromForm(),
          webhookUrl: form.value.webhookUrl,
          webhookSecret: form.value.webhookSecret,
        },
      })
    }
    dialog.value = false
    await load()
  } catch (err) {
    formError.value = toDisplayMessage(err)
  } finally {
    saving.value = false
  }
}

async function disable(rule: AlertRule): Promise<void> {
  if (!rule.ruleId) return
  errorMessage.value = ''
  try {
    await api.DELETE('/api/v1/alert-rules/{ruleId}', {
      params: { path: { ruleId: rule.ruleId } },
    })
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  }
}

const severityLabels: Record<string, string> = {
  SEVERITY_LOW: 'Low',
  SEVERITY_MEDIUM: 'Medium',
  SEVERITY_HIGH: 'High',
  SEVERITY_CRITICAL: 'Critical',
}

const aggregateLabels: Record<string, string> = {
  RULE_AGGREGATE_COUNT: 'count',
  RULE_AGGREGATE_RATE: 'rate',
  RULE_AGGREGATE_DISTINCT_IPS: 'distinct IPs',
}

const comparatorLabels: Record<string, string> = {
  RULE_COMPARATOR_GT: '>',
  RULE_COMPARATOR_GTE: '≥',
  RULE_COMPARATOR_LT: '<',
  RULE_COMPARATOR_LTE: '≤',
}

function describeRule(rule: AlertRule): string {
  const c = rule.condition ?? {}
  const aggregate = aggregateLabels[c.aggregate ?? ''] ?? '?'
  const comparator = comparatorLabels[c.comparator ?? ''] ?? '?'
  const grouped = c.groupBy?.length ? ` by ${c.groupBy.join(', ')}` : ''
  return `${aggregate} ${comparator} ${c.threshold} over ${c.windowSeconds}s${grouped}`
}

const wouldFireCount = computed(
  () => preview.value?.filter((g) => g.wouldFire).length ?? 0,
)
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <div class="d-flex align-center mb-4">
      <div class="text-h6">Alert rules</div>
      <v-spacer />
      <v-btn
        v-if="auth.can.manageRules"
        color="primary"
        prepend-icon="mdi-plus"
        @click="openCreate"
      >
        New rule
      </v-btn>
    </div>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <v-card>
      <v-table density="compact">
        <thead>
          <tr>
            <th>Name</th>
            <th>Severity</th>
            <th>Condition</th>
            <th>Webhook</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="rule in rules" :key="rule.ruleId">
            <td>{{ rule.name }}</td>
            <td>{{ severityLabels[rule.severity ?? ''] ?? '—' }}</td>
            <td><code>{{ describeRule(rule) }}</code></td>
            <td>
              <span v-if="rule.webhookUrl">
                {{ rule.webhookUrl }}
                <v-chip
                  v-if="rule.webhookSigningConfigured"
                  size="x-small"
                  variant="tonal"
                  color="success"
                  class="ml-1"
                >
                  signed
                </v-chip>
              </span>
              <span v-else class="text-medium-emphasis">console only</span>
            </td>
            <td>
              <v-chip
                :color="rule.enabled ? 'success' : 'grey'"
                size="x-small"
                variant="tonal"
              >
                {{ rule.enabled ? 'Enabled' : 'Disabled' }}
              </v-chip>
            </td>
            <td class="text-no-wrap">
              <v-btn size="x-small" variant="text" @click="openEdit(rule)">
                {{ auth.can.manageRules ? 'Edit' : 'View' }}
              </v-btn>
              <v-btn
                v-if="auth.can.manageRules && rule.enabled"
                size="x-small"
                variant="text"
                @click="disable(rule)"
              >
                Disable
              </v-btn>
            </td>
          </tr>

          <tr v-if="!rules.length && !loading">
            <td colspan="6" class="text-center text-medium-emphasis py-8">
              No alert rules yet.
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card>

    <v-dialog v-model="dialog" max-width="820" scrollable>
      <v-card>
        <v-card-title class="text-subtitle-1">
          {{ editingId ? 'Edit rule' : 'New rule' }}
        </v-card-title>

        <v-card-text>
          <v-alert v-if="formError" type="error" variant="tonal" class="mb-3">
            {{ formError }}
          </v-alert>

          <v-text-field
            v-model="form.name"
            label="Name"
            density="compact"
            variant="outlined"
            class="mb-3"
          />

          <v-row dense>
            <v-col cols="6">
              <v-select
                v-model="form.severity"
                :items="severityOptions"
                label="Severity"
                density="compact"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6">
              <v-switch
                v-model="form.enabled"
                label="Enabled"
                color="primary"
                density="compact"
                hide-details
              />
            </v-col>
          </v-row>

          <div class="text-subtitle-2 mt-2 mb-1">Condition</div>

          <v-row dense>
            <v-col cols="12" md="5">
              <v-select
                v-model="form.aggregate"
                :items="aggregateOptions"
                label="Measure"
                :hint="aggregateHint"
                persistent-hint
                density="compact"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6" md="4">
              <v-select
                v-model="form.comparator"
                :items="comparatorOptions"
                label="is"
                density="compact"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6" md="3">
              <v-text-field
                v-model.number="form.threshold"
                label="Threshold"
                type="number"
                step="0.01"
                density="compact"
                variant="outlined"
              />
            </v-col>
          </v-row>

          <v-row dense>
            <v-col cols="6">
              <v-text-field
                v-model.number="form.windowSeconds"
                label="Window (seconds)"
                type="number"
                density="compact"
                variant="outlined"
              />
            </v-col>
            <v-col cols="6">
              <v-text-field
                v-model.number="form.cooldownSeconds"
                label="Cooldown (seconds)"
                type="number"
                density="compact"
                variant="outlined"
                :error="cooldownTooShort"
                :error-messages="
                  cooldownTooShort
                    ? 'Must be at least the window, or one condition produces a stream of duplicates.'
                    : ''
                "
              />
            </v-col>
          </v-row>

          <v-select
            v-model="form.groupBy"
            :items="groupByOptions"
            label="Group by"
            hint="Each group alerts and cools down independently. At most three."
            persistent-hint
            multiple
            chips
            closable-chips
            density="compact"
            variant="outlined"
            class="mb-3"
          />

          <v-checkbox
            v-model="form.onlyDisagreements"
            label="Only where vendors disagreed"
            density="compact"
            hide-details
          />

          <div class="text-subtitle-2 mt-4 mb-1">Delivery</div>

          <v-text-field
            v-model="form.webhookUrl"
            label="Webhook URL"
            hint="Leave blank to raise alerts in the console only."
            persistent-hint
            density="compact"
            variant="outlined"
            class="mb-3"
          />

          <v-text-field
            v-model="form.webhookSecret"
            label="Signing secret"
            type="password"
            :hint="
              editingId
                ? 'Leave blank to keep the existing key. It is never shown.'
                : 'Deliveries are signed with this. It is stored in the secret manager and never returned.'
            "
            persistent-hint
            density="compact"
            variant="outlined"
          />

          <!-- The dry run. -->
          <div class="d-flex align-center mt-4 mb-2">
            <div class="text-subtitle-2">Dry run</div>
            <v-spacer />
            <v-btn
              size="small"
              variant="tonal"
              :loading="previewing"
              @click="runPreview"
            >
              Preview against recent data
            </v-btn>
          </div>

          <v-alert v-if="previewError" type="error" variant="tonal" density="compact">
            {{ previewError }}
          </v-alert>

          <template v-else-if="preview">
            <v-alert
              :type="wouldFireCount ? 'warning' : 'info'"
              variant="tonal"
              density="compact"
              class="mb-2"
            >
              {{ wouldFireCount }} of {{ preview.length }} group(s) would have fired.
            </v-alert>

            <v-table v-if="preview.length" density="compact">
              <thead>
                <tr>
                  <th>Group</th>
                  <th class="text-right">Observed</th>
                  <th>Would fire</th>
                </tr>
              </thead>
              <tbody>
                <!-- Non-firing groups are listed too: tuning a threshold against only
                     the values that tripped it is tuning blind. -->
                <tr v-for="(group, index) in preview" :key="index">
                  <td>
                    <code>
                      {{
                        Object.entries(group.groupValues ?? {})
                          .map(([k, v]) => `${k}=${v}`)
                          .join(' ') || 'all traffic'
                      }}
                    </code>
                  </td>
                  <td class="text-right">{{ group.observedValue }}</td>
                  <td>
                    <v-chip
                      :color="group.wouldFire ? 'warning' : 'grey'"
                      size="x-small"
                      variant="tonal"
                    >
                      {{ group.wouldFire ? 'Yes' : 'No' }}
                    </v-chip>
                  </td>
                </tr>
              </tbody>
            </v-table>
          </template>
        </v-card-text>

        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = false">Cancel</v-btn>
          <v-btn
            v-if="auth.can.manageRules"
            color="primary"
            :loading="saving"
            :disabled="!form.name || cooldownTooShort"
            @click="save"
          >
            Save
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>
