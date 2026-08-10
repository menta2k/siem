<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components, operations } from '@/api/schema'

/** The query this endpoint accepts, named so the literal below is checked against it. */
type AlertsQuery = NonNullable<operations['Alerts_ListAlerts']['parameters']['query']>

type Alert = components['schemas']['Alert']
type AlertState = NonNullable<Alert['state']>

const alerts = ref<Alert[]>([])
const loading = ref(false)
const errorMessage = ref('')
const busyAlertId = ref<string | null>(null)

const stateFilter = ref<AlertState | 'ALL'>('ALERT_STATE_NEW')
const onlyFailedDelivery = ref(false)

const stateOptions: Array<{ title: string; value: AlertState | 'ALL' }> = [
  { title: 'New', value: 'ALERT_STATE_NEW' },
  { title: 'Acknowledged', value: 'ALERT_STATE_ACKNOWLEDGED' },
  { title: 'Resolved', value: 'ALERT_STATE_RESOLVED' },
  { title: 'All', value: 'ALL' },
]

const severityStyles: Record<string, { label: string; color: string }> = {
  SEVERITY_LOW: { label: 'Low', color: 'grey' },
  SEVERITY_MEDIUM: { label: 'Medium', color: 'info' },
  SEVERITY_HIGH: { label: 'High', color: 'warning' },
  SEVERITY_CRITICAL: { label: 'Critical', color: 'error' },
}

const stateStyles: Record<string, { label: string; color: string }> = {
  ALERT_STATE_NEW: { label: 'New', color: 'error' },
  ALERT_STATE_ACKNOWLEDGED: { label: 'Acknowledged', color: 'warning' },
  ALERT_STATE_RESOLVED: { label: 'Resolved', color: 'success' },
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''

  const to = new Date()
  const from = new Date(to.getTime() - 7 * 24 * 60 * 60 * 1000)

  const query: AlertsQuery = {
    'timeRange.from': from.toISOString(),
    'timeRange.to': to.toISOString(),
  }
  // Assigned rather than spread: a spread in the literal turns off excess-property
  // checking, which is how a misnamed parameter reached production on the audit page.
  if (stateFilter.value !== 'ALL') query.state = stateFilter.value
  if (onlyFailedDelivery.value) query.notifyStatus = 'NOTIFY_STATUS_FAILED'

  try {
    const { data } = await api.GET('/api/v1/alerts', { params: { query } })
    alerts.value = data?.alerts ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function transition(alert: Alert, action: 'acknowledge' | 'resolve'): Promise<void> {
  if (!alert.alertId) return

  busyAlertId.value = alert.alertId
  errorMessage.value = ''
  try {
    const path =
      action === 'acknowledge'
        ? '/api/v1/alerts/{alertId}/acknowledge'
        : '/api/v1/alerts/{alertId}/resolve'

    const { data } = await api.POST(path, {
      params: { path: { alertId: alert.alertId } },
      body: { alertId: alert.alertId, note: '' },
    })

    // The response is the updated alert, so the row is replaced from the server rather
    // than patched locally — a local guess would drift from the stored state the
    // moment a transition has any side effect.
    if (data) {
      alerts.value = alerts.value.map((a) => (a.alertId === data.alertId ? data : a))
    }
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    busyAlertId.value = null
  }
}

const failedDeliveryCount = computed(
  () => alerts.value.filter((a) => a.notifyStatus === 'NOTIFY_STATUS_FAILED').length,
)

function formatTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : '—'
}

/** A short description of what tripped, so the row is readable without opening it. */
function describe(alert: Alert): string {
  const observed = Number(alert.observedValue ?? 0)
  const threshold = Number(alert.threshold ?? 0)
  const groups = Object.entries(alert.groupValues ?? {})
    .map(([key, value]) => `${key}=${value}`)
    .join(' ')

  const measure = `${observed} vs ${threshold}`
  return groups ? `${measure} · ${groups}` : measure
}

function isBusy(alert: Alert): boolean {
  return busyAlertId.value === alert.alertId
}
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <!--
      Delivery failures are surfaced at the top, not buried in a column. An operator
      who believes they were notified and was not has no reason to come looking, so
      the page has to volunteer it (FR-032).
    -->
    <v-alert
      v-if="failedDeliveryCount"
      type="warning"
      variant="tonal"
      class="mb-4"
      :text="`${failedDeliveryCount} alert(s) could not be delivered to their webhook. They are listed below with the failure reason.`"
    />

    <v-card class="mb-4">
      <v-card-text class="d-flex flex-wrap align-center ga-3">
        <v-btn-toggle v-model="stateFilter" density="compact" variant="outlined" divided>
          <v-btn
            v-for="option in stateOptions"
            :key="option.value"
            :value="option.value"
            size="small"
            @click="load"
          >
            {{ option.title }}
          </v-btn>
        </v-btn-toggle>

        <v-checkbox
          v-model="onlyFailedDelivery"
          label="Delivery failed"
          density="compact"
          hide-details
          @update:model-value="load"
        />

        <v-spacer />
        <v-btn
          variant="text"
          size="small"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="load"
        >
          Refresh
        </v-btn>
      </v-card-text>
    </v-card>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <v-card>
      <v-table density="compact">
        <thead>
          <tr>
            <th>Fired</th>
            <th>Severity</th>
            <th>Rule</th>
            <th>Observed</th>
            <th>State</th>
            <th>Delivery</th>
            <th>Evidence</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="alert in alerts" :key="alert.alertId">
            <td class="text-no-wrap">{{ formatTime(alert.firedAt) }}</td>
            <td>
              <v-chip
                :color="severityStyles[alert.severity ?? '']?.color ?? 'grey'"
                size="x-small"
                variant="tonal"
              >
                {{ severityStyles[alert.severity ?? '']?.label ?? 'Unknown' }}
              </v-chip>
            </td>
            <td>{{ alert.ruleName || '—' }}</td>
            <td>{{ describe(alert) }}</td>
            <td>
              <v-chip
                :color="stateStyles[alert.state ?? '']?.color ?? 'grey'"
                size="x-small"
                variant="tonal"
              >
                {{ stateStyles[alert.state ?? '']?.label ?? 'Unknown' }}
              </v-chip>
            </td>
            <td>
              <v-tooltip
                v-if="alert.notifyStatus === 'NOTIFY_STATUS_FAILED'"
                :text="alert.notifyLastError || 'The webhook could not be reached.'"
                location="top"
                max-width="360"
              >
                <template #activator="{ props: tooltipProps }">
                  <v-chip v-bind="tooltipProps" color="error" size="x-small" variant="flat">
                    <v-icon icon="mdi-alert" start size="x-small" />
                    Failed ({{ alert.notifyAttempts }})
                  </v-chip>
                </template>
              </v-tooltip>
              <v-chip
                v-else-if="alert.notifyStatus === 'NOTIFY_STATUS_PENDING'"
                color="warning"
                size="x-small"
                variant="tonal"
              >
                Pending
              </v-chip>
              <v-chip v-else color="success" size="x-small" variant="tonal">Delivered</v-chip>
            </td>
            <td>
              <!--
                One click from the alert to the record that caused it (SC-006). Anything
                more and an operator reconstructs the query behind a number instead.
              -->
              <router-link
                v-if="alert.evidenceCorrelationIds?.length"
                :to="{
                  name: 'correlated',
                  params: { id: alert.evidenceCorrelationIds[0] },
                }"
              >
                Open ({{ alert.evidenceCorrelationIds.length }})
              </router-link>
              <span v-else class="text-medium-emphasis">—</span>
            </td>
            <td class="text-no-wrap">
              <v-btn
                v-if="alert.state === 'ALERT_STATE_NEW'"
                size="x-small"
                variant="tonal"
                :loading="isBusy(alert)"
                @click="transition(alert, 'acknowledge')"
              >
                Acknowledge
              </v-btn>
              <v-btn
                v-if="alert.state !== 'ALERT_STATE_RESOLVED'"
                size="x-small"
                variant="text"
                class="ml-1"
                :loading="isBusy(alert)"
                @click="transition(alert, 'resolve')"
              >
                Resolve
              </v-btn>
            </td>
          </tr>

          <tr v-if="!alerts.length && !loading">
            <td colspan="8" class="text-center text-medium-emphasis py-8">
              No alerts in this range.
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card>
  </div>
</template>
