<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import ConfidenceChip from '@/components/ConfidenceChip.vue'
import VendorVerdictBadge from '@/components/VendorVerdictBadge.vue'
import CorrelationChain from '@/components/CorrelationChain.vue'

type CorrelatedRequest = components['schemas']['CorrelatedRequest']
type VendorVerdict = components['schemas']['VendorVerdict']

const route = useRoute()

const record = ref<CorrelatedRequest | null>(null)
const loading = ref(false)
const errorMessage = ref('')

const correlationId = computed(() => String(route.params.id ?? ''))

async function load(): Promise<void> {
  if (!correlationId.value) return

  loading.value = true
  errorMessage.value = ''
  try {
    const { data } = await api.GET('/api/v1/correlated/{correlationId}', {
      params: { path: { correlationId: correlationId.value } },
    })
    record.value = data ?? null
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
    record.value = null
  } finally {
    loading.value = false
  }
}

onMounted(load)
watch(correlationId, load)

/**
 * Which vendors disagree with the rest.
 *
 * Computed per vendor rather than taken from the record's single `hasDisagreement`
 * flag: the flag says a conflict exists, but an analyst needs to see WHICH vendor is
 * the outlier before they can decide who to believe.
 */
const disagreeingVendors = computed<Set<string>>(() => {
  const verdicts = record.value?.vendorVerdicts ?? []
  if (!record.value?.hasDisagreement || verdicts.length < 2) return new Set()

  const distinct = new Set(verdicts.map((v) => v.verdict))
  if (distinct.size < 2) return new Set()

  // Every vendor whose verdict is not shared by all of them is part of the conflict.
  return new Set(verdicts.map((v) => v.vendor ?? '').filter(Boolean))
})

const joinTierLabel = computed(() => {
  switch (record.value?.joinTier) {
    case 1:
      return 'Tier 1 — exact shared request identifier'
    case 2:
      return 'Tier 2 — matched on request shape and time'
    default:
      return 'No join'
  }
})

const signalLabels: Record<string, string> = {
  JOIN_SIGNAL_VENDOR_REQUEST_ID: 'Shared vendor request id',
  JOIN_SIGNAL_IP_HOST_PATH_METHOD: 'Client, host, path and method',
  JOIN_SIGNAL_TIME_WINDOW: 'Within the correlation window',
}

const disagreementLabels: Record<string, string> = {
  DISAGREEMENT_KIND_NONE: 'Vendors agreed',
  DISAGREEMENT_KIND_ALLOW_VS_BLOCK: 'One vendor allowed it, another blocked it',
  DISAGREEMENT_KIND_ALLOW_VS_CHALLENGE: 'One vendor allowed it, another challenged it',
  DISAGREEMENT_KIND_SCORE_CONFLICT: 'All vendors allowed it, but one scored it as automated',
}

const outcomeLabels: Record<string, string> = {
  VERDICT_ALLOWED: 'Allowed',
  VERDICT_BLOCKED: 'Blocked',
  VERDICT_CHALLENGED: 'Challenged',
  VERDICT_RATE_LIMITED: 'Rate limited',
  VERDICT_MONITORED: 'Monitored',
  VERDICT_UNKNOWN: 'Unknown',
}

function formatTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : '—'
}

/** How long the vendors' observations were spread across. */
const spread = computed(() => {
  const first = record.value?.firstEventTime
  const last = record.value?.lastEventTime
  if (!first || !last) return null
  const ms = new Date(last).getTime() - new Date(first).getTime()
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`
})

function vendorOf(v: VendorVerdict): string {
  return v.vendor ?? ''
}
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <template v-if="record">
      <!-- Summary: the two facts that decide whether this record needs attention. -->
      <v-card class="mb-4">
        <v-card-text>
          <div class="d-flex flex-wrap align-center ga-3 mb-3">
            <div class="text-h6">
              {{ outcomeLabels[record.combinedOutcome ?? ''] ?? 'Outcome unknown' }}
            </div>

            <ConfidenceChip
              :confidence="record.confidence"
              :join-tier="record.joinTier"
              :candidate-count="record.candidateCount"
              :ip-shared="record.client?.ipShared"
              :vendor-count="record.vendorCount"
            />

            <v-chip
              v-if="record.hasDisagreement"
              color="warning"
              variant="flat"
              size="small"
              aria-label="Vendors disagreed about this request"
            >
              <v-icon icon="mdi-alert-outline" start size="small" />
              Disagreement
            </v-chip>

            <v-chip v-if="record.amended" color="info" variant="tonal" size="small">
              <v-icon icon="mdi-history" start size="small" />
              Amended (v{{ record.version }})
            </v-chip>
          </div>

          <div class="text-body-2 text-medium-emphasis">
            {{ disagreementLabels[record.disagreementKind ?? ''] ?? '' }}
          </div>

          <div class="mt-3 text-body-1">
            <code
              >{{ record.request?.method }} {{ record.request?.host
              }}{{ record.request?.path }}</code
            >
          </div>
        </v-card-text>
      </v-card>

      <v-row>
        <!-- Each vendor's own account, side by side. This is the record's whole point:
             a flattened summary would say the vendors disagreed without saying who
             said what, which is not something an analyst can act on. -->
        <v-col cols="12" md="7">
          <v-card class="mb-4">
            <v-card-title class="text-subtitle-1">What each vendor reported</v-card-title>
            <v-card-text>
              <div class="d-flex flex-wrap ga-3">
                <VendorVerdictBadge
                  v-for="v in record.vendorVerdicts ?? []"
                  :key="vendorOf(v)"
                  :vendor="v.vendor"
                  :verdict="v.verdict"
                  :rule-id="v.ruleId"
                  :score="v.score"
                  :disagreeing="disagreeingVendors.has(vendorOf(v))"
                />
              </div>

              <v-alert
                v-if="(record.vendorCount ?? 0) <= 1"
                type="info"
                variant="tonal"
                density="compact"
                class="mt-4"
              >
                Only one vendor reported this request. That is normal for hostnames behind a single
                vendor — it is not a correlation failure.
              </v-alert>
            </v-card-text>
          </v-card>

          <!-- Why the join was made. Without this an analyst cannot audit the record,
               and a record that cannot be audited cannot be acted on (FR-015). -->
          <v-card class="mb-4">
            <v-card-title class="text-subtitle-1">Why these events were joined</v-card-title>
            <v-card-text>
              <div class="mb-3 text-body-2">{{ joinTierLabel }}</div>

              <v-list density="compact" class="pa-0">
                <v-list-item v-for="signal in record.joinSignals ?? []" :key="signal" class="px-0">
                  <template #prepend>
                    <v-icon icon="mdi-check" size="small" class="mr-2" />
                  </template>
                  <v-list-item-title class="text-body-2">
                    {{ signalLabels[signal] ?? signal }}
                  </v-list-item-title>
                </v-list-item>
              </v-list>

              <v-alert
                v-if="record.joinTier !== 1 && (record.candidateCount ?? 1) > 1"
                type="warning"
                variant="tonal"
                density="compact"
                class="mt-3"
              >
                {{ record.candidateCount }} events from a single vendor competed for this join, so
                the partner chosen here may be the wrong one.
              </v-alert>

              <v-alert
                v-if="record.client?.ipShared"
                type="warning"
                variant="tonal"
                density="compact"
                class="mt-3"
              >
                The client address is shared — NAT, a proxy, or a carrier range — so several
                distinct clients could produce this same match.
              </v-alert>
            </v-card-text>
          </v-card>
        </v-col>

        <v-col cols="12" md="5">
          <v-card class="mb-4">
            <v-card-title class="text-subtitle-1">Request</v-card-title>
            <v-card-text>
              <v-table density="compact">
                <tbody>
                  <tr>
                    <td class="text-medium-emphasis">Client</td>
                    <td>
                      <code>{{ record.client?.ip || '—' }}</code>
                    </td>
                  </tr>
                  <tr>
                    <td class="text-medium-emphasis">Country</td>
                    <td>{{ record.client?.country || '—' }}</td>
                  </tr>
                  <tr v-if="record.client?.asn">
                    <td class="text-medium-emphasis">Network</td>
                    <!-- The owner is what makes the number mean something: whether this
                         request came from a residential ISP or a hosting provider is
                         usually the next question. Absent when the published table does
                         not list the ASN, leaving the bare number. -->
                    <td>
                      AS{{ record.client.asn }}
                      <span v-if="record.client.asnOwner" class="text-medium-emphasis ml-1">
                        {{ record.client.asnOwner }}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td class="text-medium-emphasis">First seen</td>
                    <td>{{ formatTime(record.firstEventTime) }}</td>
                  </tr>
                  <tr>
                    <td class="text-medium-emphasis">Last seen</td>
                    <td>{{ formatTime(record.lastEventTime) }}</td>
                  </tr>
                  <tr v-if="spread">
                    <td class="text-medium-emphasis">Spread</td>
                    <td>{{ spread }}</td>
                  </tr>
                </tbody>
              </v-table>
            </v-card-text>
          </v-card>

          <!-- The chain itself: every contributing event in observation order, each
               expandable to the vendor's own fields and the payload as received
               (FR-024). A bare list of ids answered "which events" but never "what did
               they say", which is the question a disagreement actually raises. -->
          <CorrelationChain :event-ids="record.eventIds ?? []" :conflicting="disagreeingVendors" />

          <div class="mt-3 text-caption text-medium-emphasis">
            Correlation id <code>{{ record.correlationId }}</code>
          </div>
        </v-col>
      </v-row>
    </template>

    <v-card v-else-if="!loading && !errorMessage" class="pa-6">
      <div class="text-body-2 text-medium-emphasis">No correlated request found.</div>
    </v-card>
  </div>
</template>
