<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import FeedHealthChip from '@/components/FeedHealthChip.vue'
import RejectedEventsDialog from '@/components/RejectedEventsDialog.vue'

const auth = useAuthStore()

import type { components } from '@/api/schema'

type Feed = components['schemas']['Feed']
type Vendor = NonNullable<Feed['vendor']>
type Delivery = NonNullable<Feed['deliveryMode']>

const feeds = ref<Feed[]>([])
const loading = ref(false)
const errorMessage = ref('')

const createDialog = ref(false)
const rejectsFeedId = ref<string | null>(null)
const saving = ref(false)
const formError = ref('')

const form = ref<{
  vendor: Vendor
  name: string
  deliveryMode: Delivery
  credential: string
  signingSecret: string
  pullConfig: string
}>({
  vendor: 'VENDOR_CLOUDFLARE',
  name: '',
  deliveryMode: 'DELIVERY_MODE_PUSH',
  credential: '',
  signingSecret: '',
  pullConfig: '',
})

const vendorOptions: { title: string; value: Vendor }[] = [
  { title: 'Cloudflare', value: 'VENDOR_CLOUDFLARE' },
  { title: 'F5', value: 'VENDOR_F5' },
  { title: 'DataDome', value: 'VENDOR_DATADOME' },
]

const deliveryOptions: { title: string; value: Delivery }[] = [
  { title: 'Push — the vendor posts to us', value: 'DELIVERY_MODE_PUSH' },
  { title: 'Pull — we poll the vendor', value: 'DELIVERY_MODE_PULL' },
]

const isPull = computed(() => form.value.deliveryMode === 'DELIVERY_MODE_PULL')

/** Feeds that have gone quiet, surfaced first — a dead feed looks like clean traffic. */
const silentFeeds = computed(() => feeds.value.filter((f) => f?.health?.silent))

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const { data } = await api.GET('/api/v1/feeds')
    feeds.value = data?.feeds ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

async function createFeed(): Promise<void> {
  saving.value = true
  formError.value = ''
  try {
    await api.POST('/api/v1/feeds', {
      body: {
        vendor: form.value.vendor,
        name: form.value.name,
        deliveryMode: form.value.deliveryMode,
        credential: form.value.credential,
        signingSecret: form.value.signingSecret || undefined,
        pullConfig: isPull.value ? form.value.pullConfig : undefined,
      },
    })
    createDialog.value = false
    resetForm()
    await load()
  } catch (err) {
    formError.value = toDisplayMessage(err)
  } finally {
    saving.value = false
  }
}

async function toggleEnabled(feed: Feed): Promise<void> {
  if (!feed?.feedId) return
  try {
    await api.PATCH('/api/v1/feeds/{feedId}', {
      params: { path: { feedId: feed.feedId } },
      body: { enabled: !feed.enabled },
    })
    await load()
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  }
}

async function testFeed(feed: Feed): Promise<void> {
  if (!feed?.feedId) return
  try {
    const { data } = await api.POST('/api/v1/feeds/{feedId}/test', {
      params: { path: { feedId: feed.feedId } },
      body: {},
    })
    errorMessage.value = data?.detail ?? ''
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  }
}

function resetForm(): void {
  form.value = {
    vendor: 'VENDOR_CLOUDFLARE',
    name: '',
    deliveryMode: 'DELIVERY_MODE_PUSH',
    credential: '',
    signingSecret: '',
    pullConfig: '',
  }
  formError.value = ''
}

function vendorLabel(vendor: Vendor | undefined): string {
  return vendorOptions.find((v) => v.value === vendor)?.title ?? 'Unknown'
}

onMounted(load)
</script>

<template>
  <div>
    <div class="d-flex align-center mb-4">
      <div>
        <div class="text-h6">Feeds</div>
        <div class="text-body-2 text-medium-emphasis">
          One connection per vendor. Credentials are stored once and never shown again.
        </div>
      </div>
      <v-spacer />
      <v-btn
        v-if="auth.can.manageFeeds"
        color="primary"
        prepend-icon="mdi-plus"
        @click="createDialog = true"
      >
        Add feed
      </v-btn>
    </div>

    <v-alert
      v-if="errorMessage"
      type="info"
      variant="tonal"
      density="compact"
      closable
      class="mb-4"
      @click:close="errorMessage = ''"
    >
      {{ errorMessage }}
    </v-alert>

    <!--
      Silence is called out separately because it is invisible on a dashboard: a feed
      that stopped sending looks exactly like a quiet one with no attacks.
    -->
    <v-alert v-if="silentFeeds.length" type="warning" variant="tonal" class="mb-4">
      <div class="font-weight-medium">
        {{ silentFeeds.length }} feed{{ silentFeeds.length > 1 ? 's have' : ' has' }} sent nothing
        recently
      </div>
      <div class="text-body-2">
        A silent feed looks identical to clean traffic. Check the vendor's delivery configuration.
      </div>
    </v-alert>

    <v-card>
      <v-data-table
        :items="feeds"
        :loading="loading"
        :headers="[
          { title: 'Vendor', key: 'vendor' },
          { title: 'Name', key: 'name' },
          { title: 'Delivery', key: 'deliveryMode' },
          { title: 'Health', key: 'health', sortable: false },
          { title: 'Events/sec', key: 'rate' },
          { title: 'Rejected (1h)', key: 'rejected' },
          { title: '', key: 'actions', sortable: false },
        ]"
        items-per-page="25"
      >
        <template #item.vendor="{ item }">
          {{ vendorLabel(item.vendor) }}
        </template>

        <template #item.name="{ item }">
          <!-- Server-supplied text, interpolated so it can never execute. -->
          <span class="font-weight-medium">{{ item.name }}</span>
          <v-chip v-if="!item.enabled" size="x-small" class="ml-2" variant="tonal">disabled</v-chip>
        </template>

        <template #item.deliveryMode="{ item }">
          {{ item.deliveryMode === 'DELIVERY_MODE_PULL' ? 'Pull' : 'Push' }}
        </template>

        <template #item.health="{ item }">
          <FeedHealthChip :health="item.health" :enabled="item.enabled ?? false" />
        </template>

        <template #item.rate="{ item }">
          {{ (item.health?.eventsPerSec ?? 0).toFixed(2) }}
        </template>

        <template #item.rejected="{ item }">
          <span :class="Number(item.health?.eventsRejected1h ?? 0) > 0 ? 'text-error' : ''">
            {{ item.health?.eventsRejected1h ?? 0 }}
          </span>
        </template>

        <template #item.actions="{ item }">
          <v-btn size="small" variant="text" @click="rejectsFeedId = item.feedId ?? null">
            Rejects
          </v-btn>
          <v-btn v-if="auth.can.manageFeeds" size="small" variant="text" @click="testFeed(item)">
            Test
          </v-btn>
          <v-btn
            v-if="auth.can.manageFeeds"
            size="small"
            variant="text"
            @click="toggleEnabled(item)"
          >
            {{ item.enabled ? 'Disable' : 'Enable' }}
          </v-btn>
        </template>

        <template #no-data>
          <div class="pa-8 text-center text-medium-emphasis">
            No feeds yet. Add one per vendor to start ingesting.
          </div>
        </template>
      </v-data-table>
    </v-card>

    <!-- Create ------------------------------------------------------------ -->
    <v-dialog v-model="createDialog" max-width="620">
      <v-card>
        <v-card-title>Add feed</v-card-title>
        <v-card-text>
          <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mb-4">
            {{ formError }}
          </v-alert>

          <v-select v-model="form.vendor" :items="vendorOptions" label="Vendor" class="mb-3" />
          <v-text-field v-model="form.name" label="Name" class="mb-3" />
          <v-select
            v-model="form.deliveryMode"
            :items="deliveryOptions"
            label="Delivery"
            class="mb-3"
          />

          <v-text-field
            v-model="form.credential"
            label="Credential"
            type="password"
            hint="Stored in the secret manager. This is the only time it is visible."
            persistent-hint
            class="mb-3"
          />
          <v-text-field
            v-model="form.signingSecret"
            label="Signing secret (optional)"
            type="password"
            hint="If set, every delivery must carry a valid HMAC signature."
            persistent-hint
            class="mb-3"
          />
          <v-textarea
            v-if="isPull"
            v-model="form.pullConfig"
            label="Pull configuration (JSON)"
            rows="4"
            placeholder='{"endpoint": "...", "bucket": "...", "interval_seconds": 60}'
          />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="createDialog = false">Cancel</v-btn>
          <v-btn color="primary" :loading="saving" @click="createFeed">Create</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <RejectedEventsDialog :feed-id="rejectsFeedId" @close="rejectsFeedId = null" />
  </div>
</template>
