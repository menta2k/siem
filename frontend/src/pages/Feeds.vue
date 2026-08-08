<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { copyText } from '@/lib/clipboard'
import { generateFeedToken } from '@/lib/tokens'
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
  { title: 'nginx (origin)', value: 'VENDOR_NGINX' },
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

// ---------------------------------------------------------------- credential rotation
//
// Two dialogs on purpose. Rotating takes effect immediately, so the vendor's next
// delivery is rejected until its configuration is updated — that deserves a deliberate
// confirmation, not a single click in a row of buttons. The second dialog exists because
// the platform stores only a REFERENCE to the token: this is the one and only time it can
// be read back, and closing the dialog without copying it means rotating again.
const rotateTarget = ref<Feed | null>(null)
const rotating = ref(false)
const rotatedToken = ref('')
const rotateError = ref('')
const copied = ref(false)

async function rotateCredential(): Promise<void> {
  const feed = rotateTarget.value
  if (!feed?.feedId) return

  rotating.value = true
  rotateError.value = ''
  try {
    const token = generateFeedToken()
    await api.PATCH('/api/v1/feeds/{feedId}', {
      params: { path: { feedId: feed.feedId } },
      body: { credential: token },
    })
    // Only shown after the write succeeds. Displaying it first would hand the operator a
    // token the platform never stored, and every delivery using it would be rejected.
    rotatedToken.value = token
    rotateTarget.value = null
    await load()
  } catch (err) {
    rotateError.value = toDisplayMessage(err)
  } finally {
    rotating.value = false
  }
}

async function copyToken(): Promise<void> {
  copied.value = await copyText(rotatedToken.value)
}

function dismissToken(): void {
  rotatedToken.value = ''
  copied.value = false
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
          <v-btn
            v-if="auth.can.manageFeeds"
            size="small"
            variant="text"
            @click="rotateTarget = item"
          >
            Rotate token
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

    <!-- Rotate: confirm ---------------------------------------------------- -->
    <v-dialog :model-value="rotateTarget !== null" max-width="560" @update:model-value="rotateTarget = null">
      <v-card>
        <v-card-title>Rotate ingest token</v-card-title>
        <v-card-text>
          <v-alert type="warning" variant="tonal" density="comfortable" class="mb-4">
            The new token takes effect immediately. Deliveries from
            <strong>{{ rotateTarget?.name }}</strong> will be rejected with
            <code>401</code> until the vendor is reconfigured.
          </v-alert>
          <p class="text-body-2 text-medium-emphasis">
            Rejected deliveries are not lost data — the platform returns a non-2xx and
            every vendor retries. Update the vendor promptly and the backlog drains on its
            own.
          </p>
          <v-alert v-if="rotateError" type="error" variant="tonal" class="mt-4">
            {{ rotateError }}
          </v-alert>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="rotating" @click="rotateTarget = null">Cancel</v-btn>
          <v-btn color="warning" :loading="rotating" @click="rotateCredential">
            Rotate token
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Rotate: the new token, shown once ----------------------------------- -->
    <v-dialog :model-value="rotatedToken !== ''" max-width="640" persistent>
      <v-card>
        <v-card-title>New ingest token</v-card-title>
        <v-card-text>
          <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
            This is shown <strong>once</strong>. The platform stores only a reference to
            it, so it cannot be displayed again — only rotated.
          </v-alert>
          <!-- Interpolated, never v-html: this is rendered as text and can never execute. -->
          <v-textarea
            :model-value="rotatedToken"
            readonly
            rows="2"
            variant="outlined"
            class="font-monospace"
            label="Token"
          />
          <v-alert v-if="copied" type="success" variant="tonal" density="compact">
            Copied to the clipboard.
          </v-alert>
          <p v-else class="text-body-2 text-medium-emphasis">
            Copy it into the vendor's configuration now. If the button does nothing, the
            browser is blocking clipboard access — select the text above and copy it by
            hand.
          </p>
        </v-card-text>
        <v-card-actions>
          <v-btn variant="text" @click="copyToken">Copy</v-btn>
          <v-spacer />
          <v-btn color="primary" @click="dismissToken">I have saved it</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <RejectedEventsDialog :feed-id="rejectsFeedId" @close="rejectsFeedId = null" />
  </div>
</template>
