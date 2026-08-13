<script setup lang="ts">
import { ref, watch } from 'vue'
import QRCode from 'qrcode'

/**
 * Renders a TOTP provisioning URI as a scannable QR code.
 *
 * The URI is shown exactly once, during enrolment, and is never retrievable again — so
 * this is the only chance the user gets to put it into their authenticator. Asking them
 * to retype an `otpauth://` string containing a base32 secret was a transcription error
 * waiting to happen, and a mistyped secret fails at the NEXT step with an invalid code,
 * which reads as "the system is broken" rather than "you typed it wrong".
 *
 * Generated locally with the bundled library. The secret must never leave the browser
 * for a QR service, which is what every hosted chart API would do with it.
 */
const props = defineProps<{ uri: string }>()

const dataUrl = ref('')
const failed = ref(false)

watch(
  () => props.uri,
  async (uri) => {
    if (!uri) return
    try {
      // SVG, not the canvas-backed toDataURL. It is pure JS — so it needs no canvas and
      // works identically under test — and it scales without going soft on a high-DPI
      // phone screen being held up to another screen, which is the actual usage.
      const svg = await QRCode.toString(uri, {
        type: 'svg',
        // Quiet zone and contrast are what scanners need. Fixed dark-on-light rather
        // than theme-derived colours: a QR inverted by a dark theme is unreadable to
        // many phone cameras, and this is the one image on the page whose job is to be
        // machine-read rather than to match the palette.
        margin: 2,
        width: 220,
        color: { dark: '#000000', light: '#ffffff' },
        errorCorrectionLevel: 'M',
      })
      // Wrapped as a data: URI for an <img> rather than injected with v-html. The markup
      // is library-generated and safe, but keeping the no-v-html rule absolute means
      // nobody has to re-audit that judgement the next time this file is edited.
      dataUrl.value = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
      failed.value = false
    } catch {
      // The manual key below is a complete fallback, so a rendering failure costs
      // convenience rather than the ability to enrol at all.
      failed.value = true
    }
  },
  { immediate: true },
)

/**
 * The bare base32 secret, for entering by hand.
 *
 * Kept available even when the QR renders: a desktop password manager often takes the
 * key directly, and a user on the same device as the console cannot scan their own
 * screen.
 */
const manualKey = ref('')
watch(
  () => props.uri,
  (uri) => {
    manualKey.value = new URLSearchParams(uri.split('?')[1] ?? '').get('secret') ?? ''
  },
  { immediate: true },
)

const showManual = ref(false)
</script>

<template>
  <div class="mb-4">
    <v-alert type="info" variant="tonal" density="compact" class="mb-3">
      Scan this with your authenticator app. It is shown once and cannot be retrieved again.
    </v-alert>

    <div v-if="dataUrl" class="d-flex justify-center mb-3">
      <!-- A locally-generated data: URI, never a remote image. alt is deliberately not
           the secret: it would be read aloud by a screen reader and copied into any
           accessibility log. -->
      <img
        :src="dataUrl"
        alt="Two-factor authentication enrolment QR code"
        width="220"
        height="220"
        class="rounded"
        style="background: #fff; padding: 8px"
      />
    </div>

    <v-alert v-else-if="failed" type="warning" variant="tonal" density="compact" class="mb-3">
      The QR code could not be drawn. Use the setup key below instead.
    </v-alert>

    <v-btn
      size="small"
      variant="text"
      :append-icon="showManual ? 'mdi-chevron-up' : 'mdi-chevron-down'"
      @click="showManual = !showManual"
    >
      Can't scan it?
    </v-btn>

    <div v-if="showManual" class="mt-2">
      <div class="text-caption text-medium-emphasis mb-1">
        Enter this setup key in your authenticator app instead.
      </div>
      <!-- Interpolated, never v-html: this string is server-supplied. -->
      <code v-if="manualKey" class="text-caption d-block text-break">{{ manualKey }}</code>
      <code v-else class="text-caption d-block text-break">{{ uri }}</code>
    </div>
  </div>
</template>
