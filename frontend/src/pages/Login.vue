<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { toDisplayMessage } from '@/api/client'
import MfaEnrolment from '@/components/MfaEnrolment.vue'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const email = ref('')
const password = ref('')
const code = ref('')
const errorMessage = ref('')
const busy = ref(false)

async function submitPassword(): Promise<void> {
  errorMessage.value = ''
  busy.value = true
  try {
    await auth.login(email.value, password.value)
  } catch (err) {
    // The backend returns one message for every failure so the form cannot be used
    // to discover which addresses are registered. It is shown verbatim.
    errorMessage.value = toDisplayMessage(err)
  } finally {
    busy.value = false
  }
}

async function submitCode(): Promise<void> {
  errorMessage.value = ''
  busy.value = true
  try {
    await auth.verifyMfa(code.value)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboards'
    await router.push(redirect)
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
    code.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-main>
    <v-container class="fill-height" fluid>
      <v-row justify="center" align="center">
        <v-col cols="12" sm="8" md="5" lg="4">
          <v-card class="pa-6">
            <div class="text-h5 mb-1">SIEM</div>
            <div class="text-body-2 text-medium-emphasis mb-6">
              Multi-vendor WAF &amp; bot-defence correlation
            </div>

            <v-alert
              v-if="errorMessage"
              type="error"
              variant="tonal"
              density="compact"
              class="mb-4"
            >
              {{ errorMessage }}
            </v-alert>

            <!-- Step 1: password. No token is issued here. -->
            <v-form v-if="!auth.awaitingMfa" @submit.prevent="submitPassword">
              <v-text-field
                v-model="email"
                label="Email"
                type="email"
                autocomplete="username"
                autofocus
                class="mb-3"
              />
              <v-text-field
                v-model="password"
                label="Password"
                type="password"
                autocomplete="current-password"
                class="mb-4"
              />
              <v-btn type="submit" color="primary" block :loading="busy"> Continue </v-btn>
            </v-form>

            <!-- Step 2: TOTP. Only this step yields an access token. -->
            <v-form v-else @submit.prevent="submitCode">
              <!-- Shown on first sign-in, and again after an admin resets MFA. Both
                   reach this same step, so enrolment has one presentation. -->
              <MfaEnrolment v-if="auth.mfaProvisioningUri" :uri="auth.mfaProvisioningUri" />

              <v-text-field
                v-model="code"
                label="Authentication code"
                inputmode="numeric"
                autocomplete="one-time-code"
                maxlength="6"
                autofocus
                class="mb-4"
              />
              <v-btn type="submit" color="primary" block :loading="busy"> Sign in </v-btn>
            </v-form>
          </v-card>
        </v-col>
      </v-row>
    </v-container>
  </v-main>
</template>
