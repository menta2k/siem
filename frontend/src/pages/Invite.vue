<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'

const route = useRoute()
const router = useRouter()

/**
 * The setup token, read from the query string.
 *
 * It is deliberately NOT put anywhere durable — no localStorage, no Pinia store. It is
 * a live credential that sets a password, and the only place it should exist after this
 * page closes is wherever the admin sent it.
 */
const setupToken = typeof route.query.token === 'string' ? route.query.token : ''

/** Minimum password length. Mirrors auth.MinPasswordLength; the server is the authority. */
const MIN_PASSWORD_LENGTH = 12

const email = ref('')
const password = ref('')
const confirmation = ref('')
const errorMessage = ref('')
const checking = ref(true)
const busy = ref(false)
const done = ref(false)

/**
 * Local checks, so the common mistakes are caught before a request is spent.
 *
 * These do not replace the server's rules — the backend validates independently, and it
 * is what actually enforces the floor. They exist so a typo in the confirmation field
 * does not cost a round trip.
 */
const passwordTooShort = computed(
  () => password.value.length > 0 && password.value.length < MIN_PASSWORD_LENGTH,
)
const mismatch = computed(
  () => confirmation.value.length > 0 && confirmation.value !== password.value,
)
const canSubmit = computed(
  () =>
    password.value.length >= MIN_PASSWORD_LENGTH &&
    confirmation.value === password.value &&
    !busy.value,
)

/**
 * Names the account before asking for a password.
 *
 * A preview does not spend the token, so an expired or already-used link fails HERE
 * rather than after someone has typed a password twice.
 */
onMounted(async () => {
  if (!setupToken) {
    errorMessage.value = 'This setup link is missing its token. Ask an administrator for a new one.'
    checking.value = false
    return
  }

  try {
    const { data } = await api.POST('/api/v1/auth/invite/preview', {
      body: { setupToken },
    })
    email.value = data?.email ?? ''
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    checking.value = false
  }
})

async function submit(): Promise<void> {
  errorMessage.value = ''
  busy.value = true
  try {
    await api.POST('/api/v1/auth/invite/redeem', {
      body: { setupToken, password: password.value },
    })
    done.value = true
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    busy.value = false
    // Cleared on every outcome. Leaving a chosen password sitting in reactive state
    // after the form is finished with it serves no purpose.
    password.value = ''
    confirmation.value = ''
  }
}

/**
 * Sends the user on to sign in.
 *
 * Redemption creates no session deliberately: the first sign-in is also where MFA
 * enrolment happens, and issuing a token here would be a way into the platform that
 * never passes a second factor.
 */
async function goToSignIn(): Promise<void> {
  await router.push({ name: 'login' })
}
</script>

<template>
  <v-main>
    <v-container class="fill-height" fluid>
      <v-row justify="center" align="center">
        <v-col cols="12" sm="8" md="5" lg="4">
          <v-card class="pa-6">
            <div class="text-h5 mb-1">SIEM</div>
            <div class="text-body-2 text-medium-emphasis mb-6">Set up your account</div>

            <div v-if="checking" class="d-flex justify-center py-6">
              <v-progress-circular indeterminate color="primary" />
            </div>

            <template v-else-if="done">
              <v-alert type="success" variant="tonal" density="compact" class="mb-4">
                Your password is set. Signing in will walk you through setting up your authenticator
                app.
              </v-alert>
              <v-btn color="primary" block @click="goToSignIn">Sign in</v-btn>
            </template>

            <template v-else>
              <v-alert
                v-if="errorMessage"
                type="error"
                variant="tonal"
                density="compact"
                class="mb-4"
              >
                {{ errorMessage }}
              </v-alert>

              <!-- Only rendered once the token has been confirmed to name an account.
                   Asking for a password against a dead link wastes the user's time. -->
              <v-form v-if="email" @submit.prevent="submit">
                <v-alert type="info" variant="tonal" density="compact" class="mb-4">
                  Choose a password for <strong>{{ email }}</strong
                  >. This link works once.
                </v-alert>

                <v-text-field
                  v-model="password"
                  label="New password"
                  type="password"
                  autocomplete="new-password"
                  autofocus
                  :error="passwordTooShort"
                  :error-messages="
                    passwordTooShort ? `Use at least ${MIN_PASSWORD_LENGTH} characters` : ''
                  "
                  :hint="`At least ${MIN_PASSWORD_LENGTH} characters. A passphrase is easier to remember and harder to crack.`"
                  persistent-hint
                  class="mb-3"
                />
                <v-text-field
                  v-model="confirmation"
                  label="Confirm password"
                  type="password"
                  autocomplete="new-password"
                  :error="mismatch"
                  :error-messages="mismatch ? 'The two passwords do not match' : ''"
                  class="mb-4"
                />
                <v-btn type="submit" color="primary" block :loading="busy" :disabled="!canSubmit">
                  Set password
                </v-btn>
              </v-form>
            </template>
          </v-card>
        </v-col>
      </v-row>
    </v-container>
  </v-main>
</template>
