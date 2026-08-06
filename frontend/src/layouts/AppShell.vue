<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterView, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const router = useRouter()
const drawer = ref(true)

interface NavItem {
  title: string
  icon: string
  to: string
  visible: boolean
}

// Items are hidden when the role cannot use them. This is navigation hygiene, not
// access control — every route and every API call behind it is enforced server-side.
const navItems = computed<NavItem[]>(() => [
  { title: 'Dashboards', icon: 'mdi-view-dashboard', to: '/dashboards', visible: auth.can.search },
  { title: 'Search', icon: 'mdi-magnify', to: '/search', visible: auth.can.search },
  { title: 'Alerts', icon: 'mdi-bell-alert', to: '/alerts', visible: auth.can.search },
  { title: 'Feeds', icon: 'mdi-import', to: '/feeds', visible: auth.can.search },
  { title: 'Audit', icon: 'mdi-clipboard-text-clock', to: '/audit', visible: auth.can.readAudit },
  { title: 'Administration', icon: 'mdi-cog', to: '/admin', visible: auth.can.manageUsers },
])

const visibleItems = computed(() => navItems.value.filter((i) => i.visible))

async function signOut(): Promise<void> {
  await auth.logout()
  await router.push({ name: 'login' })
}
</script>

<template>
  <v-navigation-drawer v-model="drawer" :width="240">
    <div class="pa-4">
      <div class="text-h6">SIEM</div>
      <!-- Tenant name is server-supplied data; interpolation keeps it inert. -->
      <div class="text-caption text-medium-emphasis">
        {{ auth.user?.tenantName }}
      </div>
    </div>

    <v-divider />

    <v-list nav density="compact">
      <v-list-item
        v-for="item in visibleItems"
        :key="item.to"
        :to="item.to"
        :prepend-icon="item.icon"
        :title="item.title"
      />
    </v-list>

    <template #append>
      <v-divider />
      <div class="pa-3">
        <div class="text-body-2">
          {{ auth.user?.email }}
        </div>
        <div class="text-caption text-medium-emphasis mb-2">
          {{ auth.user?.role }}
        </div>
        <v-btn size="small" variant="tonal" block prepend-icon="mdi-logout" @click="signOut">
          Sign out
        </v-btn>
      </div>
    </template>
  </v-navigation-drawer>

  <v-app-bar flat density="comfortable">
    <v-app-bar-nav-icon @click="drawer = !drawer" />
    <v-app-bar-title>{{ $route.meta.title }}</v-app-bar-title>
  </v-app-bar>

  <v-main>
    <v-container fluid class="pa-4">
      <RouterView />
    </v-container>
  </v-main>
</template>
