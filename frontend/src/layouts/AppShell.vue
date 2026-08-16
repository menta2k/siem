<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterView, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import TimeFormatMenu from '@/components/TimeFormatMenu.vue'

const auth = useAuthStore()
const router = useRouter()
const drawer = ref(true)

interface NavItem {
  title: string
  icon: string
  to: string
  visible: boolean
  /** Sub-items, for a section that is several worklists rather than one page. */
  children?: NavItem[]
}

// Items are hidden when the role cannot use them. This is navigation hygiene, not
// access control — every route and every API call behind it is enforced server-side.
const navItems = computed<NavItem[]>(() => [
  { title: 'Dashboards', icon: 'mdi-view-dashboard', to: '/dashboards', visible: auth.can.search },
  { title: 'Search', icon: 'mdi-magnify', to: '/search', visible: auth.can.search },
  {
    title: 'Correlated',
    icon: 'mdi-vector-link',
    to: '/correlated',
    visible: auth.can.search,
  },
  { title: 'Alerts', icon: 'mdi-bell-alert', to: '/alerts', visible: auth.can.search },
  {
    title: 'WAF tuning',
    icon: 'mdi-shield-search',
    to: '/waf-tuning',
    visible: auth.can.manageRules || auth.can.triageAlerts,
  },
  {
    // Three sub-items rather than one page: the stages of moving enforcement from F5 to
    // Cloudflare are three different worklists, done in order, with a different action
    // at the end of each. Collapsing them into one screen would hide that order.
    title: 'WAF migration',
    icon: 'mdi-swap-horizontal-bold',
    to: '/waf-migration/uncovered',
    visible: auth.can.manageRules || auth.can.triageAlerts,
    children: [
      {
        title: 'Uncovered by CF',
        icon: 'mdi-shield-off-outline',
        to: '/waf-migration/uncovered',
        visible: true,
      },
      {
        title: 'Ready to enforce',
        icon: 'mdi-shield-check-outline',
        to: '/waf-migration/ready',
        visible: true,
      },
      {
        title: 'Likely false positives',
        icon: 'mdi-shield-alert-outline',
        to: '/waf-migration/false-positives',
        visible: true,
      },
    ],
  },
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
      <template v-for="item in visibleItems" :key="item.to">
        <!-- A section opens to show its stages. Kept open by default when one of them is
             the current page, so the reader can see where in the sequence they are. -->
        <v-list-group v-if="item.children" :value="item.title">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" :prepend-icon="item.icon" :title="item.title" />
          </template>
          <v-list-item
            v-for="child in item.children"
            :key="child.to"
            :to="child.to"
            :prepend-icon="child.icon"
            :title="child.title"
          />
        </v-list-group>

        <v-list-item v-else :to="item.to" :prepend-icon="item.icon" :title="item.title" />
      </template>
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

    <v-spacer />

    <!-- Which clock the page is in, stated where every page can see it. -->
    <TimeFormatMenu />
  </v-app-bar>

  <v-main>
    <v-container fluid class="pa-4">
      <RouterView />
    </v-container>
  </v-main>
</template>
