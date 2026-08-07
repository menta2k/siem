import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore, type Role } from '@/stores/auth'

/** Roles permitted on a route. Absent means any authenticated user. */
declare module 'vue-router' {
  interface RouteMeta {
    public?: boolean
    roles?: Role[]
    title?: string
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/pages/Login.vue'),
    meta: { public: true, title: 'Sign in' },
  },
  {
    path: '/',
    component: () => import('@/layouts/AppShell.vue'),
    children: [
      { path: '', redirect: { name: 'dashboards' } },
      {
        path: 'dashboards',
        name: 'dashboards',
        component: () => import('@/pages/Dashboards.vue'),
        meta: { title: 'Dashboards' },
      },
      {
        path: 'search',
        name: 'search',
        component: () => import('@/pages/Search.vue'),
        meta: { title: 'Search' },
      },
      {
        // The list, and the reason the detail route below is reachable at all: an
        // analyst starts from "which requests did the vendors see differently", not
        // from a correlation id they already know.
        path: 'correlated',
        name: 'correlated-list',
        component: () => import('@/pages/Correlated.vue'),
        meta: { title: 'Correlated requests' },
      },
      {
        path: 'correlated/:id',
        name: 'correlated',
        component: () => import('@/pages/CorrelatedRequest.vue'),
        meta: { title: 'Correlated request' },
      },
      {
        path: 'feeds',
        name: 'feeds',
        component: () => import('@/pages/Feeds.vue'),
        meta: { title: 'Feeds' },
      },
      {
        path: 'alert-rules',
        name: 'alert-rules',
        component: () => import('@/pages/AlertRules.vue'),
        meta: { title: 'Alert rules' },
      },
      {
        path: 'alerts',
        name: 'alerts',
        component: () => import('@/pages/Alerts.vue'),
        meta: { title: 'Alerts', roles: ['admin', 'analyst', 'auditor'] },
      },
      {
        path: 'audit',
        name: 'audit',
        component: () => import('@/pages/Audit.vue'),
        meta: { title: 'Audit', roles: ['admin', 'auditor'] },
      },
      {
        path: 'admin',
        name: 'admin',
        component: () => import('@/pages/Admin.vue'),
        meta: { title: 'Administration', roles: ['admin'] },
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: { name: 'dashboards' } },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})

/**
 * Route guard.
 *
 * This keeps users out of pages they cannot use — it is NOT a security boundary. Every
 * underlying API call is independently authorized server-side, so bypassing this guard
 * gains an attacker nothing but an empty page.
 */
router.beforeEach(async (to) => {
  const auth = useAuthStore()

  // A page reload discards the in-memory access token, so on the first navigation the
  // store always looks signed out. The refresh token survives in an httpOnly cookie, so
  // one silent exchange is attempted BEFORE concluding anything — without this, every
  // browser refresh bounced the user to the login screen.
  if (!auth.isAuthenticated) {
    await auth.restore()
  }

  if (to.meta.public) {
    return auth.isAuthenticated ? { name: 'dashboards' } : true
  }
  if (!auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  const allowed = to.meta.roles
  if (allowed && (!auth.role || !allowed.includes(auth.role))) {
    return { name: 'dashboards' }
  }
  return true
})

router.afterEach((to) => {
  document.title = to.meta.title ? `${to.meta.title} · SIEM` : 'SIEM'
})
