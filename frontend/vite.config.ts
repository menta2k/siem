import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
}

export default defineConfig({
  plugins: [vue(), vuetify({ autoImport: true })],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  // Security headers, served on the response rather than only in a <meta> tag.
  //
  // frame-ancestors is IGNORED by browsers when delivered via <meta>, so the meta CSP
  // in index.html silently provides no clickjacking protection at all. It has to come
  // back as a header, and X-Frame-Options rides along for older agents that do not
  // implement frame-ancestors.
  //
  // Any production edge (reverse proxy, CDN, static host) must set the same headers —
  // this covers the dev server and the Compose stack, which serves the SPA from Vite.
  server: {
    host: '0.0.0.0',
    port: 5173,
    headers: SECURITY_HEADERS,
    proxy: {
      // The SPA never talks to anything but the backend contract surface.
      '/api': {
        target: process.env.VITE_API_TARGET ?? 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  preview: {
    headers: SECURITY_HEADERS,
  },
  test: {
    environment: 'jsdom',
    include: ['tests/unit/**/*.spec.ts'],
    // Vuetify ships per-component CSS that Node cannot import directly. Inlining the
    // package routes those imports through Vite's transform, which is what lets a
    // component test mount a real Vuetify component instead of a stub — the point of
    // the test being to check what an analyst actually sees.
    server: { deps: { inline: ['vuetify'] } },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,vue}'],
      // Constitution: 80% coverage floor, enforced by the build not by review.
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
})
