import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css'
import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi'

/**
 * Theme.
 *
 * Verdict colours are defined once here and referenced everywhere, so "blocked" looks
 * identical on a dashboard, in a results table, and on a correlated record. An analyst
 * scanning during an incident should never have to re-learn what a colour means.
 *
 * Dark is the default: this console is read for long stretches in operations rooms.
 */
export const vuetify = createVuetify({
  icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
  defaults: {
    VDataTable: { density: 'compact', hover: true },
    VTextField: { variant: 'outlined', density: 'comfortable', hideDetails: 'auto' },
    VSelect: { variant: 'outlined', density: 'comfortable', hideDetails: 'auto' },
    VCard: { elevation: 1 },
    VBtn: { variant: 'flat' },
  },
  theme: {
    defaultTheme: 'siemDark',
    themes: {
      siemDark: {
        dark: true,
        colors: {
          background: '#0F1419',
          surface: '#171D24',
          'surface-bright': '#1F262F',
          primary: '#4C8DFF',
          secondary: '#7A8899',

          // Verdicts, most restrictive to least.
          error: '#F2555A', // blocked
          warning: '#F0A030', // rate_limited
          info: '#4C8DFF', // challenged
          success: '#3FB950', // allowed
          'on-surface': '#E4E9F0',
        },
      },
      siemLight: {
        dark: false,
        colors: {
          background: '#F7F9FC',
          surface: '#FFFFFF',
          primary: '#1B62D6',
          secondary: '#5A6878',
          error: '#C7343A',
          warning: '#B4700C',
          info: '#1B62D6',
          success: '#1F7A32',
        },
      },
    },
  },
})

/** Maps a normalized verdict to its theme colour. One definition, used everywhere. */
export function verdictColor(verdict: string): string {
  switch (verdict) {
    case 'blocked':
      return 'error'
    case 'rate_limited':
      return 'warning'
    case 'challenged':
      return 'info'
    case 'allowed':
      return 'success'
    case 'monitored':
      // Deliberately distinct from allowed: a vendor in monitoring mode did not
      // choose to allow the request, and showing them alike would hide real conflicts.
      return 'secondary'
    default:
      return 'grey'
  }
}

/** Maps a join confidence to a colour, so an uncertain join never looks authoritative. */
export function confidenceColor(confidence: string): string {
  switch (confidence) {
    case 'high':
      return 'success'
    case 'medium':
      return 'info'
    case 'low':
      return 'warning'
    default:
      return 'grey'
  }
}
