import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { router } from './router'
import { vuetify } from './plugins/vuetify'

const app = createApp(App)

app.use(createPinia())
app.use(vuetify)
// Pinia before the router: the navigation guard reads the auth store on the very
// first resolution, so the store must already exist.
app.use(router)

/**
 * Last-resort handler. An uncaught error must not leave a blank console during an
 * incident, and it must never surface internal detail to the user.
 */
app.config.errorHandler = (err, _instance, info) => {
  console.error('unhandled application error', { info, err })
}

app.mount('#app')
